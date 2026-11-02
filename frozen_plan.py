"""Offline verification of unchanged original inputs; no execution authority.

The production loader/pilot remain closed. Inputs are bytes, never paths or
downloaded Python. Raw identity and canonical consistency are separate checks.
Returned spans retain original boundaries; normalized chunks describe only
covered lines. No receipt, inference, finding accuracy or approval is implied.
"""
import dataclasses
import json

import data_driver as driver
import pilot_batch
import source_archive as source

FROZEN_PLAN_SHA = 'ad7c9a7b6914670c82b436ede89d543e8e09a3c0902448c9378fb6ab1aaecf44'
ROOT_KEYS = ('archive_sha256', 'chunk_count', 'chunks', 'expected_status',
             'github_approval', 'maker_model', 'manifest_path', 'max_chunk_bytes',
             'merge_authorized', 'plan_sha256', 'review_target', 'root_prefix',
             'schema', 'source_file_count')
CHUNK_KEYS = ('index', 'path', 'start_byte', 'end_byte', 'start_line', 'end_line',
              'sha256', 'source_sha256')


def need(condition, code='INVALID_FROZEN_PLAN'):
    driver.require(condition, code)


def path_value(value, directory=False):
    need(type(value) is str and 0 < len(value) <= 256
         and all(32 <= ord(c) < 127 for c in value)
         and not any(c in value for c in '\\:'))
    need(value.endswith('/') == directory)
    clean = value[:-1] if directory else value
    need(clean and all(part not in ('', '.', '..') for part in clean.split('/')))
    return value


@dataclasses.dataclass(frozen=True, repr=False)
class FrozenSpan:
    index: int
    path: str
    start_byte: int
    end_byte: int
    start_line: int
    end_line: int
    covered_end_line: int
    sha256: str
    source_sha256: str

    def __repr__(self):
        return 'FrozenSpan()'


@dataclasses.dataclass(frozen=True, repr=False)
class VerifiedPlan:
    source_sha: str
    plan_sha: str
    canonical_plan_sha: str
    spans: tuple
    chunks: tuple

    def __repr__(self):
        return 'VerifiedPlan()'


def verify_plan(archive_raw, plan_raw):
    """Fresh verification from independently pinned immutable bytes, no I/O.

    This read-only adapter grants no production/model/merge permission. A prior
    VerifiedPlan or candidate metadata is never accepted as a trust anchor.
    """
    need(type(archive_raw) is bytes and 0 < len(archive_raw) <= source.MAX_ARCHIVE,
         'ARCHIVE_SIZE_OR_TYPE')
    need(type(plan_raw) is bytes and 0 < len(plan_raw) <= source.MAX_PLAN,
         'PLAN_SIZE_OR_TYPE')
    need(driver.digest(archive_raw) == source.FROZEN_SHA, 'FROZEN_SOURCE_HASH_MISMATCH')
    need(driver.digest(plan_raw) == FROZEN_PLAN_SHA, 'FROZEN_PLAN_HASH_MISMATCH')
    plan = driver.parse_json(plan_raw, source.MAX_PLAN)
    driver.exact_keys(plan, ROOT_KEYS)
    for key, expected in (('schema', 1), ('source_file_count', 47),
                          ('chunk_count', 104), ('max_chunk_bytes', 2300)):
        need(type(plan[key]) is int and plan[key] == expected)
    need(plan['archive_sha256'] == source.FROZEN_SHA
         and plan['expected_status'] == 'REVIEW_NOT_INVOKED'
         and plan['github_approval'] is False and plan['merge_authorized'] is False)
    for key, limit in (('maker_model', 80), ('review_target', 256)):
        value = plan[key]
        need(type(value) is str and 0 < len(value) <= limit
             and all(ord(c) >= 32 and ord(c) != 127 for c in value))
    need(driver.valid_hash(plan['plan_sha256']))
    body = {key: value for key, value in plan.items() if key != 'plan_sha256'}
    canonical = json.dumps(body, sort_keys=True, ensure_ascii=False,
                           separators=(',', ':'), allow_nan=False).encode('utf-8')
    need(driver.digest(canonical) == plan['plan_sha256'],
         'FROZEN_PLAN_CANONICAL_HASH_MISMATCH')
    prefix = path_value(plan['root_prefix'], directory=True)
    manifest = prefix + path_value(plan['manifest_path'])
    records = plan['chunks']
    need(type(records) is list and len(records) == 104)
    archive = source.read_frozen_archive(archive_raw)
    need(manifest in archive.files, 'FROZEN_PLAN_COVERAGE')
    positions = {}; spans = []; chunks = []
    for index, record in enumerate(records):
        driver.exact_keys(record, CHUNK_KEYS)
        need(all(type(record[key]) is int for key in
                 ('index', 'start_byte', 'end_byte', 'start_line', 'end_line')))
        need(record['index'] == index)
        path = path_value(record['path'])
        full_path = prefix + path
        need(full_path in archive.files and full_path != manifest, 'FROZEN_PLAN_COVERAGE')
        file = archive.files[full_path]
        start, end = record['start_byte'], record['end_byte']
        need(start == positions.get(path, 0), 'FROZEN_PLAN_COVERAGE')
        need(0 <= start < end <= len(file.content) and end-start <= 2300)
        need(driver.valid_hash(record['source_sha256']) and
             record['source_sha256'] == file.sha and driver.valid_hash(record['sha256']))
        content = file.content[start:end]
        need(driver.digest(content) == record['sha256'])
        try:
            content.decode('utf-8')
        except UnicodeError:
            raise driver.GateError('FROZEN_PLAN_ENCODING') from None
        start_line = file.content[:start].count(b'\n') + 1
        end_line = file.content[:end].count(b'\n') + 1
        covered_end = file.content[:end-1].count(b'\n') + 1
        need(record['start_line'] == start_line and record['end_line'] == end_line)
        chunk = driver.Chunk(f'{index:03}', path, start_line, content)
        need(chunk.end_line == covered_end, 'FROZEN_PLAN_LINE_CONVENTION')
        spans.append(FrozenSpan(index, path, start, end, start_line, end_line,
                                covered_end, record['sha256'], record['source_sha256']))
        chunks.append(chunk)
        positions[path] = end
    need(len(positions) == 47 and
         {prefix+path for path in positions} == set(archive.files)-{manifest},
         'FROZEN_PLAN_COVERAGE')
    need(all(position == len(archive.files[prefix+path].content)
             for path, position in positions.items()), 'FROZEN_PLAN_COVERAGE')
    return VerifiedPlan(archive.archive_sha, driver.digest(plan_raw),
                        plan['plan_sha256'], tuple(spans), tuple(chunks))


def prepare_pilot_batch(archive_raw, plan_raw, *, run_id, attempt, commit):
    """Derive the first eight host expectations from freshly verified raw data.

    Validate all 104 spans before selecting 000..007. The host supplies run
    identity; source and RAW plan identity come only from the pinned inputs.
    This offline adapter does not admit private execution, export evidence,
    classify input as PUBLIC, or grant receipt/approval status. Callers still
    need the separate production admission and confidential runtime gates.
    """
    verified = verify_plan(archive_raw, plan_raw)
    batch = driver.Batch(run_id, attempt, commit, verified.source_sha,
                         verified.plan_sha, verified.chunks[:8])
    pilot_batch.encode_batch(batch)  # Enforce the existing bounded staging contract.
    return batch
