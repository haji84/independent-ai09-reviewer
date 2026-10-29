#!/usr/bin/env python3
"""Owner-local codec/context boundary; real DPAPI format remains unsupported.

The expected-context digest must arrive through the separate authenticated owner
handoff. A matching digest alone cannot authenticate a JSON supplier. No network,
key generation, plaintext-key argument/environment fallback or approval is here.
Windows ACLs and the existing owner's key format/roundtrip remain NOT_RUN.
"""
import argparse
import dataclasses
import datetime
import os
import pathlib
import re
import stat
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import data_driver as driver
import pilot_batch
import pilot_host
import private_pilot
import public_runner
import sealed_input
import source_archive

_CONTEXT_SCHEMA = 'AI09-EXPECTED-HOST-CONTEXT-v1'
_CONTEXT_KEYS = ('schema', 'repository', 'workflow_path', 'run_id', 'attempt',
    'head_sha', 'run_event', 'head_branch', 'run_conclusion', 'job_id', 'job_name',
    'job_conclusion', 'log_sha256', 'observation_sha256', 'observation')
_MAX_CONTEXT = 16 * 1024
_MAX_LOG = 16 * 1024 * 1024
_STAMP = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z')
_SAFE_ERRORS = frozenset(('OWNER_CONTEXT_REJECTED', 'OWNER_EVIDENCE_REJECTED',
                         'OWNER_KEY_FORMAT_UNSUPPORTED', 'OWNER_BUNDLE_FAILED'))


def _need(value, code='OWNER_BUNDLE_FAILED'):
    driver.require(value, code)


def _run_id(value):
    return type(value) is str and re.fullmatch('[1-9][0-9]{0,19}', value) is not None


def _api_run_id(value, expected):
    return type(value) is int and 0 < value < 10**20 and str(value) == expected


def _logged_observation(log_bytes):
    _need(type(log_bytes) is bytes and 0 < len(log_bytes) <= _MAX_LOG)
    text = log_bytes.decode('utf-8')
    found = []
    marker = private_pilot.OBSERVATION_PREFIX[:-1]
    for number, line in enumerate(text.split('\n')):
        if number == 0 and line.startswith('\ufeff'):
            line = line[1:]
        if line.endswith('\r'):
            line = line[:-1]
        stripped = line.lstrip()
        parts = re.fullmatch(r'(\S+)([ \t]+)(.*)', stripped)
        message = parts[3] if parts else stripped
        # Workflow command/source echoes contain the marker as a substring;
        # only a whole log message can be the coordinator's observation.
        if not (message.lstrip().startswith(marker) or stripped.startswith(marker)):
            continue
        _need(line == stripped and parts is not None and parts[2] == ' '
              and _STAMP.fullmatch(parts[1]) is not None)
        datetime.datetime.strptime(parts[1][:19], '%Y-%m-%dT%H:%M:%S')
        _need(message.startswith(private_pilot.OBSERVATION_PREFIX))
        raw = message[len(private_pilot.OBSERVATION_PREFIX):].encode('ascii')
        _need(0 < len(raw) <= 2048)
        value = driver.parse_json(raw, 2048)
        _need(driver.encode_json(value) == raw)
        found.append(private_pilot.validate_observation(value))
        _need(len(found) == 1)
    _need(len(found) == 1)
    return found[0]


def _validated_context(raw, expected_sha256):
    try:
        _need(type(raw) is bytes and 0 < len(raw) <= _MAX_CONTEXT
              and driver.valid_hash(expected_sha256) and driver.digest(raw) == expected_sha256)
        value = driver.parse_json(raw, _MAX_CONTEXT)
        driver.exact_keys(value, _CONTEXT_KEYS)
        _need(driver.encode_json(value) == raw)
        observation = private_pilot.validate_observation(value['observation'])
        _need(value['schema'] == _CONTEXT_SCHEMA and value['repository'] == private_pilot.REPOSITORY
              and value['workflow_path'] == private_pilot.WORKFLOW_PATH
              and value['run_event'] == 'workflow_dispatch' and value['head_branch'] == 'main'
              and value['run_conclusion'] == 'success' and value['job_name'] == 'isolated-pilot'
              and value['job_conclusion'] == 'success' and driver.positive_int(value['job_id']))
        _need(_run_id(value['run_id']) and value['run_id'] == observation['run_id']
              and type(value['attempt']) is int and value['attempt'] == observation['attempt']
              and driver.valid_hash(value['head_sha'], 40) and value['head_sha'] == observation['commit'])
        _need(driver.valid_hash(value['log_sha256']) and driver.valid_hash(value['observation_sha256'])
              and value['observation_sha256'] == driver.digest(driver.encode_json(observation)))
        return value
    except Exception:
        raise driver.GateError('OWNER_CONTEXT_REJECTED') from None


def build_expected_context(run_metadata, job_metadata, log_bytes, *, approved_run_id,
        approved_attempt, approved_commit, approved_input_sha256, approved_input_bytes,
        approved_job_id) -> bytes:
    """Bind exact retrieved metadata/logs to independently approved public identity.

    This pure function checks content, not retrieval authenticity. Its caller
    must retrieve the exact run/attempt/job with the authenticated owner reader.
    The original decoded UTF-8 log bytes, including any BOM, are hashed unchanged.
    """
    try:
        _need(_run_id(approved_run_id) and type(approved_attempt) is int and approved_attempt == 1
              and driver.valid_hash(approved_commit, 40) and driver.valid_hash(approved_input_sha256)
              and driver.positive_int(approved_input_bytes)
              and driver.positive_int(approved_job_id))
        _need(type(run_metadata) is dict and type(job_metadata) is dict)
        run, job = run_metadata, job_metadata
        _need(_api_run_id(run['id'], approved_run_id) and _api_run_id(job['run_id'], approved_run_id)
              and type(run['run_attempt']) is int and run['run_attempt'] == approved_attempt
              and type(job['run_attempt']) is int and job['run_attempt'] == approved_attempt
              and type(job['id']) is int and job['id'] == approved_job_id)
        _need(type(run['repository']) is dict and run['repository']['full_name'] == private_pilot.REPOSITORY
              and run['path'] == private_pilot.WORKFLOW_PATH and run['event'] == 'workflow_dispatch'
              and run['head_branch'] == 'main' and job['head_branch'] == 'main'
              and run['head_sha'] == approved_commit and job['head_sha'] == approved_commit
              and run['status'] == 'completed' and job['status'] == 'completed'
              and run['conclusion'] == 'success' and job['conclusion'] == 'success'
              and job['name'] == 'isolated-pilot')
        observation = _logged_observation(log_bytes)
        _need(observation['run_id'] == approved_run_id and observation['attempt'] == approved_attempt
              and observation['commit'] == approved_commit
              and observation['input_ciphertext_sha256'] == approved_input_sha256
              and observation['input_ciphertext_bytes'] == approved_input_bytes)
        value = {'schema': _CONTEXT_SCHEMA, 'repository': private_pilot.REPOSITORY,
            'workflow_path': private_pilot.WORKFLOW_PATH, 'run_id': approved_run_id,
            'attempt': approved_attempt, 'head_sha': approved_commit,
            'run_event': 'workflow_dispatch', 'head_branch': 'main', 'run_conclusion': 'success',
            'job_id': approved_job_id, 'job_name': 'isolated-pilot', 'job_conclusion': 'success',
            'log_sha256': driver.digest(log_bytes),
            'observation_sha256': driver.digest(driver.encode_json(observation)), 'observation': observation}
        raw = driver.encode_json(value)
        _validated_context(raw, driver.digest(raw))
        return raw
    except Exception:
        raise driver.GateError('OWNER_CONTEXT_REJECTED') from None


@dataclasses.dataclass(frozen=True, slots=True, repr=False)
class VerifiedEvidence:
    """Public verification metadata only; no raw payload, findings or approval."""
    ciphertext_sha256: str
    ciphertext_bytes: int
    observed_responses: int = dataclasses.field(default=8, init=False)
    fixed_subject_receipts: int = dataclasses.field(default=0, init=False)

    def __repr__(self):
        return 'VerifiedEvidence()'


def verify_evidence_bytes(archive_raw, plan_raw, key, ciphertext,
                          expected_context_raw, expected_context_sha256):
    """Authenticate evidence against separately supplied host commitments.

    The committed launch is reconstructed only after its external digest matches.
    Original pins and all 47 sources/104 spans are freshly checked by the existing
    verifier. Success grants no hardware/model attestation, finding correctness,
    receipt admission, merge approval or private activation.
    """
    context = _validated_context(expected_context_raw, expected_context_sha256)
    try:
        observed = context['observation']
        _need(type(key) is bytes and len(key) == 32 and type(ciphertext) is bytes
              and 0 < len(ciphertext) <= public_runner.MAX_ENCRYPTED
              and len(ciphertext) == observed['output_ciphertext_bytes']
              and driver.digest(ciphertext) == observed['output_ciphertext_sha256'])
        plaintext = public_runner.unseal(ciphertext, key, pilot_host.PURPOSE)
        envelope = driver.parse_json(plaintext, driver.MAX_PACKET)
        launch = envelope['launch']
        launch_raw = driver.encode_json(launch)
        _need(len(launch_raw) <= driver.MAX_JSON
              and driver.digest(launch_raw) == observed['launch_sha256'])
        result = pilot_batch.verify_frozen_evidence(plaintext, archive_raw, plan_raw,
            run_id=observed['run_id'], attempt=observed['attempt'], commit=observed['commit'],
            launch=launch, host_start=observed['host_start_ns'], host_end=observed['host_end_ns'])
        _need(result.observed_responses == 8 and result.fixed_subject_receipts == 0)
        return VerifiedEvidence(driver.digest(ciphertext), len(ciphertext))
    except Exception:
        raise driver.GateError('OWNER_EVIDENCE_REJECTED') from None


def _load_owner_key(dpapi_key_file):
    # The installed CurrentUser filename/wrapper contract has not been obtained.
    # Never guess it, inspect a candidate secret file, or accept a plaintext key.
    raise driver.GateError('OWNER_KEY_FORMAT_UNSUPPORTED') from None


def _file_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def _guarded_path(value):
    path = pathlib.Path(os.path.abspath(os.fspath(value)))
    parents = []
    for parent in reversed(path.parents):
        info = parent.lstat()
        _need(stat.S_ISDIR(info.st_mode))
        parents.append((parent, (info.st_dev, info.st_ino, info.st_mode)))
    def recheck():
        for parent, expected in parents:
            info = parent.lstat()
            _need((info.st_dev, info.st_ino, info.st_mode) == expected)
    return path, recheck


def _regular(info, limit):
    _need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 <= info.st_size <= limit)


def _read_bounded(value, limit):
    path, recheck = _guarded_path(value)
    initial = path.lstat(); _regular(initial, limit)
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0)
    flags |= getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_BINARY', 0)
    fd = os.open(path, flags)
    try:
        _need(_file_identity(os.fstat(fd)) == _file_identity(initial))
        result = bytearray()
        while True:
            block = os.read(fd, min(65_536, limit - len(result) + 1))
            if not block:
                break
            result.extend(block); _need(len(result) <= limit)
        _need(len(result) == initial.st_size
              and _file_identity(os.fstat(fd)) == _file_identity(initial)
              and _file_identity(path.lstat()) == _file_identity(initial))
        recheck()
        return bytes(result)
    finally:
        os.close(fd)


def _write_ciphertext(value, ciphertext, archive_raw, plan_raw, key):
    path, recheck = _guarded_path(value)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    flags |= getattr(os, 'O_CLOEXEC', 0) | getattr(os, 'O_BINARY', 0)
    fd = os.open(path, flags, 0o600)
    try:
        _regular(os.fstat(fd), 0)
        position = 0
        while position < len(ciphertext):
            block = memoryview(ciphertext)[position:position + 65_536]
            count = os.write(fd, block)
            _need(type(count) is int and 0 < count <= len(block)); position += count
        os.fsync(fd)
        written = os.fstat(fd); _regular(written, len(ciphertext))
        _need(written.st_size == len(ciphertext))
        if os.name == 'posix':
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        actual = _read_bounded(path, private_pilot.MAX_CIPHERTEXT)
        recovered = sealed_input.open_frozen_input(actual, key)
        _need(recovered.archive_raw == archive_raw and recovered.plan_raw == plan_raw
              and actual == ciphertext
              and _file_identity(os.fstat(fd)) == _file_identity(written)
              and _file_identity(path.lstat()) == _file_identity(written))
        recheck()
        return {'ciphertext_sha256': driver.digest(actual), 'ciphertext_bytes': len(actual)}
    finally:
        os.close(fd)


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise driver.GateError('OWNER_BUNDLE_FAILED') from None


def main(argv=None):
    try:
        parser = _Parser(description=__doc__, allow_abbrev=False)
        commands = parser.add_subparsers(dest='command', required=True)
        for name in ('seal-input', 'verify-evidence'):
            command = commands.add_parser(name, allow_abbrev=False)
            for option in ('archive', 'plan', 'dpapi-key-file'):
                command.add_argument('--' + option, required=True)
            if name == 'seal-input':
                command.add_argument('--output', required=True)
            else:
                command.add_argument('--evidence', required=True)
                command.add_argument('--expected-context', required=True)
                command.add_argument('--expected-context-sha256', required=True)
        args = parser.parse_args(argv)
        if args.command == 'verify-evidence':
            # Invalid/missing context must fail before any key adapter access.
            try:
                context_raw = _read_bounded(args.expected_context, _MAX_CONTEXT)
                _validated_context(context_raw, args.expected_context_sha256)
            except Exception:
                raise driver.GateError('OWNER_CONTEXT_REJECTED') from None
        key = _load_owner_key(args.dpapi_key_file)
        archive = _read_bounded(args.archive, source_archive.MAX_ARCHIVE)
        plan = _read_bounded(args.plan, source_archive.MAX_PLAN)
        if args.command == 'seal-input':
            ciphertext = sealed_input.seal_frozen_input(archive, plan, key)
            metadata = _write_ciphertext(args.output, ciphertext, archive, plan, key)
        else:
            ciphertext = _read_bounded(args.evidence, public_runner.MAX_ENCRYPTED)
            verified = verify_evidence_bytes(archive, plan, key, ciphertext,
                                            context_raw, args.expected_context_sha256)
            metadata = {'ciphertext_sha256': verified.ciphertext_sha256,
                'ciphertext_bytes': verified.ciphertext_bytes, 'observed_responses': 8,
                'fixed_subject_receipts': 0}
        print(driver.encode_json(metadata).decode('ascii'))
        return 0
    except SystemExit as error:
        return 0 if error.code == 0 else 2
    except BaseException as error:
        code = str(error) if str(error) in _SAFE_ERRORS else 'OWNER_BUNDLE_FAILED'
        print('OWNER_BUNDLE_ERROR=' + code)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
