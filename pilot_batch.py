"""Eight data-only observations; contract validation is not execution authority.

The caller must own the input, launch, capture and positive container teardown.
This module performs no I/O or model calls and grants no REAL/approval status.
Production admission stays closed. Raw data and findings have hidden reprs.
"""
import base64
import dataclasses
import datetime
import re

import context_probe
import data_driver as driver
import runtime_assets as assets

STAGING_SCHEMA = 'AI09-STAGED-BATCH-v1'
OBSERVATION_SCHEMA = 'AI09-OBSERVED-BATCH-v1'
EVIDENCE_SCHEMA = 'AI09-OBSERVED-EVIDENCE-v1'
RECORD_KEYS = ('chunk_id', 'input_sha', 'request_sha', 'response_sha',
               'request_b64', 'response_b64')


def need(condition):
    driver.require(condition, 'INVALID_OBSERVED_BATCH')


def _eight(batch):
    need(type(batch) is driver.Batch and len(batch.chunks) == 8)
    start = int(batch.chunks[0].chunk_id)
    need(start % 8 == 0 and tuple(c.chunk_id for c in batch.chunks) ==
         tuple(f'{i:03}' for i in range(start, start+8)))


def _encode(raw):
    return base64.b64encode(raw).decode('ascii')


def _decode(value, limit):
    need(type(value) is str and 0 < len(value) <= 4*((limit+2)//3))
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, UnicodeError):
        raise driver.GateError('INVALID_OBSERVED_BATCH') from None
    need(0 < len(raw) <= limit and _encode(raw) == value)
    return raw


def encode_batch(batch):
    _eight(batch)
    raw = driver.encode_json({'schema':STAGING_SCHEMA, 'context':batch.context(),
        'chunks':[{'chunk_id':c.chunk_id, 'path':c.path, 'start_line':c.start_line,
                   'content_b64':_encode(c.content)} for c in batch.chunks]})
    need(len(raw) <= driver.MAX_JSON)
    return raw


def decode_batch(raw):
    value = driver.parse_json(raw)
    driver.exact_keys(value, ('schema', 'context', 'chunks'))
    need(value['schema'] == STAGING_SCHEMA)
    context = value['context']
    driver.exact_keys(context, ('run_id', 'attempt', 'commit', 'source_sha', 'plan_sha'))
    need(type(value['chunks']) is list and len(value['chunks']) == 8)
    chunks = []
    for item in value['chunks']:
        driver.exact_keys(item, ('chunk_id', 'path', 'start_line', 'content_b64'))
        chunks.append(driver.Chunk(item['chunk_id'], item['path'], item['start_line'],
                                   _decode(item['content_b64'], driver.MAX_CHUNK)))
    batch = driver.Batch(**context, chunks=tuple(chunks))
    need(encode_batch(batch) == raw)
    return batch


def _timestamp_ns(stamp):
    need(type(stamp) is str)
    match = re.fullmatch(r'([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]{1,9}))?Z', stamp)
    need(match is not None)
    try:
        when = datetime.datetime.strptime(match[1], '%Y-%m-%dT%H:%M:%S')
    except ValueError:
        raise driver.GateError('INVALID_OBSERVED_BATCH') from None
    delta = when-datetime.datetime(1970, 1, 1)
    return (delta.days*86400+delta.seconds)*1_000_000_000 + int((match[2] or '').ljust(9, '0'))


@dataclasses.dataclass(frozen=True, repr=False)
class ValidatedObservation:
    payload: bytes
    observed_responses: int = dataclasses.field(default=8, init=False)
    fixed_subject_receipts: int = dataclasses.field(default=0, init=False)

    def __repr__(self):
        return 'ValidatedObservation()'


def verify_observation(raw, expected, host_start, host_end):
    """Validate exact bytes only after host-owned positive teardown.

    A valid packet alone cannot establish a genuine launch, model execution,
    original-source identity, cryptographic attestation or owner approval.
    """
    _eight(expected)
    need(driver.positive_int(host_start) and driver.positive_int(host_end) and host_start <= host_end)
    value = driver.parse_json(raw, driver.MAX_PACKET)
    driver.exact_keys(value, ('schema', 'context', 'exchanges', 'version_before',
        'tags_before', 'version_after', 'tags_after', 'context_rejection'))
    need(value['schema'] == OBSERVATION_SCHEMA and value['context'] == expected.context())
    driver.exact_keys(value['context'], expected.context())
    need(type(value['context']['attempt']) is int)
    for suffix in ('before', 'after'):
        assets.validate_inventory(_decode(value['version_'+suffix], driver.MAX_RESPONSE),
                                  _decode(value['tags_'+suffix], driver.MAX_RESPONSE))
    exchanges = value['exchanges']
    need(type(exchanges) is list and len(exchanges) == 8)
    previous = host_start
    for item, chunk in zip(exchanges, expected.chunks):
        driver.exact_keys(item, (*RECORD_KEYS, 'started_ns', 'finished_ns'))
        start, end = item['started_ns'], item['finished_ns']
        need(driver.positive_int(start) and driver.positive_int(end) and previous <= start <= end <= host_end)
        request = _decode(item['request_b64'], driver.MAX_JSON)
        response = _decode(item['response_b64'], driver.MAX_RESPONSE)
        need({key:item[key] for key in RECORD_KEYS} == driver.record_exchange(chunk, request, response))
        need(start <= _timestamp_ns(driver.parse_json(response, driver.MAX_RESPONSE)['created_at']) <= end)
        previous = end
    context_probe.verify_rejection(value['context_rejection'], expected,
                                    not_before=previous, not_after=host_end)
    return ValidatedObservation(raw)


def _launch_bytes(launch, expected):
    driver.exact_keys(launch, ('image', 'runtime', 'driver', 'ollama_archive',
        'model', 'model_blobs', 'context', 'input_class', 'staged_input_sha',
        'container_id', 'inspection'))
    need(type(launch['image']) is str and re.fullmatch(r'sha256:[0-9a-f]{64}', launch['image']))
    need(driver.valid_hash(launch['container_id']))
    need(launch['ollama_archive'] == assets.OLLAMA_SHA and launch['model'] == assets.MODEL_SHA)
    need(launch['input_class'] == 'PUBLIC_SYNTHETIC')  # No private activation by metadata.
    need(launch['context'] == expected.context() and type(launch['context']['attempt']) is int)
    need(launch['staged_input_sha'] == driver.digest(encode_batch(expected)))
    for name in ('runtime', 'driver'):
        hashes = launch[name]
        need(type(hashes) is dict and 0 < len(hashes) <= 128)
        need(all(type(key) is str and 0 < len(key) <= 256 and driver.valid_hash(value)
                 for key, value in hashes.items()))
    need(type(launch['model_blobs']) in (list, tuple) and 0 < len(launch['model_blobs']) <= 8)
    for entry in launch['model_blobs']:
        need(type(entry) in (list, tuple) and len(entry) == 2 and
             driver.valid_hash(entry[0]) and driver.positive_int(entry[1]))
    need(type(launch['inspection']) is dict and 0 < len(launch['inspection']) <= 32)
    raw = driver.encode_json(launch)
    need(len(raw) <= driver.MAX_JSON)
    driver.parse_json(raw)  # Same strict integer/Unicode/depth contract on both sides.
    return raw


def evidence_envelope(raw, expected, launch, host_start, host_end):
    """Preserve COMPLETE observation and host-owned launch, not only inner records.

    The host must inspect the actual container and obtain its own launch/times.
    PUBLIC-only here: this contract cannot enable confidential inference.
    """
    _eight(expected)
    need(type(raw) is bytes and len(raw) <= driver.MAX_PACKET)
    launch_raw = _launch_bytes(launch, expected)
    need(4*((len(raw)+2)//3)+len(launch_raw)+driver.MAX_JSON <= driver.MAX_PACKET)
    verify_observation(raw, expected, host_start, host_end)
    payload = driver.encode_json({'schema':EVIDENCE_SCHEMA, 'context':expected.context(),
        'host_start':host_start, 'host_end':host_end, 'launch':launch, 'packet_b64':_encode(raw)})
    need(len(payload) <= driver.MAX_PACKET)
    return payload


def verify_evidence(payload, expected, launch, host_start, host_end):
    """Authenticated decryption does not replace independent semantic verification."""
    _eight(expected)
    _launch_bytes(launch, expected)
    value = driver.parse_json(payload, driver.MAX_PACKET)
    driver.exact_keys(value, ('schema', 'context', 'host_start', 'host_end', 'launch', 'packet_b64'))
    need(value['schema'] == EVIDENCE_SCHEMA and value['context'] == expected.context())
    need(type(value['host_start']) is int and type(value['host_end']) is int)
    need(value['host_start'] == host_start and value['host_end'] == host_end)
    need(driver.encode_json(value['launch']) == driver.encode_json(launch))
    raw = _decode(value['packet_b64'], driver.MAX_PACKET)
    rebuilt = evidence_envelope(raw, expected, launch, host_start, host_end)
    need(payload == rebuilt)
    return verify_observation(raw, expected, host_start, host_end)
