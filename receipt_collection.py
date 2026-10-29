"""Bounded13x8 SYNTHETIC completeness; no inference or frozen-plan adapter.

Expectations belong to the trusted host, never to a packet/index. Call only on
immutable packets retained after worker teardown. This stateless component does
not prove original file coverage, model execution or replay prevention between
separate calls. The production adapter and approval gates remain closed.
"""
import base64
import dataclasses

import data_driver as driver

SCHEMA='AI09-SYNTHETIC-COLLECTION-v1'
COUNT=13
MAX_COLLECTION=driver.MAX_PACKET
MAX_INDEX=driver.MAX_JSON
OVERHEAD=len(driver.encode_json({'schema':SCHEMA,'index':{},'packets_b64':['']*COUNT}))-2


def need(condition,code='INVALID_SYNTHETIC_COLLECTION'):driver.require(condition,code)


def _expected(batches):
    need(type(batches) is tuple and len(batches)==COUNT)
    need(all(type(batch) is driver.Batch and len(batch.chunks)==8 for batch in batches))
    need(tuple(chunk.chunk_id for batch in batches for chunk in batch.chunks)==
         tuple(f'{i:03}' for i in range(104)))
    subject=lambda batch:(batch.commit,batch.source_sha,batch.plan_sha)
    need(all(subject(batch)==subject(batches[0]) for batch in batches))


def _budget(encoded_lengths):
    need(sum(encoded_lengths)+MAX_INDEX+OVERHEAD<=MAX_COLLECTION,'COLLECTION_SIZE_LIMIT')


@dataclasses.dataclass(frozen=True)
class SyntheticCollection:
    payload:bytes=dataclasses.field(repr=False)
    evidence_kind:str=dataclasses.field(default='SYNTHETIC',init=False)
    synthetic_receipts:int=dataclasses.field(default=104,init=False)
    fixed_subject_receipts:int=dataclasses.field(default=0,init=False)


def assemble_synthetic_collection(expected_batches,packets):
    _expected(expected_batches)
    need(type(packets) is tuple and len(packets)==COUNT)
    need(all(type(raw) is bytes and 0<len(raw)<=driver.MAX_PACKET for raw in packets))
    # Reserve the complete bounded index and JSON framing before any packet is
    # parsed or base64 output allocated. Do not raise global parser/seal limits.
    _budget(4*((len(raw)+2)//3) for raw in packets)
    batches=[]
    for ordinal,(expected,raw) in enumerate(zip(expected_batches,packets)):
        driver.verify_synthetic_packet(raw,expected)
        records=driver.parse_json(raw,driver.MAX_PACKET)['records']
        chunks=[{key:record[key] for key in ('chunk_id','input_sha','request_sha','response_sha')}
                for record in records]
        batches.append({'ordinal':ordinal,'context':expected.context(),
                        'packet_sha':driver.digest(raw),'chunks':chunks})
    index={'evidence_kind':'SYNTHETIC','synthetic_receipts':104,
           'fixed_subject_receipts':0,'batches':batches}
    need(len(driver.encode_json(index))<=MAX_INDEX,'COLLECTION_SIZE_LIMIT')
    payload=driver.encode_json({'schema':SCHEMA,'index':index,
                               'packets_b64':[base64.b64encode(raw).decode('ascii') for raw in packets]})
    need(len(payload)<=MAX_COLLECTION,'COLLECTION_SIZE_LIMIT')
    return SyntheticCollection(payload)


def verify_synthetic_collection(payload,expected_batches):
    """Rebuild from external expectations, including after authenticated unseal.

    Storage uses the exact canonical collection encoding. Original embedded
    packets are never normalized; their hashes bind their exact raw bytes.
    """
    _expected(expected_batches)
    need(type(payload) is bytes)
    need(len(payload)<=MAX_COLLECTION,'COLLECTION_SIZE_LIMIT')
    value=driver.parse_json(payload,MAX_COLLECTION)
    driver.exact_keys(value,('schema','index','packets_b64'))
    need(value['schema']==SCHEMA)
    encoded=value['packets_b64']
    need(type(encoded) is list and len(encoded)==COUNT and all(type(item) is str for item in encoded))
    _budget(len(item) for item in encoded)
    try:packets=tuple(base64.b64decode(item,validate=True) for item in encoded)
    except (ValueError,UnicodeError):raise driver.GateError('INVALID_SYNTHETIC_COLLECTION') from None
    rebuilt=assemble_synthetic_collection(expected_batches,packets)
    # Exact bytes also reject bool/int aliases, extra fields and an index made
    # self-consistent by a worker. Nothing in candidate metadata grants trust.
    need(payload==rebuilt.payload)
    return rebuilt
