"""Fixed PUBLIC input and strict pinned context-error evidence; no inference.

This is a public negative probe, never a frozen chunk or a successful review.
Host verification assumes the reviewed driver and pinned offline runtime are
trusted. It is not a tokenizer/model attestation or production admission gate.
"""
import base64

import data_driver as driver

SCHEMA='AI09-PUBLIC-CONTEXT-REJECTION-v1'
CODE='PUBLIC_CONTEXT_PROBE_REJECTED'
MAX_ERROR=2048


def need(condition):driver.require(condition,CODE)


def keys(value,names):need(type(value) is dict and set(value)==set(names))


def public_chunk():
    raw=(b'# PUBLIC CONTEXT LIMIT PROBE\n'+b'0123456789'*1600)[:driver.MAX_CHUNK]
    return driver.Chunk('103','PUBLIC_CONTEXT_LIMIT.txt',1,raw)


def public_request():return driver.build_request(public_chunk())


def validate_error(raw):
    """Only the pinned text-completion context-limit error counts as evidence."""
    try:
        outer=driver.parse_json(raw,MAX_ERROR);keys(outer,('error',))
        need(type(outer['error']) is str)
        nested=driver.parse_json(outer['error'].encode('utf-8'),MAX_ERROR)
        keys(nested,('error',));error=nested['error']
        keys(error,('code','type','message','n_prompt_tokens','n_ctx'))
        need(type(error['code']) is int and error['code']==400 and
             error['type']=='exceed_context_size_error')
        count=error['n_prompt_tokens'];context=error['n_ctx']
        need(type(context) is int and context==4096 and
             type(count) is int and context<=count<=driver.MAX_JSON)
        need(error['message']==f'request ({count} tokens) exceeds the available context size ({context} tokens), try increasing it')
        return count
    except (driver.GateError,UnicodeError):raise driver.GateError(CODE) from None


def record_rejection(expected,request,response,started_ns,finished_ns):
    need(type(expected) is driver.Batch and request==public_request())
    validate_error(response)
    need(driver.positive_int(started_ns) and driver.positive_int(finished_ns) and started_ns<=finished_ns)
    return {'schema':SCHEMA,'context':expected.context(),'status':400,
            'input_sha':driver.digest(public_chunk().content),
            'request_b64':base64.b64encode(request).decode('ascii'),
            'response_b64':base64.b64encode(response).decode('ascii'),
            'started_ns':started_ns,'finished_ns':finished_ns}


def _decode(value,limit):
    need(type(value) is str and len(value)<=4*((limit+2)//3))
    try:raw=base64.b64decode(value,validate=True)
    except (ValueError,UnicodeError):raise driver.GateError(CODE) from None
    need(len(raw)<=limit)
    return raw


def verify_rejection(value,expected,*,not_before,not_after):
    """Call only on captured data after the host verifies container teardown."""
    need(type(expected) is driver.Batch)
    keys(value,('schema','context','status','input_sha','request_b64','response_b64',
                'started_ns','finished_ns'))
    keys(value['context'],expected.context())
    need(type(value['context']['attempt']) is int and value['context']==expected.context())
    need(type(value['status']) is int and value['status']==400)
    started=value['started_ns'];finished=value['finished_ns']
    need(driver.positive_int(started) and driver.positive_int(finished) and
         not_before<=started<=finished<=not_after)
    request=_decode(value['request_b64'],driver.MAX_JSON)
    response=_decode(value['response_b64'],MAX_ERROR)
    need(value==record_rejection(expected,request,response,started,finished))
    return validate_error(response)
