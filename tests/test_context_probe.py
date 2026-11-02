"""Public rejection evidence only; never original chunks or actual inference."""
import base64
import copy
import importlib
import unittest

import data_driver as driver

try:
    probe=importlib.import_module('context_probe')
except ModuleNotFoundError:
    probe=None


def context_error(tokens=6000,context=4096,**changes):
    inner={'code':400,'type':'exceed_context_size_error','n_prompt_tokens':tokens,
           'n_ctx':context,'message':f'request ({tokens} tokens) exceeds the available context size ({context} tokens), try increasing it'}
    inner.update(changes)
    return driver.encode_json({'error':driver.encode_json({'error':inner}).decode('ascii')})


def expected():
    return driver.Batch('123',1,'a'*40,'b'*64,'c'*64,
                        (driver.Chunk('000','PUBLIC.py',1,b'PUBLIC\n'),))


class ContextProbeTest(unittest.TestCase):
    def ready(self):
        self.assertIsNotNone(probe,'public context rejection contract is missing')

    def test_public_case_is_deterministic_bounded_and_not_a_fixed_review(self):
        self.ready()
        chunk=probe.public_chunk()
        self.assertEqual(chunk,probe.public_chunk())
        self.assertEqual(len(chunk.content),driver.MAX_CHUNK)
        self.assertTrue(chunk.content.startswith(b'# PUBLIC CONTEXT LIMIT PROBE\n'))
        request=driver.parse_json(probe.public_request())
        self.assertIs(request['truncate'],False);self.assertIs(request['shift'],False)
        self.assertEqual(driver.parse_json(request['prompt'].split('\n',1)[1].encode())['source'].encode(),chunk.content)

    def test_only_the_pinned_nested_context_error_is_accepted(self):
        self.ready()
        self.assertEqual(probe.validate_error(context_error()),6000)
        invalid=[b'{}',b'{"error":"context too long"}',context_error(type='invalid_request_error'),
                 context_error(code=True),context_error(code=500),context_error(tokens=True),
                 context_error(tokens=4095),context_error(tokens=driver.MAX_JSON+1),
                 context_error(context=8192),context_error(extra=0),
                 context_error(message='PRIVATE-CANARY'),context_error()+b'{}',b'x'*2049]
        inner=driver.parse_json(context_error())['error']
        invalid.extend((inner.encode(),driver.encode_json({'error':inner+' OOM'}),
                        driver.encode_json({'error':inner,'extra':0})))
        for raw in invalid:
            with self.subTest(raw=raw[:35]):
                with self.assertRaisesRegex(driver.GateError,'^PUBLIC_CONTEXT_PROBE_REJECTED$'):
                    probe.validate_error(raw)

    def test_host_verifies_exact_context_request_response_and_time(self):
        self.ready()
        value=probe.record_rejection(expected(),probe.public_request(),context_error(),120,140)
        self.assertEqual(probe.verify_rejection(value,expected(),not_before=100,not_after=200),6000)
        variants=[]
        for key,new in (('status',200),('status',True),('started_ns',True),('started_ns',99),
                        ('finished_ns',201),('finished_ns',119),('input_sha','d'*64),
                        ('schema','REAL'),('response_b64','!'),('response_b64','A'*3000)):
            changed=copy.deepcopy(value);changed[key]=new;variants.append(changed)
        for name,new in (('attempt',2),('attempt',True),('run_id','124'),('commit','d'*40),
                         ('source_sha','d'*64),('plan_sha','d'*64)):
            changed=copy.deepcopy(value);changed['context'][name]=new;variants.append(changed)
        for flag in ('truncate','shift'):
            changed=copy.deepcopy(value);request=driver.parse_json(base64.b64decode(changed['request_b64']))
            request[flag]=0;changed['request_b64']=base64.b64encode(driver.encode_json(request)).decode()
            variants.append(changed)
        changed=copy.deepcopy(value);changed['response_b64']=base64.b64encode(context_error(code=500)).decode();variants.append(changed)
        changed=copy.deepcopy(value);changed['extra']=0;variants.append(changed)
        changed=copy.deepcopy(value);changed.pop('status');variants.append(changed)
        for changed in variants:
            with self.assertRaises(driver.GateError):
                probe.verify_rejection(changed,expected(),not_before=100,not_after=200)

    def test_rejection_constructor_refuses_modified_public_input_and_error(self):
        self.ready()
        for request,response in ((b'{}',context_error()),(probe.public_request(),b'{"error":"unknown"}')):
            with self.assertRaises(driver.GateError):
                probe.record_rejection(expected(),request,response,120,140)


if __name__=='__main__':unittest.main()
