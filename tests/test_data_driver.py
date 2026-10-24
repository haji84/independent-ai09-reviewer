"""PUBLIC synthetic receipt contract tests; no actual-model evidence."""
import base64
import dataclasses
import hashlib
import json
import unittest

import data_driver as driver


def batch():
    return driver.Batch('123', 1, 'a'*40, 'b'*64, 'c'*64,
                        (driver.Chunk('000', 'public.py', 7, b'print(1)\n'),))


def response(chunk_id='000'):
    return driver.encode_json({
        'model': driver.MODEL, 'created_at': '2026-10-25T00:00:00Z',
        'response': json.dumps({'chunk_id': chunk_id, 'findings': []}),
        'done': True, 'done_reason': 'stop', 'total_duration': 100,
        'load_duration': 1, 'prompt_eval_count': 2, 'prompt_eval_duration': 10,
        'eval_count': 3, 'eval_duration': 20})


def packet(expected=None):
    expected = expected or batch()
    chunk = expected.chunks[0]
    return driver.make_packet(expected, [driver.record_exchange(
        chunk, driver.build_request(chunk), response(chunk.chunk_id))])


class DataDriverTest(unittest.TestCase):
    def test_original_plan_adapter_always_blocks_before_io_or_inference(self):
        with self.assertRaisesRegex(driver.GateError, '^FROZEN_PLAN_SCHEMA_UNVERIFIED$'):
            driver.load_frozen_plan(None, None)

    def test_strict_json_rejects_ambiguous_or_unbounded_inputs(self):
        invalid = [b'{"x":1,"x":2}', b'NaN', b'Infinity', b'1e309',
                   b'1.0', b'1'*25, b'"\\ud800"', b'[] trailing', b'\xff',
                   b'['*40+b']'*40, b'"'+b'x'*131072+b'"']
        for value in invalid:
            with self.subTest(value=value[:30]):
                with self.assertRaises(driver.GateError):
                    driver.parse_json(value)
        self.assertEqual(driver.parse_json(b'{"ok":[1,true,null]}'), {'ok':[1,True,None]})

    def test_valid_packet_returns_exact_bytes_but_only_synthetic_classification(self):
        raw = packet()
        verified = driver.verify_synthetic_packet(raw, batch())
        self.assertEqual(verified.payload, raw)
        self.assertEqual(verified.evidence_kind, 'SYNTHETIC')
        self.assertEqual(verified.fixed_subject_receipts, 0)

    def test_attempt_context_and_chunk_swaps_are_rejected(self):
        raw = packet()
        changes = dict(run_id='124', attempt=2, commit='d'*40,
                       source_sha='d'*64, plan_sha='e'*64,
                       chunks=(driver.Chunk('001','other.py',1,b'other'),))
        for key, value in changes.items():
            with self.subTest(key=key):
                with self.assertRaises(driver.GateError):
                    driver.verify_synthetic_packet(raw, dataclasses.replace(batch(), **{key:value}))

    def test_worker_cannot_promote_to_real_or_omit_duplicate_append_records(self):
        value = json.loads(packet())
        variants = []
        real = dict(value, evidence_kind='REAL'); variants.append(real)
        variants.append(dict(value, records=[]))
        variants.append(dict(value, records=value['records']*2))
        variants.append(dict(value, approval='APPROVED'))
        for item in variants:
            with self.assertRaises(driver.GateError):
                driver.verify_synthetic_packet(driver.encode_json(item), batch())
        with self.assertRaises(driver.GateError):
            driver.verify_synthetic_packet(packet()+b'\n{}', batch())

    def test_self_consistent_modified_request_is_rejected_by_host(self):
        value = json.loads(packet())
        record = value['records'][0]
        request = json.loads(base64.b64decode(record['request_b64']))
        request['options']['num_predict'] = 999
        raw = driver.encode_json(request)
        record['request_b64'] = base64.b64encode(raw).decode('ascii')
        record['request_sha'] = hashlib.sha256(raw).hexdigest()
        with self.assertRaises(driver.GateError):
            driver.verify_synthetic_packet(driver.encode_json(value), batch())

    def test_bad_model_status_and_boolean_counters_are_rejected(self):
        valid = json.loads(response())
        for key, value in [('model','other'), ('done',False), ('done_reason','length'),
                           ('eval_count',True), ('eval_count',0), ('eval_duration',0),
                           ('created_at','not-a-time'), ('error','private error')]:
            with self.subTest(key=key,value=value):
                changed = dict(valid, **{key:value})
                with self.assertRaises(driver.GateError):
                    driver.record_exchange(batch().chunks[0], driver.build_request(batch().chunks[0]),
                                           driver.encode_json(changed))

    def test_pinned_ollama_optional_cached_count_is_bounded_and_exactly_typed(self):
        chunk=batch().chunks[0];valid=json.loads(response())
        for count in (0,1,valid['prompt_eval_count']):
            raw=driver.encode_json(dict(valid,prompt_eval_cached_count=count))
            record=driver.record_exchange(chunk,driver.build_request(chunk),raw)
            self.assertEqual(base64.b64decode(record['response_b64']),raw)
        for count in (True,False,-1,valid['prompt_eval_count']+1,None,'0',1.5):
            with self.subTest(count=count):
                with self.assertRaises(driver.GateError):
                    driver.validate_response(driver.encode_json(dict(valid,prompt_eval_cached_count=count)),chunk)
        with self.assertRaises(driver.GateError):
            driver.validate_response(driver.encode_json(dict(valid,unrecognized_metric=0)),chunk)

    def test_untrusted_findings_cannot_escape_chunk_or_grant_approval(self):
        valid = json.loads(response())
        good = {'file':'public.py','start_line':7,'end_line':7,
                'severity':'LOW','explanation':'PUBLIC test','recommendation':'PUBLIC fix'}
        for change in [dict(file='../other'),dict(start_line=True),dict(end_line=99),
                       dict(severity='APPROVED'),dict(approval=True)]:
            finding = dict(good, **change)
            changed = dict(valid, response=json.dumps({'chunk_id':'000','findings':[finding]}))
            with self.assertRaises(driver.GateError):
                driver.record_exchange(batch().chunks[0],driver.build_request(batch().chunks[0]),
                                       driver.encode_json(changed))

    def test_chunk_identity_and_exact_types_are_validated(self):
        for args in [('104','x',1,b'x'),('000','../x',1,b'x'),
                     ('000','x',True,b'x'),('000','x',1,b'\xff')]:
            with self.assertRaises(driver.GateError): driver.Chunk(*args)
        with self.assertRaises(driver.GateError): dataclasses.replace(batch(),attempt=True)


if __name__ == '__main__': unittest.main()
