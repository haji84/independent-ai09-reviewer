"""PUBLIC eight-item observations, never original inputs or inference evidence."""
import base64
import copy
import dataclasses
import datetime
import importlib.util
import unittest

import context_probe
import data_driver as driver
import runtime_assets as assets
import public_runner
from test_context_probe import context_error
from test_data_driver import response

pilot = (__import__('pilot_batch') if importlib.util.find_spec('pilot_batch') else None)
SECOND = 1_000_000_000
BASE = 1_761_350_400 * SECOND  # 2025-10-25 UTC; PUBLIC deterministic clock only.


def encoded(raw):
    return base64.b64encode(raw).decode('ascii')


def batch():
    return driver.Batch('123', 1, 'a'*40, 'b'*64, 'c'*64, tuple(
        driver.Chunk(f'{i:03}', f'PUBLIC{i}.py', 1, b'def add(a, b):\n    return a + b\n')
        for i in range(8)))


def observation():
    expected = batch()
    version = b'{"version":"0.34.0"}'
    tags = driver.encode_json({'models':[{'name':driver.MODEL,'digest':assets.MODEL_SHA}]})
    exchanges = []
    for number, chunk in enumerate(expected.chunks):
        start = BASE + (number*2+1)*SECOND
        value = driver.parse_json(response(chunk.chunk_id))
        value['created_at'] = datetime.datetime.fromtimestamp(
            start//SECOND, datetime.timezone.utc).isoformat().replace('+00:00', 'Z')
        record = driver.record_exchange(chunk, driver.build_request(chunk), driver.encode_json(value))
        exchanges.append(dict(record, started_ns=start, finished_ns=start+SECOND))
    return {'schema':'AI09-OBSERVED-BATCH-v1','context':expected.context(),
            'exchanges':exchanges,'version_before':encoded(version),'version_after':encoded(version),
            'tags_before':encoded(tags),'tags_after':encoded(tags),
            'context_rejection':context_probe.record_rejection(expected, context_probe.public_request(),
                context_error(), BASE+18*SECOND, BASE+19*SECOND)}


def launch():
    return {'image':'sha256:'+'d'*64,'runtime':{'bin/ollama':'e'*64},
            'driver':{'/guest.py':'f'*64},'ollama_archive':assets.OLLAMA_SHA,
            'model':assets.MODEL_SHA,'model_blobs':[['a'*64,100]],'context':batch().context(),
            'input_class':'PUBLIC_SYNTHETIC','staged_input_sha':driver.digest(pilot.encode_batch(batch())),
            'container_id':'1'*64,'inspection':{'NetworkMode':'none','ReadonlyRootfs':True}}


class PilotBatchTest(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(pilot, 'eight-item observed batch contract is missing')

    def verify(self, value):
        return pilot.verify_observation(driver.encode_json(value), batch(), BASE, BASE+20*SECOND)

    def test_staged_eight_round_trip_preserves_bytes_and_has_hidden_repr(self):
        raw = pilot.encode_batch(batch())
        self.assertLessEqual(len(raw), driver.MAX_JSON)
        self.assertEqual(pilot.decode_batch(raw), batch())
        value = self.verify(observation())
        self.assertEqual(value.observed_responses, 8)
        self.assertEqual(value.fixed_subject_receipts, 0)
        self.assertEqual(value.payload, driver.encode_json(observation()))
        self.assertNotIn('PUBLIC', repr(value))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            value.observed_responses = 104

    def test_staging_rejects_count_order_aliases_unknown_fields_and_bad_encoding(self):
        raw = driver.parse_json(pilot.encode_batch(batch()))
        changes = []
        value = copy.deepcopy(raw); value['chunks'].pop(); changes.append(value)
        value = copy.deepcopy(raw); value['chunks'].reverse(); changes.append(value)
        value = copy.deepcopy(raw); value['context']['attempt'] = True; changes.append(value)
        value = copy.deepcopy(raw); value['authorized'] = True; changes.append(value)
        value = copy.deepcopy(raw); value['chunks'][0]['content_b64'] = '!!!'; changes.append(value)
        value = copy.deepcopy(raw); value['chunks'][0]['start_line'] = True; changes.append(value)
        for value in changes:
            with self.assertRaises(driver.GateError):
                pilot.decode_batch(driver.encode_json(value))
        with self.assertRaises(driver.GateError):
            pilot.decode_batch(b'x'*(driver.MAX_JSON+1))

    def test_all_eight_records_and_external_context_are_required(self):
        for change in ('missing', 'duplicate', 'reverse', 'attempt', 'commit', 'synthetic'):
            value = observation()
            if change == 'missing': value['exchanges'].pop()
            elif change == 'duplicate': value['exchanges'][-1] = value['exchanges'][0]
            elif change == 'reverse': value['exchanges'].reverse()
            elif change == 'attempt': value['context']['attempt'] = True
            elif change == 'commit': value['context']['commit'] = 'd'*40
            else: value['schema'] = driver.SCHEMA
            with self.subTest(change=change), self.assertRaises(driver.GateError):
                self.verify(value)

    def test_last_request_or_response_substitution_fails_even_when_rehashed(self):
        for key in ('request', 'response'):
            value = observation(); record = value['exchanges'][-1]
            raw = base64.b64decode(record[key+'_b64'])
            item = driver.parse_json(raw)
            if key == 'request': item['truncate'] = True
            else: item['done_reason'] = 'length'
            raw = driver.encode_json(item)
            record[key+'_b64'] = encoded(raw); record[key+'_sha'] = driver.digest(raw)
            with self.assertRaises(driver.GateError): self.verify(value)

    def test_inventory_before_and_after_are_verified(self):
        for key in ('version_before', 'tags_before', 'version_after', 'tags_after'):
            value = observation(); value[key] = encoded(b'{}')
            with self.assertRaises(driver.GateError): self.verify(value)

    def test_request_order_host_window_boolean_and_response_timestamp_are_checked(self):
        changes = []
        value = observation(); value['exchanges'][0]['started_ns'] = True; changes.append(value)
        value = observation(); value['exchanges'][-1]['finished_ns'] = BASE+21*SECOND; changes.append(value)
        value = observation(); value['exchanges'][1]['started_ns'] = BASE+SECOND; changes.append(value)
        value = observation(); record = value['exchanges'][0]
        body = driver.parse_json(base64.b64decode(record['response_b64']))
        body['created_at'] = '2020-01-01T00:00:00Z'
        raw = driver.encode_json(body); record['response_b64'] = encoded(raw)
        record['response_sha'] = driver.digest(raw); changes.append(value)
        for value in changes:
            with self.assertRaises(driver.GateError): self.verify(value)
        with self.assertRaises(driver.GateError):
            pilot.verify_observation(driver.encode_json(observation()), batch(), True, BASE+20*SECOND)

    def test_context_rejection_must_follow_the_eight_responses(self):
        for change in ('missing', 'boolean', 'overlap', 'wrong-input'):
            value = observation()
            if change == 'missing': value.pop('context_rejection')
            elif change == 'boolean': value['context_rejection'] = True
            elif change == 'overlap': value['context_rejection']['started_ns'] = BASE+SECOND
            else: value['context_rejection']['input_sha'] = 'd'*64
            with self.assertRaises(driver.GateError): self.verify(value)

    def test_complete_packet_launch_and_host_window_survive_encryption(self):
        operation=getattr(pilot,'evidence_envelope',None)
        self.assertTrue(callable(operation),'complete observed evidence envelope is missing')
        raw=driver.encode_json(observation()); expected_launch=launch()
        payload=operation(raw,batch(),expected_launch,BASE,BASE+20*SECOND)
        envelope=driver.parse_json(payload,driver.MAX_PACKET)
        self.assertEqual(base64.b64decode(envelope['packet_b64']),raw)
        self.assertEqual(envelope['launch'],expected_launch)
        key=bytes(range(32));purpose=b'CONFIDENTIAL-REVIEW-EVIDENCE'
        encrypted=public_runner.seal(payload,key,purpose)
        recovered=public_runner.unseal(encrypted,key,purpose)
        verified=pilot.verify_evidence(recovered,batch(),expected_launch,BASE,BASE+20*SECOND)
        self.assertEqual(verified.payload,raw)
        self.assertEqual(verified.observed_responses,8)
        self.assertEqual(verified.fixed_subject_receipts,0)

    def test_authenticated_envelope_still_requires_external_expectations_and_semantics(self):
        operation=getattr(pilot,'evidence_envelope',None)
        self.assertTrue(callable(operation),'complete observed evidence envelope is missing')
        payload=operation(driver.encode_json(observation()),batch(),launch(),BASE,BASE+20*SECOND)
        envelope=driver.parse_json(payload,driver.MAX_PACKET)
        cases=[]
        value=copy.deepcopy(envelope);value['launch']['model']='d'*64;cases.append(value)
        value=copy.deepcopy(envelope);value['host_start']=True;cases.append(value)
        value=copy.deepcopy(envelope);value['context']['commit']='d'*40;cases.append(value)
        value=copy.deepcopy(envelope);packet=observation();packet['exchanges'].pop()
        value['packet_b64']=encoded(driver.encode_json(packet));cases.append(value)
        value=copy.deepcopy(envelope);packet=observation();packet['tags_after']=encoded(b'{}')
        value['packet_b64']=encoded(driver.encode_json(packet));cases.append(value)
        for value in cases:
            key=bytes(range(32));purpose=b'CONFIDENTIAL-REVIEW-EVIDENCE'
            encrypted=public_runner.seal(driver.encode_json(value),key,purpose)
            recovered=public_runner.unseal(encrypted,key,purpose)
            with self.assertRaises(driver.GateError):
                pilot.verify_evidence(recovered,batch(),launch(),BASE,BASE+20*SECOND)
        with self.assertRaises(driver.GateError):
            operation(b'x'*(driver.MAX_PACKET+1),batch(),launch(),BASE,BASE+20*SECOND)


if __name__ == '__main__':
    unittest.main()
