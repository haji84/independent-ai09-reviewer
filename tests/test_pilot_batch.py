"""PUBLIC eight-item observations, never original inputs or inference evidence."""
import base64
import contextlib
import copy
import dataclasses
import datetime
import importlib.util
import unittest
from unittest.mock import patch

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


def observation(expected=None):
    expected = expected or batch()
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


def launch(expected=None):
    expected = expected or batch()
    return {'image':'sha256:'+'d'*64,'runtime':{'bin/ollama':'e'*64},
            'driver':{'/guest.py':'f'*64},'ollama_archive':assets.OLLAMA_SHA,
            'model':assets.MODEL_SHA,'model_blobs':[['a'*64,100]],'context':expected.context(),
            'input_class':'PUBLIC_SYNTHETIC','staged_input_sha':driver.digest(pilot.encode_batch(expected)),
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


class FrozenEvidenceTest(unittest.TestCase):
    """Generated PUBLIC archives exercise a separate contract, never inference."""

    def setUp(self):
        self.envelope = getattr(pilot, 'frozen_evidence_envelope', None)
        self.verify = getattr(pilot, 'verify_frozen_evidence', None)
        self.assertTrue(callable(self.envelope), 'fresh original-input evidence envelope missing')
        self.assertTrue(callable(self.verify), 'fresh original-input evidence verification missing')
        # Import lazily: the fixture module imports this module's PUBLIC helpers.
        from test_frozen_plan import fixture, encode
        import frozen_plan
        self.frozen = frozen_plan
        self.encode_plan = encode
        self.archive, self.plan, self.files = fixture()
        self.plan_raw = encode(self.plan)
        self.host = {'run_id':'456', 'attempt':2, 'commit':'d'*40}
        with self.pins():
            self.expected = frozen_plan.prepare_pilot_batch(
                self.archive, self.plan_raw, **self.host)
        self.packet = driver.encode_json(observation(self.expected))
        self.expected_launch = launch(self.expected)
        self.expected_launch['input_class'] = 'FROZEN_DATA_ONLY'
        self.window = {'host_start':BASE, 'host_end':BASE+20*SECOND}

    @contextlib.contextmanager
    def pins(self, plan_raw=None):
        import source_archive
        # Only generated test data receives substituted pins. No production override.
        with patch.object(source_archive, 'FROZEN_SHA', driver.digest(self.archive)), \
             patch.object(self.frozen, 'FROZEN_PLAN_SHA', driver.digest(
                 self.plan_raw if plan_raw is None else plan_raw)):
            yield

    def options(self, **changes):
        return dict(self.host, launch=self.expected_launch, **self.window) | changes

    def make(self, packet=None):
        with self.pins():
            return self.envelope(self.packet if packet is None else packet,
                                 self.archive, self.plan_raw, **self.options())

    def replay(self, payload, **changes):
        with self.pins():
            return self.verify(payload, self.archive, self.plan_raw,
                               **self.options(**changes))

    def test_complete_original_packet_survives_encryption_with_no_authority_promotion(self):
        # Noncanonical whitespace must survive; the exact captured bytes are evidence.
        raw = b' \n'+self.packet+b'\n '
        payload = self.make(raw)
        value = driver.parse_json(payload, driver.MAX_PACKET)
        self.assertEqual(value['schema'], 'AI09-FROZEN-OBSERVED-EVIDENCE-v1')
        self.assertEqual(base64.b64decode(value['packet_b64']), raw)
        self.assertEqual(value['context'], dict(self.host,
            source_sha=driver.digest(self.archive), plan_sha=driver.digest(self.plan_raw)))
        self.assertEqual(value['launch'], self.expected_launch)
        encrypted = public_runner.seal(payload, bytes(range(32)), b'CONFIDENTIAL-REVIEW-EVIDENCE')
        recovered = public_runner.unseal(encrypted, bytes(range(32)), b'CONFIDENTIAL-REVIEW-EVIDENCE')
        verified = self.replay(recovered)
        self.assertEqual(verified.payload, raw)
        self.assertEqual(verified.observed_responses, 8)
        self.assertEqual(verified.fixed_subject_receipts, 0)
        self.assertEqual(repr(verified), 'ValidatedObservation()')

    def test_original_pins_cannot_be_replaced_by_matching_envelope_metadata(self):
        payload = self.make()
        for operation, content in ((self.envelope, self.packet), (self.verify, payload)):
            # Without test-only pins even a perfectly self-consistent fixture is refused.
            with self.assertRaisesRegex(driver.GateError, '^FROZEN_SOURCE_HASH_MISMATCH$'):
                operation(content, self.archive, self.plan_raw, **self.options())
            with self.pins():
                for archive, plan_raw, code in (
                    (self.archive+b'X', self.plan_raw, 'FROZEN_SOURCE_HASH_MISMATCH'),
                    (self.archive, self.plan_raw+b' ', 'FROZEN_PLAN_HASH_MISMATCH')):
                    with self.subTest(operation=operation.__name__, code=code), \
                         self.assertRaisesRegex(driver.GateError, '^'+code+'$'):
                        operation(content, archive, plan_raw, **self.options())

    def test_full_plan_is_revalidated_even_when_only_first_eight_are_observed(self):
        payload = self.make()
        broken = copy.deepcopy(self.plan)
        last = broken['chunks'][103]
        last['end_byte'] -= 1
        content = self.files[last['path']]
        last['sha256'] = driver.digest(content[last['start_byte']:last['end_byte']])
        last['end_line'] = content[:last['end_byte']].count(b'\n')+1
        broken_raw = self.encode_plan(broken)
        # Recompute both test pins and the self-hash: the actual missing byte still fails.
        with self.pins(broken_raw):
            for operation, content in ((self.envelope, self.packet), (self.verify, payload)):
                with self.subTest(operation=operation.__name__), \
                     self.assertRaisesRegex(driver.GateError, '^FROZEN_PLAN_COVERAGE$'):
                    operation(content, self.archive, broken_raw, **self.options())

    def test_public_and_frozen_classification_cannot_be_swapped(self):
        payload = self.make()
        public_launch = dict(self.expected_launch, input_class='PUBLIC_SYNTHETIC')
        public_payload = pilot.evidence_envelope(
            self.packet, self.expected, public_launch, **self.window)
        with self.assertRaises(driver.GateError):
            pilot.evidence_envelope(self.packet, self.expected, self.expected_launch, **self.window)
        with self.assertRaises(driver.GateError):
            pilot.verify_evidence(payload, self.expected, public_launch, **self.window)
        with self.pins():
            for operation, content in ((self.envelope, self.packet), (self.verify, payload)):
                with self.assertRaises(driver.GateError):
                    operation(content, self.archive, self.plan_raw,
                              **self.options(launch=public_launch))
            with self.assertRaises(driver.GateError):
                self.verify(public_payload, self.archive, self.plan_raw, **self.options())
        # Renaming a class field cannot disguise a PUBLIC-schema envelope.
        changed = driver.parse_json(public_payload, driver.MAX_PACKET)
        changed['launch']['input_class'] = 'FROZEN_DATA_ONLY'
        with self.assertRaises(driver.GateError):
            self.replay(driver.encode_json(changed))

    def test_external_run_launch_and_time_expectations_are_not_taken_from_payload(self):
        payload = self.make()
        changes = [dict(run_id='457'), dict(attempt=3), dict(commit='e'*40),
                   dict(host_start=BASE+SECOND), dict(host_end=BASE+21*SECOND),
                   dict(host_start=True)]
        for field in ('container_id', 'image'):
            changed = copy.deepcopy(self.expected_launch)
            changed[field] = ('sha256:' if field == 'image' else '')+'2'*64
            changes.append(dict(launch=changed))
        for change in changes:
            with self.subTest(field=tuple(change)), self.assertRaises(driver.GateError):
                self.replay(payload, **change)
        # A coherently changed run in both envelope and launch still differs from host.
        changed = driver.parse_json(payload, driver.MAX_PACKET)
        changed['context']['run_id'] = '457'
        changed['launch']['context']['run_id'] = '457'
        with self.assertRaises(driver.GateError):
            self.replay(driver.encode_json(changed))

    def test_authenticated_but_semantically_invalid_evidence_is_rejected(self):
        payload = self.make()
        cases = []
        for mode in ('missing', 'inventory', 'rehashed-request', 'reversed'):
            packet = driver.parse_json(self.packet, driver.MAX_PACKET)
            if mode == 'missing': packet['exchanges'].pop()
            elif mode == 'inventory': packet['tags_after'] = encoded(b'{}')
            elif mode == 'reversed': packet['exchanges'].reverse()
            else:
                record = packet['exchanges'][0]
                request = driver.parse_json(base64.b64decode(record['request_b64']))
                request['truncate'] = True
                request_raw = driver.encode_json(request)
                record['request_b64'] = encoded(request_raw)
                record['request_sha'] = driver.digest(request_raw)
            value = driver.parse_json(payload, driver.MAX_PACKET)
            value['packet_b64'] = encoded(driver.encode_json(packet))
            cases.append((mode, driver.encode_json(value)))
        for mode, altered in cases:
            encrypted = public_runner.seal(altered, bytes(range(32)), b'CONFIDENTIAL-REVIEW-EVIDENCE')
            recovered = public_runner.unseal(encrypted, bytes(range(32)), b'CONFIDENTIAL-REVIEW-EVIDENCE')
            with self.subTest(mode=mode), self.assertRaises(driver.GateError):
                self.replay(recovered)

    def test_no_batch_selector_verified_plan_or_hash_override_is_accepted(self):
        payload = self.make()
        with self.pins():
            for operation, content in ((self.envelope, self.packet), (self.verify, payload)):
                for option in (dict(expected=self.expected), dict(batch_index=1),
                               dict(source_sha=driver.digest(self.archive)),
                               dict(expected_sha=driver.digest(self.archive))):
                    with self.subTest(operation=operation.__name__, option=tuple(option)), \
                         self.assertRaises(TypeError):
                        operation(content, self.archive, self.plan_raw, **self.options(), **option)

    def test_packet_that_fits_capture_must_also_fit_base64_envelope(self):
        # For this 1021-byte launch, 2,000,000 total minus 131,072 reserved metadata
        # leaves 1,867,907 encoded bytes: at most 466,976 complete base64 groups.
        accepted_size, refused_size = 1_400_928, 1_400_929
        self.assertEqual(len(driver.encode_json(self.expected_launch)), 1021)
        accepted = self.packet+b' '*(accepted_size-len(self.packet))
        refused = self.packet+b' '*(refused_size-len(self.packet))
        self.assertEqual(pilot.verify_observation(
            refused, self.expected, **self.window).payload, refused)
        self.assertEqual(self.replay(self.make(accepted)).payload, accepted)
        for raw in (refused, self.packet+b' '*(2_000_001-len(self.packet))):
            with self.assertRaises(driver.GateError):
                self.make(raw)


if __name__ == '__main__':
    unittest.main()
