"""PUBLIC-only input fixtures. No original bytes or actual-model evidence."""
import base64
import copy
import dataclasses
import hashlib
import importlib.util
import io
import json
import unittest
import zipfile
from unittest.mock import patch

import data_driver as driver
import context_probe
import pilot_batch
import public_runner
import source_archive as source
from test_data_driver import response
from test_context_probe import context_error
from test_pilot_batch import BASE, SECOND, observation, launch

frozen = (importlib.import_module('frozen_plan')
          if importlib.util.find_spec('frozen_plan') else None)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(plan, rehash=True):
    plan = copy.deepcopy(plan)
    if rehash:
        body = {k: v for k, v in plan.items() if k != 'plan_sha256'}
        canonical = json.dumps(body, sort_keys=True, ensure_ascii=False,
                               separators=(',', ':'), allow_nan=False).encode('utf-8')
        plan['plan_sha256'] = sha(canonical)
    return (json.dumps(plan, indent=2, ensure_ascii=False, allow_nan=False) + '\n').encode('utf-8')


def fixture(first_parts=None):
    files = {}; chunks = []
    for number in range(47):
        path = f'file{number:02}.txt'
        count = 3 if number < 10 else 2
        parts = ([b'\xe7\x95\x8c\n'] * count if number == 0 else
                 [f'PUBLIC-CANARY-{number}-{part}\n'.encode() for part in range(count)])
        if number == 0 and first_parts is not None:
            parts = first_parts
        data = b''.join(parts); files[path] = data; position = 0
        for part in parts:
            end = position + len(part)
            chunks.append({'index':len(chunks), 'path':path, 'start_byte':position,
                           'end_byte':end, 'start_line':data[:position].count(b'\n')+1,
                           'end_line':data[:end].count(b'\n')+1,
                           'sha256':sha(part), 'source_sha256':sha(data)})
            position = end
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('PUBLIC/manifest.json', b'{"PUBLIC":true}\n')
        for path, data in files.items():
            archive.writestr('PUBLIC/'+path, data)
    raw = stream.getvalue()
    plan = {'archive_sha256':sha(raw), 'chunk_count':104, 'chunks':chunks,
            'expected_status':'REVIEW_NOT_INVOKED', 'github_approval':False,
            'maker_model':'GPT-6', 'manifest_path':'manifest.json',
            'max_chunk_bytes':2300, 'merge_authorized':False,
            'review_target':'PUBLIC-審査', 'root_prefix':'PUBLIC/',
            'schema':1, 'source_file_count':47}
    return raw, plan, files


def verify_fixture(raw, plan_raw):
    # Test-only pins. Production callers have no expected-hash override.
    with patch.object(source, 'FROZEN_SHA', sha(raw)), \
         patch.object(frozen, 'FROZEN_PLAN_SHA', sha(plan_raw)):
        return frozen.verify_plan(raw, plan_raw)


class FrozenPlanTest(unittest.TestCase):
    def ready(self):
        self.assertIsNotNone(frozen, 'offline frozen input verifier missing')

    def test_chunk_representation_hides_source_and_path(self):
        chunk = driver.Chunk('000', 'PUBLIC-PRIVATE-PATH.py', 1, b'PUBLIC-SOURCE-CANARY\n')
        self.assertEqual(repr(chunk), 'Chunk()')

    def test_48_archive_files_47_sources_104_exact_spans_preserve_both_line_conventions(self):
        self.ready(); raw, plan, files = fixture(); original = encode(plan)
        result = verify_fixture(raw, original)
        self.assertEqual((result.source_sha, result.plan_sha), (sha(raw), sha(original)))
        self.assertEqual(result.canonical_plan_sha, json.loads(original)['plan_sha256'])
        self.assertNotEqual(result.plan_sha, result.canonical_plan_sha)
        self.assertEqual(len(result.spans), 104); self.assertEqual(len(result.chunks), 104)
        self.assertEqual(len({s.path for s in result.spans}), 47)
        self.assertEqual(result.spans[0].end_line, 2)
        self.assertEqual(result.spans[0].covered_end_line, 1)
        self.assertEqual(result.chunks[0].end_line, 1)
        for span, chunk in zip(result.spans, result.chunks):
            self.assertEqual(chunk.content, files[span.path][span.start_byte:span.end_byte])
            self.assertEqual(chunk.end_line, span.covered_end_line)
            self.assertEqual(chunk.chunk_id, f'{span.index:03}')
        self.assertEqual(repr(result), 'VerifiedPlan()')
        self.assertEqual(repr(result.spans[0]), 'FrozenSpan()')
        with self.assertRaises(dataclasses.FrozenInstanceError):result.spans[0].end_line = 1
        with self.assertRaises(dataclasses.FrozenInstanceError):result.chunks[0].content = b'other'

    def test_independent_pins_reject_replacement_before_parsing_and_cannot_be_overridden(self):
        self.ready(); raw, plan, _ = fixture(); original = encode(plan)
        self.assertEqual(frozen.FROZEN_PLAN_SHA,
                         'ad7c9a7b6914670c82b436ede89d543e8e09a3c0902448c9378fb6ab1aaecf44')
        with patch.object(source, 'FROZEN_SHA', sha(raw)), \
             patch.object(driver, 'parse_json', side_effect=AssertionError('must not parse')):
            with self.assertRaisesRegex(driver.GateError, '^FROZEN_PLAN_HASH_MISMATCH$'):
                frozen.verify_plan(raw, original)
        with self.assertRaises(TypeError):
            frozen.verify_plan(raw, original, expected_sha=sha(original))

    def test_types_size_depth_and_duplicate_keys_fail_closed(self):
        self.ready(); raw, plan, _ = fixture(); original = encode(plan)
        for archive, value in ((bytearray(raw),original),(b'',original),
                               (b'x'*(source.MAX_ARCHIVE+1),original),
                               (raw,bytearray(original)),(raw,b''),
                               (raw,b'x'*(source.MAX_PLAN+1))):
            with patch.object(driver, 'parse_json', side_effect=AssertionError('must not parse')):
                with self.assertRaises(driver.GateError):frozen.verify_plan(archive,value)
        for malformed in (original[:-2]+b',"schema":1}\n',b'['*25+b'0'+b']'*25):
            with self.assertRaises(driver.GateError):verify_fixture(raw,malformed)

    def test_root_schema_types_authority_and_canonical_hash_are_strict(self):
        self.ready(); raw, plan, _ = fixture()
        variants=[]
        for key,value in (('schema',True),('schema',2),('source_file_count',48),
                          ('chunk_count',103),('max_chunk_bytes',2301),
                          ('github_approval',0),('github_approval',True),
                          ('merge_authorized',0),('merge_authorized',True),
                          ('expected_status','APPROVED'),('maker_model',''),
                          ('review_target',''),('archive_sha256','d'*64)):
            changed=copy.deepcopy(plan);changed[key]=value;variants.append(encode(changed))
        for key in ('schema','chunks'):
            changed=copy.deepcopy(plan);del changed[key];variants.append(encode(changed))
        changed=copy.deepcopy(plan);changed['extra']=False;variants.append(encode(changed))
        changed=copy.deepcopy(plan);changed['plan_sha256']='d'*64
        variants.append(encode(changed,rehash=False))
        for candidate in variants:
            with self.assertRaises(driver.GateError):verify_fixture(raw,candidate)

    def test_prefix_paths_manifest_and_source_selection_are_exact(self):
        self.ready(); raw, plan, _ = fixture()
        for key,value in (('root_prefix','../PUBLIC/'),('root_prefix','/PUBLIC/'),
                          ('root_prefix','PUBLIC//'),('root_prefix','public/'),
                          ('manifest_path','file00.txt'),('manifest_path','MANIFEST.json'),
                          ('manifest_path','../manifest.json')):
            changed=copy.deepcopy(plan);changed[key]=value
            with self.assertRaises(driver.GateError):verify_fixture(raw,encode(changed))
        for path in ('../file00.txt','FILE00.txt','manifest.json','missing.txt','a\\b'):
            changed=copy.deepcopy(plan);changed['chunks'][0]['path']=path
            with self.assertRaises(driver.GateError):verify_fixture(raw,encode(changed))

    def test_chunk_shape_integer_aliases_hashes_and_line_bounds_are_strict(self):
        self.ready(); raw, plan, _ = fixture()
        variants=[]
        for key,value in (('index',True),('index',1),('start_byte',False),
                          ('end_byte',True),('end_byte',0),('start_line',True),
                          ('start_line',2),('end_line',True),('end_line',1),
                          ('sha256','d'*64),('source_sha256','d'*64)):
            changed=copy.deepcopy(plan);changed['chunks'][0][key]=value;variants.append(changed)
        changed=copy.deepcopy(plan);del changed['chunks'][0]['sha256'];variants.append(changed)
        changed=copy.deepcopy(plan);changed['chunks'][0]['extra']=0;variants.append(changed)
        changed=copy.deepcopy(plan);changed['chunks']=changed['chunks'][:-1];variants.append(changed)
        changed=copy.deepcopy(plan);changed['chunks'][-1]['index']=0;variants.append(changed)
        for candidate in variants:
            with self.assertRaises(driver.GateError):verify_fixture(raw,encode(candidate))

    def test_self_consistent_gaps_overlaps_and_missing_final_byte_fail_coverage(self):
        self.ready(); raw, plan, files = fixture()
        for index, field, delta in ((4,'start_byte',1),(4,'start_byte',-1),
                                    (103,'end_byte',-1)):
            changed=copy.deepcopy(plan);chunk=changed['chunks'][index];chunk[field]+=delta
            data=files[chunk['path']];start,end=chunk['start_byte'],chunk['end_byte']
            chunk['sha256']=sha(data[start:end]);chunk['start_line']=data[:start].count(b'\n')+1
            chunk['end_line']=data[:end].count(b'\n')+1
            with self.assertRaisesRegex(driver.GateError,'^FROZEN_PLAN_COVERAGE$'):
                verify_fixture(raw,encode(changed))

    def test_non_utf8_cut_and_oversized_chunk_are_rejected(self):
        self.ready(); raw, plan, files = fixture()
        changed=copy.deepcopy(plan);chunk=changed['chunks'][0];chunk['end_byte']=1
        chunk['sha256']=sha(files[chunk['path']][:1]);chunk['end_line']=1
        with self.assertRaises(driver.GateError):verify_fixture(raw,encode(changed))
        raw,plan,_=fixture([b'A'*2301+b'\n',b'PUBLIC\n',b'PUBLIC\n'])
        with self.assertRaises(driver.GateError):verify_fixture(raw,encode(plan))

    def test_crlf_bytes_are_preserved_but_unmatched_line_semantics_are_rejected(self):
        self.ready(); raw,plan,_=fixture([b'A\r\n']*3)
        result=verify_fixture(raw,encode(plan));self.assertEqual(result.chunks[0].content,b'A\r\n')
        raw,plan,_=fixture([b'A\rB\n']*3)
        with self.assertRaisesRegex(driver.GateError,'^FROZEN_PLAN_LINE_CONVENTION$'):
            verify_fixture(raw,encode(plan))

    def test_next_boundary_line_cannot_be_cited_in_a_finding(self):
        self.ready();raw,plan,_=fixture();result=verify_fixture(raw,encode(plan));chunk=result.chunks[0]
        request=driver.parse_json(driver.build_request(chunk))
        header=driver.parse_json(request['prompt'].split('\n',1)[1].encode('ascii'))
        self.assertEqual(header['end_line'],1)
        envelope=driver.parse_json(response(chunk.chunk_id))
        envelope['response']=json.dumps({'chunk_id':chunk.chunk_id,'findings':[{
            'file':chunk.path,'start_line':2,'end_line':2,'severity':'LOW',
            'explanation':'PUBLIC out-of-covered-line','recommendation':'PUBLIC'}]})
        with self.assertRaises(driver.GateError):driver.validate_response(driver.encode_json(envelope),chunk)

    def test_production_entry_still_refuses_before_io_or_model_use(self):
        self.ready();raw,plan,_=fixture();original=encode(plan)
        with patch.object(frozen,'verify_plan',side_effect=AssertionError('production must not call')):
            with self.assertRaisesRegex(driver.GateError,'^FROZEN_PLAN_SCHEMA_UNVERIFIED$'):
                driver.load_frozen_plan(raw,original)


class FrozenPilotInputTest(unittest.TestCase):
    """Bridge PUBLIC archive fixtures only; no private launch or real receipts."""

    def setUp(self):
        self.prepare = getattr(frozen, 'prepare_pilot_batch', None)
        self.assertTrue(callable(self.prepare), 'verified original-to-pilot input bridge missing')
        self.host = {'run_id':'456', 'attempt':2, 'commit':'d'*40}

    def prepare_fixture(self, raw, plan_raw, **host):
        # Only these test-generated PUBLIC bytes use replacement pins.
        with patch.object(source, 'FROZEN_SHA', sha(raw)), \
             patch.object(frozen, 'FROZEN_PLAN_SHA', sha(plan_raw)):
            return self.prepare(raw, plan_raw, **(host or self.host))

    def public_observation(self, batch):
        value = observation()
        value['context'] = batch.context()
        for record, chunk in zip(value['exchanges'], batch.chunks):
            reply = base64.b64decode(record['response_b64'], validate=True)
            record.update(driver.record_exchange(chunk, driver.build_request(chunk), reply))
        value['context_rejection'] = context_probe.record_rejection(
            batch, context_probe.public_request(), context_error(),
            BASE+18*SECOND, BASE+19*SECOND)
        expected_launch = launch()
        expected_launch['context'] = batch.context()
        expected_launch['staged_input_sha'] = sha(pilot_batch.encode_batch(batch))
        return driver.encode_json(value), expected_launch

    def test_raw_input_identity_first_eight_bytes_and_covered_lines_reach_staging(self):
        raw, plan, _ = fixture([b'\xe7\x95\x8c\r\n']*3)
        plan_raw = encode(plan)
        batch = self.prepare_fixture(raw, plan_raw)
        self.assertEqual(batch.context(), dict(self.host, source_sha=sha(raw), plan_sha=sha(plan_raw)))
        self.assertNotEqual(batch.plan_sha, json.loads(plan_raw)['plan_sha256'])
        self.assertEqual(tuple(chunk.chunk_id for chunk in batch.chunks),
                         ('000','001','002','003','004','005','006','007'))
        self.assertEqual(batch.chunks[0].content, b'\xe7\x95\x8c\r\n')
        self.assertEqual((batch.chunks[0].start_line, batch.chunks[0].end_line), (1,1))
        self.assertEqual((batch.chunks[2].start_line, batch.chunks[2].end_line), (3,3))
        self.assertEqual(batch.chunks[-1].content, b'PUBLIC-CANARY-2-1\n')
        self.assertEqual((batch.chunks[-1].start_line, batch.chunks[-1].end_line), (2,2))
        staged = pilot_batch.encode_batch(batch)
        self.assertEqual(pilot_batch.decode_batch(staged), batch)
        self.assertNotIn('file00', repr(batch))
        self.assertNotIn('CANARY', repr(batch))

    def test_only_fresh_raw_inputs_are_admitted_without_selectors_or_pin_overrides(self):
        raw, plan, _ = fixture(); plan_raw = encode(plan)
        verified = verify_fixture(raw, plan_raw)
        for value in (verified, bytearray(raw), 'PUBLIC/path.zip'):
            with self.subTest(value_type=type(value).__name__), self.assertRaises(driver.GateError):
                self.prepare(value, plan_raw, **self.host)
        for option in ({'start':8}, {'batch_index':1}, {'expected_sha':sha(raw)},
                       {'source_sha':sha(raw)}, {'verified':verified}):
            with self.subTest(option=tuple(option)), self.assertRaises(TypeError):
                self.prepare(raw, plan_raw, **self.host, **option)

    def test_replacement_inputs_fail_independent_hash_checks_before_parsing(self):
        raw, plan, _ = fixture(); plan_raw = encode(plan)
        with patch.object(driver, 'parse_json', side_effect=AssertionError('must not parse')):
            with self.assertRaisesRegex(driver.GateError, '^FROZEN_SOURCE_HASH_MISMATCH$'):
                self.prepare(raw, plan_raw, **self.host)
            with patch.object(source, 'FROZEN_SHA', sha(raw)):
                with self.assertRaisesRegex(driver.GateError, '^FROZEN_PLAN_HASH_MISMATCH$'):
                    self.prepare(raw, plan_raw, **self.host)

    def test_host_context_rejects_boolean_attempt_and_invalid_run_or_commit(self):
        raw, plan, _ = fixture(); plan_raw = encode(plan)
        for name, value in (('attempt',True), ('attempt',0), ('attempt','2'),
                            ('run_id','0'), ('run_id',456), ('run_id','456\n'),
                            ('commit','d'*39), ('commit','D'*40), ('commit',None)):
            host = dict(self.host); host[name] = value
            with self.subTest(field=name,value=value), self.assertRaises(driver.GateError):
                self.prepare_fixture(raw, plan_raw, **host)

    def test_corrupted_last_span_blocks_first_pilot_even_with_recomputed_hashes(self):
        raw, plan, files = fixture()
        changed = copy.deepcopy(plan)
        last = changed['chunks'][103]
        last['end_byte'] -= 1
        data = files[last['path']]
        last['sha256'] = sha(data[last['start_byte']:last['end_byte']])
        last['end_line'] = data[:last['end_byte']].count(b'\n')+1
        # Both canonical self-hash and test-only raw hash pin are recomputed.
        with self.assertRaisesRegex(driver.GateError, '^FROZEN_PLAN_COVERAGE$'):
            self.prepare_fixture(raw, encode(changed))

    def test_public_origin_to_observation_encryption_revalidates_against_host_input(self):
        raw, plan, _ = fixture(); plan_raw = encode(plan)
        batch = self.prepare_fixture(raw, plan_raw)
        packet, expected_launch = self.public_observation(batch)
        payload = pilot_batch.evidence_envelope(packet, batch, expected_launch, BASE, BASE+20*SECOND)
        # PUBLIC test material only. A launch label is not source provenance.
        key = bytes(range(32)); purpose = b'CONFIDENTIAL-REVIEW-EVIDENCE'
        encrypted = public_runner.seal(payload, key, purpose)
        recovered = public_runner.unseal(encrypted, key, purpose)
        replay = pilot_batch.verify_evidence(recovered, batch, expected_launch, BASE, BASE+20*SECOND)
        self.assertEqual(replay.payload, packet)
        self.assertEqual(replay.observed_responses, 8)
        self.assertEqual(replay.fixed_subject_receipts, 0)
        wrong_host = dataclasses.replace(batch, plan_sha=json.loads(plan_raw)['plan_sha256'])
        with self.assertRaises(driver.GateError):
            pilot_batch.verify_evidence(recovered, wrong_host, expected_launch, BASE, BASE+20*SECOND)

    def test_authenticated_context_substitution_and_seven_responses_are_rejected(self):
        raw, plan, _ = fixture(); batch = self.prepare_fixture(raw, encode(plan))
        packet, expected_launch = self.public_observation(batch)
        payload = pilot_batch.evidence_envelope(packet, batch, expected_launch, BASE, BASE+20*SECOND)
        envelope = driver.parse_json(payload, driver.MAX_PACKET)
        candidates = []
        changed = copy.deepcopy(envelope); changed['context']['attempt'] = 3; candidates.append(changed)
        changed = copy.deepcopy(envelope); incomplete = driver.parse_json(packet, driver.MAX_PACKET)
        incomplete['exchanges'].pop()
        changed['packet_b64'] = base64.b64encode(driver.encode_json(incomplete)).decode('ascii')
        candidates.append(changed)
        for candidate in candidates:
            encrypted = public_runner.seal(driver.encode_json(candidate), bytes(range(32)),
                                           b'CONFIDENTIAL-REVIEW-EVIDENCE')
            recovered = public_runner.unseal(encrypted, bytes(range(32)),
                                             b'CONFIDENTIAL-REVIEW-EVIDENCE')
            with self.assertRaises(driver.GateError):
                pilot_batch.verify_evidence(recovered, batch, expected_launch, BASE, BASE+20*SECOND)

    def test_preparing_offline_input_does_not_open_production_entry(self):
        raw, plan, _ = fixture(); plan_raw = encode(plan)
        self.prepare_fixture(raw, plan_raw)
        with self.assertRaisesRegex(driver.GateError, '^FROZEN_PLAN_SCHEMA_UNVERIFIED$'):
            driver.load_frozen_plan(raw, plan_raw)


if __name__=='__main__':unittest.main()
