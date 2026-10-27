"""PUBLIC-only input fixtures. No original bytes or actual-model evidence."""
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
import source_archive as source
from test_data_driver import response

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


if __name__=='__main__':unittest.main()
