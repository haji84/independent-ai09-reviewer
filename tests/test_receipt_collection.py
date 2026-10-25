"""PUBLIC fake receipts; completeness never implies original/model coverage."""
import base64
import copy
import dataclasses
import importlib
import unittest
from unittest.mock import patch

import data_driver as driver
from public_runner import seal,unseal
from test_data_driver import response

try:
    collection=importlib.import_module('receipt_collection')
except ModuleNotFoundError:
    collection=None


def fixtures(shared_run=False):
    expected=[];packets=[]
    for ordinal in range(13):
        chunks=tuple(driver.Chunk(f'{i:03}',f'PUBLIC/file{i%47:02}.py',1,
                                  f'# PUBLIC-SYNTHETIC-COLLECTION-{i}\n'.encode())
                     for i in range(ordinal*8,ordinal*8+8))
        batch=driver.Batch('1000' if shared_run else str(1000+ordinal),1,'a'*40,'b'*64,'c'*64,chunks)
        records=[driver.record_exchange(chunk,driver.build_request(chunk),response(chunk.chunk_id)) for chunk in chunks]
        expected.append(batch);packets.append(driver.make_packet(batch,records))
    return tuple(expected),tuple(packets)


class ReceiptCollectionTest(unittest.TestCase):
    def ready(self):self.assertIsNotNone(collection,'104 receipt collection verifier is missing')

    def test_complete_13_by_8_preserves_exact_raw_packets_and_synthetic_classification(self):
        self.ready();expected,packets=fixtures()
        result=collection.assemble_synthetic_collection(expected,packets)
        value=driver.parse_json(result.payload,driver.MAX_PACKET)
        self.assertEqual(tuple(base64.b64decode(x,validate=True) for x in value['packets_b64']),packets)
        self.assertEqual(result.evidence_kind,'SYNTHETIC')
        self.assertEqual(result.synthetic_receipts,104);self.assertEqual(result.fixed_subject_receipts,0)
        ids=[chunk['chunk_id'] for batch in value['index']['batches'] for chunk in batch['chunks']]
        self.assertEqual(ids,[f'{i:03}' for i in range(104)])
        for ordinal,index in enumerate(value['index']['batches']):
            self.assertEqual(index['ordinal'],ordinal);self.assertEqual(index['context'],expected[ordinal].context())
            self.assertEqual(index['packet_sha'],driver.digest(packets[ordinal]))
        with self.assertRaises(dataclasses.FrozenInstanceError):result.fixed_subject_receipts=104
        with self.assertRaises(ValueError):dataclasses.replace(result,evidence_kind='REAL')

    def test_shared_run_attempt_and_repeat_verification_are_valid_without_persistent_replay_claim(self):
        self.ready();expected,packets=fixtures(shared_run=True)
        result=collection.assemble_synthetic_collection(expected,packets)
        for _ in range(2):
            self.assertEqual(collection.verify_synthetic_collection(result.payload,expected).payload,result.payload)

    def test_missing_extra_reordered_or_duplicate_batch_never_returns_partial_success(self):
        self.ready();expected,packets=fixtures()
        variants=(packets[:-1],packets+(packets[-1],),(packets[1],packets[0])+packets[2:],
                  (packets[0],packets[0])+packets[2:],packets[:-1]+(b'{}',))
        for changed in variants:
            with self.assertRaises(driver.GateError):collection.assemble_synthetic_collection(expected,changed)

    def test_host_expectations_require_exact_ids_counts_and_common_subject(self):
        self.ready();expected,packets=fixtures()
        variants=[expected[:-1],expected+(expected[-1],),(expected[0],)*13,
                  (dataclasses.replace(expected[0],chunks=expected[0].chunks[:4]),)+expected[1:]]
        for field,value in (('commit','d'*40),('source_sha','d'*64),('plan_sha','d'*64),('attempt',2),('run_id','9999')):
            variants.append((dataclasses.replace(expected[0],**{field:value}),)+expected[1:])
        for changed in variants:
            with self.assertRaises(driver.GateError):collection.assemble_synthetic_collection(changed,packets)

    def test_aggregate_base64_expansion_is_rejected_before_packet_parsing(self):
        self.ready();expected,_=fixtures();packets=(b'x'*150000,)*13
        self.assertLess(sum(map(len,packets)),driver.MAX_PACKET)
        with patch.object(driver,'verify_synthetic_packet',side_effect=AssertionError('must not parse')):
            with self.assertRaisesRegex(driver.GateError,'^COLLECTION_SIZE_LIMIT$'):
                collection.assemble_synthetic_collection(expected,packets)

    def test_input_objects_and_packet_byte_types_are_strict(self):
        self.ready();expected,packets=fixtures()
        for host,data in ((list(expected),packets),(expected,list(packets)),
                          (expected,(bytearray(packets[0]),)+packets[1:])):
            with self.assertRaises(driver.GateError):collection.assemble_synthetic_collection(host,data)

    def test_reader_rebuilds_index_and_rejects_classification_context_and_packet_tampering(self):
        self.ready();expected,packets=fixtures();result=collection.assemble_synthetic_collection(expected,packets)
        good=driver.parse_json(result.payload,driver.MAX_PACKET);variants=[]
        for key,value in (('evidence_kind','REAL'),('synthetic_receipts',103),('fixed_subject_receipts',False)):
            changed=copy.deepcopy(good);changed['index'][key]=value;variants.append(changed)
        changed=copy.deepcopy(good);changed['index']['batches'][0]['packet_sha']='d'*64;variants.append(changed)
        changed=copy.deepcopy(good);changed['index']['batches'][0]['context']['attempt']=True;variants.append(changed)
        changed=copy.deepcopy(good);changed['index']['batches'][0]['chunks'][0]['input_sha']='d'*64;variants.append(changed)
        for key,value in (('schema','REAL'),('extra',0),('packets_b64',['!']*13),('packets_b64',[])):
            changed=copy.deepcopy(good);changed[key]=value;variants.append(changed)
        changed=copy.deepcopy(good);packet=driver.parse_json(packets[0],driver.MAX_PACKET)
        packet['context']['attempt']=2
        changed['packets_b64'][0]=base64.b64encode(driver.encode_json(packet)).decode();variants.append(changed)
        changed=copy.deepcopy(good);changed['packets_b64'][0]=base64.b64encode(packets[0]+b'{}').decode();variants.append(changed)
        for changed in variants:
            with self.assertRaises(driver.GateError):collection.verify_synthetic_collection(driver.encode_json(changed),expected)
        with self.assertRaises(driver.GateError):collection.verify_synthetic_collection(result.payload+b'{}',expected)

    def test_oversized_decrypted_collection_rejected_before_json_parse(self):
        self.ready();expected,_=fixtures()
        with patch.object(driver,'parse_json',side_effect=AssertionError('must not parse')):
            with self.assertRaisesRegex(driver.GateError,'^COLLECTION_SIZE_LIMIT$'):
                collection.verify_synthetic_collection(b'x'*(driver.MAX_PACKET+1),expected)

    def test_exact_payload_seal_unseal_and_fresh_semantic_verification(self):
        self.ready();expected,packets=fixtures();result=collection.assemble_synthetic_collection(expected,packets)
        key=bytes(range(32))  # PUBLIC synthetic key; no environment or secret access
        purpose=b'CONFIDENTIAL-REVIEW-EVIDENCE'
        encrypted=seal(result.payload,key,purpose);decrypted=unseal(encrypted,key,purpose)
        self.assertEqual(decrypted,result.payload);self.assertNotIn(result.payload,encrypted)
        verified=collection.verify_synthetic_collection(decrypted,expected)
        self.assertEqual(verified.synthetic_receipts,104);self.assertEqual(verified.fixed_subject_receipts,0)
        invalid=driver.parse_json(decrypted,driver.MAX_PACKET);invalid['index']['fixed_subject_receipts']=104
        authenticated=seal(driver.encode_json(invalid),key,purpose)
        with self.assertRaises(driver.GateError):collection.verify_synthetic_collection(unseal(authenticated,key,purpose),expected)


if __name__=='__main__':unittest.main()
