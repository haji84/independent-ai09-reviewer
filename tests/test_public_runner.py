import base64,hashlib,io,os,struct,tempfile,tracemalloc,unittest,zipfile,zlib
from unittest.mock import patch
from pathlib import Path
from public_runner import seal,unseal,seal_evidence,open_bundle,key_from_env,SUBJECT,MAX_ENCRYPTED

class PublicBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.key=bytes(range(32))
        os.environ['AI09_BUNDLE_KEY_B64']=base64.b64encode(self.key).decode()
    def tearDown(self):os.environ.pop('AI09_BUNDLE_KEY_B64',None)
    def test_secret_required(self):
        del os.environ['AI09_BUNDLE_KEY_B64']
        with self.assertRaises(ValueError):key_from_env()
    def test_roundtrip(self):
        msg=b'secret source and findings'
        enc=seal(msg,self.key,b'FROZEN-SOURCE-BUNDLE')
        self.assertEqual(msg,unseal(enc,self.key,b'FROZEN-SOURCE-BUNDLE'))
        self.assertNotIn(msg,enc)
    def test_wrong_key(self):
        enc=seal(b'private',self.key,b'FROZEN-SOURCE-BUNDLE')
        with self.assertRaises(Exception):unseal(enc,b'k'*32,b'FROZEN-SOURCE-BUNDLE')
    def test_tamper(self):
        enc=bytearray(seal(b'private',self.key,b'FROZEN-SOURCE-BUNDLE'))
        enc[-1]^=1
        with self.assertRaises(Exception):unseal(bytes(enc),self.key,b'FROZEN-SOURCE-BUNDLE')
    def test_domain_separation(self):
        enc=seal(b'private',self.key,b'FROZEN-SOURCE-BUNDLE')
        with self.assertRaises(Exception):unseal(enc,self.key,b'CONFIDENTIAL-REVIEW-EVIDENCE')
    def test_sha_mismatch(self):
        mem=io.BytesIO()
        with zipfile.ZipFile(mem,'w') as z:z.writestr('universal-ai-development-v0.5-review-candidate.zip',b'wrong')
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'cipher';p.write_bytes(seal(mem.getvalue(),self.key,b'FROZEN-SOURCE-BUNDLE'))
            with self.assertRaises(ValueError):open_bundle(p,Path(t)/'out')
            self.assertFalse((Path(t)/'out').exists())
    def test_traversal(self):
        mem=io.BytesIO()
        with zipfile.ZipFile(mem,'w') as z:z.writestr('../escape.txt',b'bad')
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'cipher';p.write_bytes(seal(mem.getvalue(),self.key,b'FROZEN-SOURCE-BUNDLE'))
            with self.assertRaises(ValueError):open_bundle(p,Path(t)/'out')
    def test_seal_evidence(self):
        with tempfile.TemporaryDirectory() as t:
            d=Path(t)/'receipts';d.mkdir()
            (d/'chunk-000.json').write_text('{"finding":"secret-code"}')
            output=Path(t)/'evidence.aesgcm'
            self.assertEqual(seal_evidence(d,output),1)
            self.assertNotIn(b'secret-code',output.read_bytes())
            raw=unseal(output.read_bytes(),self.key,b'CONFIDENTIAL-REVIEW-EVIDENCE')
            with zipfile.ZipFile(io.BytesIO(raw)) as z:self.assertIn(b'secret-code',z.read('chunk-000.json'))
    def test_unexpected_evidence_fails(self):
        with tempfile.TemporaryDirectory() as t:
            d=Path(t)/'receipts';d.mkdir()
            (d/'chunk-000.json').write_text('{}')
            (d/'dump.txt').write_text('unapproved')
            with self.assertRaises(ValueError):seal_evidence(d,Path(t)/'sealed')
    def synthetic_bundle(self, entries):
        mem=io.BytesIO()
        with zipfile.ZipFile(mem,'w',compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr(SUBJECT,b'PUBLIC-SYNTHETIC-SUBJECT')
            for name,content in entries:z.writestr(name,content)
        return mem.getvalue()
    def test_file_directory_collisions_leave_no_plaintext(self):
        for entries in ([('a',b'first'),('a/child',b'second')],
                        [('a/child',b'first'),('a',b'second')],
                        [('A',b'first'),('a/child',b'second')]):
            with self.subTest(entries=entries),tempfile.TemporaryDirectory() as t:
                p=Path(t)/'cipher'
                p.write_bytes(seal(self.synthetic_bundle(entries),self.key,b'FROZEN-SOURCE-BUNDLE'))
                with patch('public_runner.FROZEN_SHA',hashlib.sha256(b'PUBLIC-SYNTHETIC-SUBJECT').hexdigest()):
                    with self.assertRaises(ValueError):open_bundle(p,Path(t)/'out')
                self.assertFalse((Path(t)/'out').exists())
    def test_nul_zip_alias_rejected_before_output(self):
        payload=self.synthetic_bundle([('safeXpayload',b'public')]).replace(b'safeXpayload',b'safe\x00payload')
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'cipher';p.write_bytes(seal(payload,self.key,b'FROZEN-SOURCE-BUNDLE'))
            with patch('public_runner.FROZEN_SHA',hashlib.sha256(b'PUBLIC-SYNTHETIC-SUBJECT').hexdigest()):
                with self.assertRaises(ValueError):open_bundle(p,Path(t)/'out')
            self.assertFalse((Path(t)/'out').exists())
    def test_underdeclared_compression_cannot_allocate_full_stream(self):
        payload=bytearray(self.synthetic_bundle([('bomb',b'A'*2_000_000)]))
        # Forge both ZIP size/CRC records; ZipExtFile trims output to the declared byte.
        for signature,size_offset,crc_offset in ((b'PK\x03\x04',22,14),(b'PK\x01\x02',24,16)):
            at=payload.rfind(signature)
            struct.pack_into('<I',payload,at+size_offset,1)
            struct.pack_into('<I',payload,at+crc_offset,zlib.crc32(b'A'))
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'cipher';p.write_bytes(seal(bytes(payload),self.key,b'FROZEN-SOURCE-BUNDLE'))
            with patch('public_runner.FROZEN_SHA',hashlib.sha256(b'PUBLIC-SYNTHETIC-SUBJECT').hexdigest()):
                tracemalloc.start()
                try:
                    open_bundle(p,Path(t)/'out')
                    peak=tracemalloc.get_traced_memory()[1]
                finally:tracemalloc.stop()
            self.assertLess(peak,4_000_000,'unbounded decompression allocated the forged full stream')
    def test_unbounded_compression_methods_rejected_before_output(self):
        for compression in (zipfile.ZIP_BZIP2,zipfile.ZIP_LZMA):
            with self.subTest(compression=compression),tempfile.TemporaryDirectory() as t:
                mem=io.BytesIO()
                with zipfile.ZipFile(mem,'w',compression=compression) as z:
                    z.writestr(SUBJECT,b'PUBLIC-SYNTHETIC-SUBJECT')
                p=Path(t)/'cipher';p.write_bytes(seal(mem.getvalue(),self.key,b'FROZEN-SOURCE-BUNDLE'))
                with patch('public_runner.FROZEN_SHA',hashlib.sha256(b'PUBLIC-SYNTHETIC-SUBJECT').hexdigest()):
                    with self.assertRaises(ValueError):open_bundle(p,Path(t)/'out')
                self.assertFalse((Path(t)/'out').exists())
    def test_seal_refuses_payload_that_unseal_cannot_read(self):
        with self.assertRaises(ValueError):seal(b'A'*MAX_ENCRYPTED,self.key,b'FROZEN-SOURCE-BUNDLE')
    def test_oversized_evidence_does_not_create_artifact(self):
        with tempfile.TemporaryDirectory() as t:
            d=Path(t)/'receipts';d.mkdir()
            for n in range(51):(d/f'chunk-{n:03d}.json').write_bytes(os.urandom(99_999))
            output=Path(t)/'evidence.aesgcm'
            with self.assertRaises(ValueError):seal_evidence(d,output)
            self.assertFalse(output.exists())
    def test_non_ascii_or_out_of_scope_chunk_names_rejected(self):
        for name in ('chunk-\u0660\u0660\u0660.json','chunk-104.json','chunk-999.json'):
            with self.subTest(name=name),tempfile.TemporaryDirectory() as t:
                d=Path(t)/'receipts';d.mkdir();(d/name).write_text('{}')
                output=Path(t)/'evidence.aesgcm'
                with self.assertRaises(ValueError):seal_evidence(d,output)
                self.assertFalse(output.exists())
    def test_maximum_sealed_payload_roundtrips(self):
        # Ten-byte magic + 12-byte nonce + 16-byte GCM tag.
        msg=b'P'*(MAX_ENCRYPTED-38)
        enc=seal(msg,self.key,b'CONFIDENTIAL-REVIEW-EVIDENCE')
        self.assertEqual(len(enc),5_000_000)
        self.assertEqual(unseal(enc,self.key,b'CONFIDENTIAL-REVIEW-EVIDENCE'),msg)
if __name__=='__main__':unittest.main()
