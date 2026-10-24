import base64,io,os,tempfile,unittest,zipfile
from pathlib import Path
from public_runner import seal,unseal,seal_evidence,open_bundle,key_from_env

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
if __name__=='__main__':unittest.main()
