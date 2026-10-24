"""Static guard against source and key leakage in public Actions logs."""
import os,pathlib,re,shutil,subprocess,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
WF=ROOT/'.github'/'workflows'/'ai09-public-safe-pilot.yml'
class PublicWorkflowBoundaryTest(unittest.TestCase):
    def test_admission_fails_before_checkout_without_secret(self):
        first=WF.read_text().split('    steps:',1)[1].split('\n      - ',2)[1]
        self.assertNotIn('uses:',first,'no action may run before the HOLD')
        script=re.search(r'        run: \|\n((?:          .*\n?)+)',first)
        self.assertIsNotNone(script,'first step must enforce HOLD')
        script='\n'.join(line[10:] for line in script.group(1).splitlines())
        bash=shutil.which('bash')
        if os.name=='nt':bash=r'C:\Program Files\Git\bin\bash.exe'
        self.assertTrue(bash and pathlib.Path(bash).is_file(),'bash required for admission test')
        with tempfile.TemporaryDirectory() as t:
            env={'PATH':os.environ.get('PATH',''),'RUNNER_TEMP':t,'GITHUB_REF':'refs/heads/main',
                 'AI09_ENABLE_PILOT':'true','AI09_BUNDLE_KEY_B64':'PUBLIC-SYNTHETIC-NONKEY'}
            result=subprocess.run([bash,'--noprofile','--norc'],input=script,text=True,
                                  cwd=t,env=env,capture_output=True,timeout=10)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('INDEPENDENT_REVIEW_NOT_PERFORMED',result.stdout)
            self.assertNotIn('PUBLIC-SYNTHETIC-NONKEY',result.stdout+result.stderr)
            self.assertEqual(list(pathlib.Path(t).iterdir()),[])
    def test_always_steps_cannot_receive_secret_or_upload_after_admission_failure(self):
        s=WF.read_text()
        sealing=s.split('      - name: Encrypt any real evidence before artifact boundary',1)[1].split('      - name:',1)[0]
        upload=s.split('      - name: Upload encrypted evidence ONLY',1)[1]
        self.assertIn("steps.open_bundle.outcome == 'success'",sealing)
        self.assertIn("steps.seal_evidence.outcome == 'success'",upload)
        self.assertIn('id: open_bundle',s)
        self.assertIn('id: seal_evidence',sealing)
    def test_only_manual_dispatch(self):
        s=WF.read_text()
        self.assertIn('workflow_dispatch:',s)
        self.assertNotRegex(s,r'(?m)^\s+push:\s*$')
        self.assertNotRegex(s,r'(?m)^\s+pull_request:\s*$')
        self.assertIn("if: github.ref == 'refs/heads/main'",s)
    def test_readonly_permissions(self):
        s=WF.read_text()
        self.assertEqual(s.count('contents: read'),2)
        self.assertNotRegex(s,r'(?m)^\s+contents: write\s*$')
        self.assertIn('persist-credentials: false',s)
    def test_secret_is_step_scoped_not_global(self):
        s=WF.read_text()
        head=s.split('    steps:',1)[0]
        self.assertNotIn('AI09_BUNDLE_KEY_B64:',head)
        self.assertEqual(s.count('AI09_BUNDLE_KEY_B64: ${{ secrets.AI09_BUNDLE_KEY_B64 }}'),2)
    def test_private_outputs_are_suppressed(self):
        s=WF.read_text()
        for name in ('ai09-private-tests.log','ai09-private-plan.log',
                     'private-inventory.log','private-inference.log','private-verify.log'):
            self.assertIn(name,s)
        self.assertIn('PRIVATE_AI09_INFERENCE_FAILED',s)
        self.assertIn('Upload encrypted evidence ONLY',s)
        self.assertIn('ai09-public-artifacts/*.aesgcm',s)
        self.assertNotIn('upload-artifact@v4\n        with:\n          name: private',s)
    def test_source_is_checksum_pinned_and_receipts_not_granted(self):
        s=WF.read_text()
        self.assertIn('9cf979733d8d4753023b1dd239ba4a5f3be2e0a6a3216c9dda206c089a2b6aa5',s)
        self.assertIn('FULL_REVIEW_NOT_APPROVED',s)
        self.assertIn('--start 0 --end 8',s)
if __name__=='__main__':unittest.main()
