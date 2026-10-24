"""Static guard against source and key leakage in public Actions logs."""
import pathlib,re,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
WF=ROOT/'.github'/'workflows'/'ai09-public-safe-pilot.yml'
class PublicWorkflowBoundaryTest(unittest.TestCase):
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
