"""Public smoke admission fails before downloading on unsupported platforms."""
import os
import pathlib
import subprocess
import sys
import unittest


class PublicModelSmokeTest(unittest.TestCase):
    def test_missing_runtime_has_only_fixed_diagnostics(self):
        path=pathlib.Path(__file__).resolve().parents[1]/'tools'/'public_model_smoke.py'
        result=subprocess.run([sys.executable,'-I',str(path)],env=dict(os.environ,PATH=''),
                              capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,2)
        self.assertEqual(result.stderr,'')
        self.assertEqual(result.stdout.splitlines(),[
            'PUBLIC_MODEL_ERROR=LINUX_DOCKER_ZSTD_REQUIRED',
            'PUBLIC_MODEL_SMOKE=FAIL; FIXED_SUBJECT_RECEIPTS=0; DESIGN_APPROVAL=HOLD'])


if __name__=='__main__':unittest.main()
