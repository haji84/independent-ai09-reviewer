"""Public smoke admission fails before downloading on unsupported platforms."""
import os
import importlib.util
import io
import pathlib
import subprocess
import sys
import unittest
from unittest.mock import patch

import data_driver as driver


ROOT=pathlib.Path(__file__).resolve().parents[1]


def guest():
    spec=importlib.util.spec_from_file_location('public_model_guest',ROOT/'tests'/'fixtures'/'model_guest.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


class PublicModelSmokeTest(unittest.TestCase):
    def test_transport_and_schema_errors_use_distinct_fixed_codes_without_raw_text(self):
        module=guest()
        for failure,expected in ((driver.GateError('PRIVATE-CANARY'),'PUBLIC_MODEL_TRANSPORT_FAILED'),
                                 (b'PRIVATE-CANARY','PUBLIC_MODEL_RESPONSE_REJECTED')):
            output=io.BytesIO()
            with patch.object(module.subprocess,'Popen') as process,\
                 patch.object(module,'get_json',return_value=b'{}'),\
                 patch.object(module.assets,'validate_inventory'),\
                 patch.object(module,'post_json',side_effect=failure if isinstance(failure,Exception) else None,
                              return_value=failure if type(failure) is bytes else None),\
                 patch.object(module.sys,'argv',['guest.py','123','1','a'*40]),\
                 patch.object(module.sys,'stdout') as stdout:
                process.return_value.poll.return_value=None
                stdout.buffer=output
                module.experiment()
            self.assertEqual(driver.parse_json(output.getvalue()),{'error':expected})

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
