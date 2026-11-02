"""Public controller lifecycle and safe failure diagnostics."""
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import unittest

PROBE = pathlib.Path(__file__).resolve().parents[1]/'tools'/'data_driver_probe.py'
spec = importlib.util.spec_from_file_location('data_driver_probe', PROBE)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class DriverProbeTest(unittest.TestCase):
    def test_failed_kill_is_not_a_substitute_for_stopped_state(self):
        for state, expected in [({'Running':False,'Pid':0,'Status':'exited'},True),
                                ({'Running':True,'Pid':123,'Status':'running'},False),
                                ({'Running':False,'Pid':123,'Status':'exited'},False)]:
            def docker(command, *args, **kwargs):
                if command == 'kill':
                    self.assertIs(kwargs['check'], False)
                    return subprocess.CompletedProcess([],1,'','PRIVATE-MUST-NOT-PRINT')
                if command == 'wait':
                    return subprocess.CompletedProcess([],0,'137\n','')
                return subprocess.CompletedProcess([],0,json.dumps([{'State':state}]),'')
            self.assertIs(probe.stop_container(docker,'host-owned-synthetic'),expected)

    def test_missing_runtime_has_only_fixed_public_diagnostics(self):
        result = subprocess.run([sys.executable,'-I',str(PROBE)],capture_output=True,
                                text=True,timeout=10,
                                env=dict(os.environ,PATH='',AI09_BUNDLE_KEY_B64='PRIVATE-CANARY'))
        self.assertEqual(result.returncode,2)
        self.assertEqual(result.stdout.splitlines(),[
            'SYNTHETIC_DRIVER_ERROR=LINUX_DOCKER_REQUIRED',
            'SYNTHETIC_DATA_DRIVER=FAIL; PRIVATE_RUNTIME_APPROVED=false'])
        self.assertEqual(result.stderr,'')


if __name__ == '__main__': unittest.main()
