"""Policy regressions for a PUBLIC-SYNTHETIC-ONLY Linux experiment."""
import copy,importlib.util,os,pathlib,subprocess,sys,unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
PROBE=ROOT/'tools'/'sandbox_probe.py'

class SandboxProbeTest(unittest.TestCase):
    def load_probe(self):
        self.assertTrue(PROBE.is_file(),'synthetic probe controller is missing')
        spec=importlib.util.spec_from_file_location('sandbox_probe',PROBE)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        return module
    def fixture(self):
        return {'Image':'sha256:synthetic-image',
                'Config':{'User':'65534:65534','Env':['PATH=/usr/local/bin:/usr/bin:/bin']},
                'HostConfig':{'ReadonlyRootfs':True,'NetworkMode':'none','CapDrop':['ALL'],
                    'CapAdd':None,'SecurityOpt':['no-new-privileges'],
                    'PidsLimit':32,'Memory':134217728,'MemorySwap':134217728,
                    'NanoCpus':1000000000,'PidMode':'','IpcMode':'private',
                    'Privileged':False,'PortBindings':{},'Devices':[],
                    'DeviceRequests':None,'LogConfig':{'Type':'none'},
                    'Tmpfs':{'/scratch':'rw,noexec,nosuid,nodev,size=16777216,mode=1777'}},
                'Mounts':[{'Type':'bind','Source':'/public/fixture.py','Destination':'/probe.py','RW':False},
                          {'Type':'bind','Source':'/synthetic/input','Destination':'/input','RW':False}]}
    def test_expected_configuration_is_accepted(self):
        module=self.load_probe()
        module.validate_inspection(self.fixture(),'sha256:synthetic-image',
                                   {'/probe.py':'/public/fixture.py','/input':'/synthetic/input'})
    def test_effective_unsafe_configuration_is_rejected(self):
        module=self.load_probe()
        changes=[('NetworkMode','bridge'),('Privileged',True),('ReadonlyRootfs',False),
                 ('CapAdd',['SYS_ADMIN']),('SecurityOpt',[]),('PidsLimit',0),
                 ('Memory',0),('MemorySwap',-1),('NanoCpus',0),('PidMode','host'),
                 ('IpcMode','host'),('PortBindings',{'80/tcp':[{'HostPort':'80'}]}),
                 ('Devices',[{'PathOnHost':'/dev/sda'}]),('LogConfig',{'Type':'json-file'})]
        for key,value in changes:
            with self.subTest(key=key):
                fixture=self.fixture();fixture['HostConfig'][key]=value
                with self.assertRaises(ValueError):
                    module.validate_inspection(fixture,'sha256:synthetic-image',
                        {'/probe.py':'/public/fixture.py','/input':'/synthetic/input'})
    def test_wrong_image_environment_and_mounts_are_rejected(self):
        module=self.load_probe()
        changes=[('Image','sha256:other'),('Config',{'User':'0','Env':[]}),
                 ('Config',{'User':'65534:65534','Env':['AI09_BUNDLE_KEY_B64=synthetic']}),
                 ('Mounts',[{'Type':'bind','Source':'/var/run/docker.sock',
                             'Destination':'/input','RW':True}])]
        for key,value in changes:
            with self.subTest(key=key,value=value):
                fixture=copy.deepcopy(self.fixture());fixture[key]=value
                with self.assertRaises(ValueError):
                    module.validate_inspection(fixture,'sha256:synthetic-image',
                        {'/probe.py':'/public/fixture.py','/input':'/synthetic/input'})
    def test_missing_runtime_fails_without_disclosing_environment(self):
        self.load_probe()
        env=dict(os.environ,PATH='',AI09_BUNDLE_KEY_B64='SYNTHETIC-MUST-NOT-PRINT')
        result=subprocess.run([sys.executable,'-I',str(PROBE)],env=env,
                              capture_output=True,text=True,timeout=10)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(result.stdout.splitlines(),['SYNTHETIC_PROBE_ERROR=LINUX_DOCKER_REQUIRED',
            'SYNTHETIC_SANDBOX_PROBE=FAIL; PRIVATE_RUNTIME_APPROVED=false'])
        self.assertEqual(result.stderr,'')
        self.assertNotIn('SYNTHETIC-MUST-NOT-PRINT',result.stdout)
    def test_missing_guest_readiness_fails_closed(self):
        module=self.load_probe()
        with self.assertRaises(TimeoutError):module.wait_for_ready(lambda:False,timeout_seconds=0)
        module.wait_for_ready(lambda:True,timeout_seconds=1)
    def test_log_stderr_canary_is_rejected(self):
        module=self.load_probe()
        with self.assertRaises(ValueError):
            module.validate_logs(subprocess.CompletedProcess([],1,'','PUBLIC-SYNTHETIC-STDERR-CANARY'))
        with self.assertRaises(ValueError):
            module.validate_logs(subprocess.CompletedProcess([],0,'PUBLIC-SYNTHETIC-STDOUT-CANARY',''))
        module.validate_logs(subprocess.CompletedProcess([],0,'',''))
        module.validate_logs(subprocess.CompletedProcess([],1,'',
            'Error response from daemon: configured logging driver does not support reading\n'))

if __name__=='__main__':unittest.main()
