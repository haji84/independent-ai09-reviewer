"""Real process/pipe/file lifecycle with deterministic PUBLIC 47/104 fixtures."""
import base64
import contextlib
import importlib.util
import io
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import data_driver as driver
import frozen_plan
import pilot_host
import public_runner
import sealed_input
import source_archive
from fixtures.private_pilot_child import public_inputs, KEY

private = __import__('private_pilot') if importlib.util.find_spec('private_pilot') else None
ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURE = ROOT/'tests/fixtures/private_pilot_child.py'
COMMIT = 'a'*40


@contextlib.contextmanager
def public_connection(mode='success', *, budget=2.0):
    """Only tests substitute the fixed child executable and external Docker."""
    archive, plan = public_inputs()
    with patch.object(source_archive,'FROZEN_SHA',driver.digest(archive)), \
         patch.object(frozen_plan,'FROZEN_PLAN_SHA',driver.digest(plan)):
        cipher=sealed_input.seal_frozen_input(archive,plan,KEY)
    with tempfile.TemporaryDirectory(prefix='ai09-public-connection-') as name:
        root=pathlib.Path(name);(root/'sealed').mkdir();(root/'runner').mkdir(mode=0o700)
        (root/'sealed/ai09-private-bundle.aesgcm').write_bytes(cipher)
        env={'GITHUB_REPOSITORY':'haji84/independent-ai09-reviewer','GITHUB_REF':'refs/heads/main',
             'GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_ACTOR':'haji84','GITHUB_RUN_ID':'123',
             'GITHUB_RUN_ATTEMPT':'1','GITHUB_SHA':COMMIT,'RUNNER_TEMP':str(root/'runner'),
             'AI09_APPROVED_MAIN_SHA':COMMIT,'AI09_INPUT_CIPHERTEXT_SHA256':driver.digest(cipher),
             'AI09_INPUT_CIPHERTEXT_BYTES':str(len(cipher)),
             'AI09_BUNDLE_KEY_B64':base64.b64encode(KEY).decode(),
             'GITHUB_TOKEN':'PUBLIC-TOKEN-CANARY','GITHUB_OUTPUT':'PUBLIC-COMMAND-CANARY',
             'GITHUB_ENV':'PUBLIC-COMMAND-CANARY','UNRELATED':'PUBLIC-UNRELATED-CANARY',
             'HTTPS_PROXY':'http://public-proxy.example:8123','NO_PROXY':'localhost'}
        processes=[];commands=[];launches=[];real_popen=subprocess.Popen
        def spawn(args,**kwargs):
            launches.append((args,kwargs))
            if args[3] != str(root/'tools/private_pilot.py') or args[4] != '--child':
                raise AssertionError('production child dispatcher changed')
            process=real_popen([sys.executable,'-I','-B',str(FIXTURE),mode,*args[5:]],**kwargs)
            processes.append(process);return process
        def docker(state,*args,**kwargs):
            commands.append((args,kwargs,state.cleanup_deadline))
            return subprocess.CompletedProcess(['docker',*args],0,'','')
        with patch.dict(os.environ,env,clear=True),patch.object(private,'ROOT',root), \
             patch.object(private,'_WORK_SECONDS',budget),patch.object(private,'_CLEANUP_SECONDS',budget+0.6), \
             patch.object(private,'_TERM_GRACE_SECONDS',0.1),patch.object(private,'_KILL_GRACE_SECONDS',0.1), \
             patch.object(private.subprocess,'Popen',spawn),patch.object(pilot_host,'_docker',docker):
            yield {'root':root,'archive':archive,'plan':plan,'cipher':cipher,'env':env,
                   'processes':processes,'commands':commands,'launches':launches}
        for process in processes:
            if process.poll() is None:
                os.killpg(process.pid,signal.SIGKILL);process.wait(timeout=1)
                raise AssertionError('coordinator left a live PUBLIC fixture child')


@unittest.skipUnless(sys.platform=='linux','Linux pipe/host contract; mandatory Linux CI')
class PrivatePilotTest(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(private,'bounded private coordinator is missing')

    def fail_closed(self):
        with self.assertRaises(driver.GateError) as error: private.coordinate()
        self.assertIn(str(error.exception),('PRIVATE_PILOT_FAILED','CLEANUP_UNVERIFIED'))
        self.assertIsNone(error.exception.__cause__)
        self.assertTrue(error.exception.__suppress_context__)

    def test_actual_coordinator_term_cleans_child_after_ready(self):
        result=subprocess.run([sys.executable,'-I','-B',str(FIXTURE),'coordinator-term'],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=4,
            env={'PATH':os.defpath,'LD_LIBRARY_PATH':str(pathlib.Path(sys.base_prefix)/'lib')})
        self.assertEqual(result.returncode,0)
        self.assertEqual(result.stdout,b'FIXTURE_CANCELLED_AND_REAPED')
        self.assertEqual(result.stderr,b'')

    def test_real_large_pipe_roundtrip_emits_only_verified_observation(self):
        with public_connection() as fixture:
            stdout=io.StringIO();stderr=io.StringIO()
            with contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stderr):
                self.assertEqual(private.main([]),0)
            line=stdout.getvalue();self.assertTrue(line.startswith('AI09_HOST_OBSERVATION='))
            self.assertEqual(line.count('\n'),1);self.assertEqual(stderr.getvalue(),'')
            observation=driver.parse_json(line.split('=',1)[1][:-1].encode())
            self.assertEqual(observation['run_id'],'123');self.assertEqual(observation['attempt'],1)
            self.assertEqual(observation['observed_responses'],8)
            self.assertEqual(observation['input_class'],'FROZEN_DATA_ONLY')
            self.assertGreater(len(fixture['cipher']),65_536)
            path=fixture['root']/'runner/ai09-private-pilot-123-1'/pilot_host.EVIDENCE_FILENAME
            encrypted=path.read_bytes();self.assertEqual(driver.digest(encrypted),observation['output_ciphertext_sha256'])
            payload=driver.parse_json(public_runner.unseal(encrypted,KEY,pilot_host.PURPOSE),driver.MAX_PACKET)
            packet=driver.parse_json(base64.b64decode(payload['packet_b64']),driver.MAX_PACKET)
            self.assertEqual([v['chunk_id'] for v in packet['exchanges']],[f'{i:03}' for i in range(8)])
            self.assertEqual(observation['launch_sha256'],driver.digest(driver.encode_json(payload['launch'])))
            self.assertEqual((observation['host_start_ns'],observation['host_end_ns']),
                             (payload['host_start'],payload['host_end']))
            self.assertEqual(fixture['commands'],[],'success must use the child host cleanup')
            args,kw=fixture['launches'][0]
            self.assertEqual(args[:3],[sys.executable,'-I','-B'])
            self.assertTrue(kw['close_fds']);self.assertTrue(kw['start_new_session'])
            self.assertEqual(kw['env']['HTTPS_PROXY'],'http://public-proxy.example:8123')
            for name in ('AI09_BUNDLE_KEY_B64','GITHUB_TOKEN','GITHUB_OUTPUT','GITHUB_ENV','UNRELATED'):
                self.assertNotIn(name,kw['env'])
            for canary in ('PUBLIC-TOKEN-CANARY','PUBLIC-COMMAND-CANARY',base64.b64encode(KEY).decode()):
                self.assertNotIn(canary,line+repr(args)+repr(kw['env']))

    def test_invalid_admission_fails_before_spawn_input_or_key(self):
        with public_connection() as fixture:
            for name,value in (('GITHUB_ACTOR','other'),('GITHUB_REF','refs/pull/2/merge'),
                ('GITHUB_EVENT_NAME','pull_request'),('GITHUB_REPOSITORY','other/repo'),
                ('GITHUB_RUN_ID','0123'),('GITHUB_RUN_ID','1\n'),('GITHUB_RUN_ID','1'*21),
                ('GITHUB_RUN_ATTEMPT','2'),('GITHUB_RUN_ATTEMPT','01'),
                ('GITHUB_SHA','b'*40),('AI09_APPROVED_MAIN_SHA',''),
                ('AI09_INPUT_CIPHERTEXT_SHA256','A'*64),('AI09_INPUT_CIPHERTEXT_BYTES','01'),
                ('AI09_INPUT_CIPHERTEXT_BYTES','2000039'),('AI09_INPUT_CIPHERTEXT_BYTES','')):
                with self.subTest(field=name,value=value),patch.dict(os.environ,{name:value}):
                    self.fail_closed()
            self.assertEqual(fixture['processes'],[])
            self.assertEqual(list((fixture['root']/'runner').iterdir()),[])

    def test_invalid_ready_never_reads_input_or_key(self):
        modes=('silent-exit','wrong-nonce','duplicate-ready','extra-ready','noncanonical-ready',
               'boolean-deadline','overlong-ready','early-done','stdout-flood','stderr-flood','stderr-ready')
        for mode in modes:
            calls=[]
            def denied(*args,**kwargs):calls.append(True);raise AssertionError('secret lookup before valid READY')
            with self.subTest(mode=mode),public_connection(mode,budget=0.4), \
                 patch.object(private,'_read_input',denied),patch.object(private,'_read_key',denied):
                self.fail_closed()
            self.assertEqual(calls,[])

    def test_partial_writes_are_completed_without_deadlock(self):
        write=os.write
        with public_connection() as fixture,patch.object(private.os,'write',lambda fd,b:write(fd,b[:37])):
            result=driver.parse_json(private.coordinate())
            self.assertEqual(result['observed_responses'],8)
            self.assertEqual(fixture['processes'][0].returncode,0)

    def test_deadlines_floods_exit_and_cleanup_failures_never_emit_ready(self):
        modes=('silent-stall','stalled-reader','duplex-flood','slow-prepare','slow-decode','slow-capture',
               'slow-fsync','crash-after-create','ambiguous-create','cleanup-failure','stop-failure',
               'logs-failure','bad-done','extra-done','nonzero-exit','stdout-after-done',
               'stderr-after-done','mutated-output','missing-output','symlink-output','hardlink-output','stall-after-done')
        for mode in modes:
            began=time.monotonic()
            with self.subTest(mode=mode),public_connection(mode,budget=0.4) as fixture:
                self.fail_closed()
                self.assertTrue(all(p.poll() is not None for p in fixture['processes']))
                for args,kw,deadline in fixture['commands']:
                    self.assertIn(args[0],('rm','ps'))
                    self.assertLessEqual(deadline,began+1.2)
            self.assertLess(time.monotonic()-began,2.0)

    def test_ignored_term_requires_bounded_kill_and_exact_name_reaper(self):
        with public_connection('hard-kill',budget=0.3) as fixture:
            self.fail_closed()
            self.assertEqual(fixture['processes'][0].returncode,-signal.SIGKILL)
            calls=fixture['commands'];self.assertEqual([c[0][0] for c in calls],['rm','ps'])
            name=calls[0][0][-1];self.assertRegex(name,r'^ai09-model-[0-9a-f]{32}$')
            self.assertEqual(calls[1][0],('ps','--all','--quiet','--filter','name=^/'+name+'$'))

    def test_reaper_failure_or_parent_interruption_never_acknowledges_output(self):
        for failing in ('reaper','interruption'):
            with self.subTest(failure=failing),public_connection('crash-after-create'):
                if failing=='reaper':
                    with patch.object(pilot_host,'_remove_container',side_effect=OSError('PUBLIC-CLEANUP-CANARY')):
                        self.fail_closed()
                else:
                    with patch.object(private,'_read_key',side_effect=KeyboardInterrupt):
                        self.fail_closed()

    def test_input_identity_and_key_failures_never_become_ready(self):
        for change in ('missing','symlink','hardlink','hash','size','key','purpose'):
            with self.subTest(change=change),public_connection() as fixture:
                path=fixture['root']/'sealed/ai09-private-bundle.aesgcm'
                if change=='missing':path.unlink()
                elif change in ('symlink','hardlink'):
                    copy=path.with_name('copy');path.rename(copy)
                    if change=='symlink':path.symlink_to(copy)
                    else:os.link(copy,path)
                elif change=='hash':os.environ['AI09_INPUT_CIPHERTEXT_SHA256']='0'*64
                elif change=='size':os.environ['AI09_INPUT_CIPHERTEXT_BYTES']=str(len(fixture['cipher'])+1)
                elif change=='key':os.environ['AI09_BUNDLE_KEY_B64']='A'*43+'B'
                else:
                    plain=public_runner.unseal(fixture['cipher'],KEY,b'FROZEN-SOURCE-BUNDLE')
                    changed=public_runner.seal(plain,KEY,pilot_host.PURPOSE);path.write_bytes(changed)
                    os.environ['AI09_INPUT_CIPHERTEXT_SHA256']=driver.digest(changed)
                calls=[];read_key=private._read_key
                def read():calls.append(True);return read_key()
                with patch.object(private,'_read_key',read):self.fail_closed()
                if change in ('missing','symlink','hardlink','hash','size'):self.assertEqual(calls,[])

    def test_fresh_output_directory_is_not_reused_or_replaced(self):
        with public_connection() as fixture:
            output=fixture['root']/'runner/ai09-private-pilot-123-1';output.mkdir(mode=0o700)
            (output/'unrelated').write_bytes(b'KEEP')
            self.fail_closed();self.assertEqual((output/'unrelated').read_bytes(),b'KEEP')
            self.assertEqual(fixture['processes'],[])

    def test_bounded_read_detects_file_and_ancestor_replacement(self):
        real_read=os.read
        for kind in ('file','ancestor'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as temp:
                base=pathlib.Path(temp);parent=base/'parent';parent.mkdir(mode=0o700)
                path=parent/'cipher';path.write_bytes(b'PUBLIC');path.chmod(0o600);changed=[]
                def swapped(fd,count):
                    raw=real_read(fd,count)
                    if not changed:
                        if kind=='file':path.rename(parent/'old');path.write_bytes(b'PUBLIC');path.chmod(0o600)
                        else:parent.rename(base/'old-parent');parent.mkdir(mode=0o700)
                        changed.append(True)
                    return raw
                with patch.object(private.os,'read',swapped),self.assertRaises(driver.GateError):
                    private._read_verified(path,driver.digest(b'PUBLIC'),6,time.monotonic()+1,private=True)
                self.assertEqual(changed,[True])

    def test_frame_reader_rejects_truncation_trailing_and_oversize_over_real_pipe(self):
        frame=b'AI09PIPE1\x00'+bytes.fromhex('1'*32)+KEY+(100_000).to_bytes(8,'big')+b'x'*100_000
        values=[frame[:-1],frame+b'x',frame+frame,frame[:10]+bytes(16)+frame[26:],
                b'BAD'+frame[3:],frame[:58]+(2_000_039).to_bytes(8,'big')]
        for number,value in enumerate([frame,*values]):
            process=subprocess.run([sys.executable,'-I','-B',str(FIXTURE),'read-frame'],input=value,
                stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=2,
                env={'PATH':os.defpath,'LD_LIBRARY_PATH':str(pathlib.Path(sys.base_prefix)/'lib')})
            with self.subTest(case=number):
                self.assertEqual(process.returncode,0 if number==0 else 2)
                self.assertEqual(process.stderr,b'')
                if number==0:self.assertEqual(driver.parse_json(process.stdout),{'key_bytes':32,'cipher_bytes':100_000})


if __name__=='__main__':unittest.main()
