#!/usr/bin/env python3
"""PUBLIC fake-model E2E. No input arguments, actual model or private inputs."""
import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import sys
import uuid

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))  # public, reviewed repository code only
from confidential_capture import capture, CaptureError
import data_driver as driver
from public_runner import seal, unseal

spec = importlib.util.spec_from_file_location('sandbox_policy', ROOT/'tools'/'sandbox_probe.py')
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)

SAFE_ERRORS = {'LINUX_DOCKER_REQUIRED','DOCKER_OPERATION_FAILED',
               'SYNTHETIC_CAPTURE_FAILED','SYNTHETIC_CAPTURE_DID_NOT_BLOCK',
               'SYNTHETIC_VERIFIER_FAILED','SYNTHETIC_VERIFIER_DID_NOT_BLOCK',
               'SYNTHETIC_SEAL_FAILED'} | policy.SAFE_ERRORS
CAPTURE_ERRORS = {'CAPTURE_LIMIT','CAPTURE_TIMEOUT','CAPTURE_EXIT','CAPTURE_FAILED',
                  'CAPTURE_CLEANUP_FAILED','CONTAINER_STOP_UNVERIFIED'}


def stop_container(docker, name):
    # kill can race with natural exit or broken attach. Its return code is not
    # proof of termination; the subsequent wait and exact inspect are required.
    docker('kill',name,check=False)
    docker('wait',name)
    state = json.loads(docker('inspect',name).stdout)[0]['State']
    return (state['Running'] is False and state['Pid'] == 0 and
            state['Status'] == 'exited')


def experiment():
    if sys.platform != 'linux' or not shutil.which('docker'):
        raise RuntimeError('LINUX_DOCKER_REQUIRED')
    safe_env = {'PATH': os.defpath}

    def docker(*args, check=True):
        result = subprocess.run(['docker', *args], env=safe_env, capture_output=True,
                                text=True, timeout=15)
        if len(result.stdout)+len(result.stderr) > 65536 or (check and result.returncode):
            raise RuntimeError('DOCKER_OPERATION_FAILED')
        return result

    # The preceding sandbox probe prefetches this pinned public image.
    image_id = json.loads(docker('image','inspect',policy.IMAGE).stdout)[0]['Id']
    mounts = {'/code/data_driver.py':str(ROOT/'data_driver.py'),
              '/code/loopback_client.py':str(ROOT/'loopback_client.py'),
              '/guest.py':str(ROOT/'tests'/'fixtures'/'data_guest.py')}
    chunks = tuple(driver.Chunk(f'{index:03}', 'PUBLIC.py', 1,
                                f'# PUBLIC-SYNTHETIC-{index}\n'.encode('ascii'))
                   for index in range(8))
    expected = driver.Batch('123',1,'a'*40,driver.digest(b'PUBLIC-ARCHIVE'),
                            driver.digest(b'PUBLIC-PLAN'),chunks)
    for mode in ('normal','tamper','trailing','oversize','escaped'):
        print('SYNTHETIC_DRIVER_PHASE='+mode.upper(), flush=True)
        name = 'ai09-data-synthetic-'+uuid.uuid4().hex
        created = False
        try:
            args = ['create','--name',name,'--pull=never','--log-driver=none',
                    '--network=none','--user=65534:65534','--read-only',
                    '--cap-drop=ALL','--security-opt=no-new-privileges',
                    '--pids-limit=32','--memory=128m','--memory-swap=128m','--cpus=1',
                    '--ipc=private','--ulimit','fsize=1048576:1048576',
                    '--tmpfs','/scratch:'+policy.TMPFS]
            for target, source in mounts.items():
                args += ['--mount',f'type=bind,source={source},target={target},readonly']
            args += [policy.IMAGE,'python','-I','-B','/guest.py',mode]
            docker(*args)
            created = True
            info = json.loads(docker('inspect',name).stdout)[0]
            policy.validate_inspection(info,image_id,mounts)

            def stop_and_verify():
                # Identity is generated/retained by this host, never from a packet.
                return stop_container(docker,name)

            try:
                raw = capture(['docker','start','--attach',name],safe_env,stop_and_verify,
                              timeout=3 if mode == 'escaped' else 30,
                              max_bytes=driver.MAX_PACKET)
            except CaptureError as error:
                code = str(error) if str(error) in CAPTURE_ERRORS else 'UNKNOWN_CAPTURE_ERROR'
                print('SYNTHETIC_CAPTURE_RESULT='+code, flush=True)
                expected_error = {'oversize':'CAPTURE_LIMIT','escaped':'CAPTURE_TIMEOUT'}.get(mode)
                if str(error) != expected_error:
                    raise RuntimeError('SYNTHETIC_CAPTURE_FAILED') from None
            else:
                if mode in ('oversize','escaped'):
                    raise RuntimeError('SYNTHETIC_CAPTURE_DID_NOT_BLOCK')
                try:
                    verified = driver.verify_synthetic_packet(raw, expected)
                except driver.GateError:
                    if mode not in ('tamper','trailing'):
                        raise RuntimeError('SYNTHETIC_VERIFIER_FAILED') from None
                else:
                    if mode != 'normal' or verified.evidence_kind != 'SYNTHETIC':
                        raise RuntimeError('SYNTHETIC_VERIFIER_DID_NOT_BLOCK')
                    # Seal EXACT verified in-memory bytes after positive teardown.
                    # No mutable output reread, private file, artifact or real key.
                    key = bytes(range(32))  # PUBLIC synthetic key only
                    purpose = b'CONFIDENTIAL-REVIEW-EVIDENCE'
                    encrypted = seal(verified.payload,key,purpose)
                    if unseal(encrypted,key,purpose) != raw or raw in encrypted:
                        raise RuntimeError('SYNTHETIC_SEAL_FAILED')
            policy.validate_logs(docker('logs',name,check=False))
        finally:
            docker('rm','--force',name,check=created)


def main():
    try:
        experiment()
    except BaseException as error:
        # Never print captured data, stderr, argv, HTTP bodies or raw exceptions.
        code = str(error) if str(error) in SAFE_ERRORS else 'UNEXPECTED_ERROR'
        print('SYNTHETIC_DRIVER_ERROR='+code)
        print('SYNTHETIC_DATA_DRIVER=FAIL; PRIVATE_RUNTIME_APPROVED=false')
        return 2
    print('SYNTHETIC_DATA_DRIVER=PASS; PRIVATE_RUNTIME_APPROVED=false; FIXED_SUBJECT_RECEIPTS=0')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
