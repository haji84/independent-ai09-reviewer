#!/usr/bin/env python3
"""Eight observed real-model calls on PUBLIC data; no private activation."""
import contextlib
import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import data_driver as driver
import runtime_assets as assets
import context_probe
import pilot_batch
import public_runner
from confidential_capture import capture

spec=importlib.util.spec_from_file_location('sandbox_policy',ROOT/'tools'/'sandbox_probe.py')
policy=importlib.util.module_from_spec(spec);spec.loader.exec_module(policy)
GUEST_ERRORS={'PUBLIC_MODEL_INPUT_REJECTED','PUBLIC_MODEL_STARTUP_FAILED','PUBLIC_MODEL_INVENTORY_MISMATCH',
              'PUBLIC_MODEL_TRANSPORT_FAILED','PUBLIC_MODEL_RESPONSE_REJECTED',
              'PUBLIC_MODEL_CONTEXT_REJECTION_FAILED'}
SAFE_ERRORS={'LINUX_DOCKER_ZSTD_REQUIRED','PUBLIC_DISK_BUDGET','PUBLIC_RUNTIME_DEADLINE',
             'PUBLIC_ASSET_DOWNLOAD_FAILED','PUBLIC_ASSET_MISMATCH','PUBLIC_ASSET_URL_BLOCKED',
             'PUBLIC_TAR_UNSUPPORTED','PUBLIC_TAR_LIMIT','PUBLIC_CPU_LIMIT','PUBLIC_CPU_INCOMPLETE',
             'PUBLIC_TAR_PATH','PUBLIC_TAR_HEADER','PUBLIC_TAR_TRUNCATED','PUBLIC_TAR_ALIAS',
             'PUBLIC_TAR_COLLISION','PUBLIC_TAR_DUPLICATE','PUBLIC_TAR_TERMINATOR','PUBLIC_TAR_TRAILING',
             'PUBLIC_TAR_DECODE_FAILED','MODEL_MANIFEST_MISMATCH','PUBLIC_DOCKER_FAILED',
             'CAPTURE_EXIT','CAPTURE_TIMEOUT','CAPTURE_LIMIT','CONTAINER_STOP_UNVERIFIED',
             'INVALID_OBSERVED_BATCH',context_probe.CODE}|GUEST_ERRORS|policy.SAFE_ERRORS


def validate_public_packet(raw,expected,host_start,host_end):
    """The host calls this only after capture has positively verified teardown."""
    value=driver.parse_json(raw,driver.MAX_PACKET)
    if (type(value) is dict and set(value)=={'error'} and type(value['error']) is str and
        value['error'] in GUEST_ERRORS):raise driver.GateError(value['error'])
    verified=pilot_batch.verify_observation(raw,expected,host_start,host_end)
    tokens=context_probe.verify_rejection(value['context_rejection'],expected,
                                          not_before=value['exchanges'][-1]['finished_ns'],not_after=host_end)
    return verified,tokens,driver.digest(driver.encode_json(value['context_rejection']))


@contextlib.contextmanager
def staged_batch(batch):
    """Only this data file is mounted; its host parent is never public assets."""
    raw=pilot_batch.encode_batch(batch)
    with tempfile.TemporaryDirectory(prefix='ai09-batch-data-') as directory:
        parent=pathlib.Path(directory);parent.chmod(0o700)
        path=parent/'batch.json'
        with path.open('xb') as output:output.write(raw)
        path.chmod(0o444)
        yield path


def experiment():
    if sys.platform!='linux' or not shutil.which('docker') or not shutil.which('zstd'):
        raise driver.GateError('LINUX_DOCKER_ZSTD_REQUIRED')
    start=time.monotonic();work_deadline=start+540;cleanup_deadline=start+600
    driver.require(shutil.disk_usage(tempfile.gettempdir()).free>=8*1024**3,'PUBLIC_DISK_BUDGET')
    safe_env={'PATH':os.defpath}
    def docker(*args,check=True,cleanup=False):
        result=subprocess.run(['docker',*args],env=safe_env,capture_output=True,text=True,
                              timeout=assets.remaining(cleanup_deadline if cleanup else work_deadline,15))
        driver.require(len(result.stdout)+len(result.stderr)<=65536 and
                       (not check or result.returncode==0),'PUBLIC_DOCKER_FAILED')
        return result
    # The small sandbox probe prefetches this immutable image before this step.
    image_id=json.loads(docker('image','inspect',policy.IMAGE).stdout)[0]['Id']
    with tempfile.TemporaryDirectory(prefix='ai09-public-model-') as directory, contextlib.ExitStack() as staging:
        base=pathlib.Path(directory);base.chmod(0o755)
        print('PUBLIC_MODEL_PHASE=PINNED_DOWNLOADS',flush=True)
        archive=base/'ollama.tar.zst'
        assets.download(assets.OLLAMA_URL,archive,assets.OLLAMA_SIZE,assets.OLLAMA_SHA,work_deadline)
        manifest_file=base/'manifest'
        assets.download(assets.MANIFEST_URL,manifest_file,assets.MANIFEST_SIZE,assets.MODEL_SHA,work_deadline)
        manifest=manifest_file.read_bytes();blobs=assets.model_blobs(manifest)
        models=base/'models';(models/'blobs').mkdir(parents=True,mode=0o755)
        for digest,size in blobs:
            assets.download('https://registry.ollama.ai/v2/library/qwen3/blobs/sha256:'+digest,
                            models/'blobs'/('sha256-'+digest),size,digest,work_deadline)
        manifest_path=models/'manifests'/'registry.ollama.ai'/'library'/'qwen3'/'1.7b'
        manifest_path.parent.mkdir(parents=True,mode=0o755)
        with manifest_path.open('xb') as output:output.write(manifest)
        manifest_path.chmod(0o444)
        print('PUBLIC_MODEL_PHASE=VERIFIED_CPU_SELECTION',flush=True)
        runtime=base/'runtime';runtime_hashes=assets.stage_cpu(archive,runtime,work_deadline)
        # Recheck the actual mounted regular bytes immediately before create.
        for name,digest in runtime_hashes.items():
            assets.verify_file(runtime/name,(runtime/name).stat().st_size,digest,work_deadline)
        for digest,size in blobs:assets.verify_file(models/'blobs'/('sha256-'+digest),size,digest,work_deadline)
        assets.verify_file(manifest_path,assets.MANIFEST_SIZE,assets.MODEL_SHA,work_deadline)
        mounts={'/opt/runtime':str(runtime),'/models':str(models),
                '/guest.py':str(ROOT/'tests'/'fixtures'/'model_guest.py')}
        for name in ('data_driver.py','loopback_client.py','runtime_assets.py','context_probe.py','pilot_batch.py'):
            mounts['/code/'+name]=str(ROOT/name)
        code_hashes={target:driver.digest(pathlib.Path(path).read_bytes()) for target,path in mounts.items()
                     if target.startswith('/code/') or target=='/guest.py'}
        chunks=tuple(driver.Chunk(f'{i:03}',f'PUBLIC{i}.py',1,
                                 b'def add(a, b):\n    return a + b\n') for i in range(8))
        expected=driver.Batch(os.environ['GITHUB_RUN_ID'],int(os.environ.get('GITHUB_RUN_ATTEMPT','1')),
                              os.environ['GITHUB_SHA'],driver.digest(b'PUBLIC-TOY-SOURCE'),
                              driver.digest(b'PUBLIC-TOY-NO-PLAN'),chunks)
        input_path=staging.enter_context(staged_batch(expected))
        mounts['/input/batch.json']=str(input_path)
        launch={'image':image_id,'runtime':runtime_hashes,
            'driver':code_hashes,'ollama_archive':assets.OLLAMA_SHA,'model':assets.MODEL_SHA,
            'model_blobs':blobs,'context':expected.context(),'input_class':'PUBLIC_SYNTHETIC',
            'staged_input_sha':driver.digest(pilot_batch.encode_batch(expected))}
        name='ai09-public-model-'+uuid.uuid4().hex;created=False
        try:
            args=['create','--name',name,'--pull=never','--log-driver=none','--network=none',
                  '--user=65534:65534','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges',
                  '--pids-limit=128','--memory=4g','--memory-swap=4g','--cpus=2','--ipc=private',
                  '--ulimit','fsize=1048576:1048576','--tmpfs','/scratch:'+policy.MODEL_TMPFS]
            for target,path in mounts.items():args+=['--mount',f'type=bind,source={path},target={target},readonly']
            args += [policy.IMAGE,'python','-I','-B','/guest.py',expected.run_id,str(expected.attempt),expected.commit]
            docker(*args);created=True
            inspection=json.loads(docker('inspect',name).stdout)[0]
            policy.validate_inspection(inspection,image_id,mounts,profile='public-model')
            fields=(*policy.EFFECTIVE_FIELDS,'SecurityOpt','LogConfig','Tmpfs','IpcMode')
            launch['container_id']=inspection['Id']
            launch['inspection']={field:inspection['HostConfig'].get(field) for field in fields}
            launch_hash=driver.digest(driver.encode_json(launch))
            def stop():
                docker('kill',name,check=False,cleanup=True);docker('wait',name,cleanup=True)
                state=json.loads(docker('inspect',name,cleanup=True).stdout)[0]['State']
                return state['Running'] is False and state['Pid']==0 and state['Status']=='exited'
            print('PUBLIC_MODEL_PHASE=OFFLINE_INFERENCE',flush=True)
            host_start=time.time_ns()
            raw=capture(['docker','start','--attach',name],safe_env,stop,
                        timeout=assets.remaining(work_deadline,480),max_bytes=driver.MAX_PACKET)
            host_end=time.time_ns()
            policy.validate_logs(docker('logs',name,check=False,cleanup=True))
            verified,tokens,rejection_hash=validate_public_packet(raw,expected,host_start,host_end)
            envelope=pilot_batch.evidence_envelope(raw,expected,launch,host_start,host_end)
            # This key is PUBLIC test material; no confidential evidence is accepted.
            key=bytes(range(32));purpose=b'CONFIDENTIAL-REVIEW-EVIDENCE'
            encrypted=public_runner.seal(envelope,key,purpose)
            recovered=public_runner.unseal(encrypted,key,purpose)
            replay=pilot_batch.verify_evidence(recovered,expected,launch,host_start,host_end)
            driver.require(replay.payload==verified.payload and replay.observed_responses==8)
            print('PUBLIC_MODEL_LAUNCH_SHA256='+launch_hash)
            print('PUBLIC_MODEL_RECEIPT_SHA256='+hashlib.sha256(verified.payload).hexdigest())
            print('PUBLIC_ENCRYPTED_EVIDENCE_SHA256='+driver.digest(encrypted))
            print('PUBLIC_EVIDENCE_ROUNDTRIP=PASS; OBSERVED_RESPONSES=8; FIXED_SUBJECT_RECEIPTS=0')
            print('PUBLIC_CONTEXT_REJECTION_SHA256='+rejection_hash)
            print('PUBLIC_CONTEXT_REJECTION=PASS; HTTP_STATUS=400; PROMPT_TOKENS='+str(tokens)+
                  '; CONTEXT_TOKENS=4096; FIXED_SUBJECT_RECEIPTS=0')
            print('PUBLIC_MODEL_ELAPSED_SECONDS='+str(round(time.monotonic()-start,2)))
        finally:
            docker('rm','--force',name,check=created,cleanup=True)


def main():
    try:experiment()
    except BaseException as error:
        code=str(error) if str(error) in SAFE_ERRORS else 'UNEXPECTED_ERROR'
        print('PUBLIC_MODEL_ERROR='+code)
        print('PUBLIC_MODEL_SMOKE=FAIL; FIXED_SUBJECT_RECEIPTS=0; DESIGN_APPROVAL=HOLD')
        return 2
    print('PUBLIC_MODEL_SMOKE=PASS; PUBLIC_TOY_MODEL_CALLS=8; FIXED_SUBJECT_RECEIPTS=0; DESIGN_APPROVAL=HOLD')
    return 0


if __name__=='__main__':raise SystemExit(main())
