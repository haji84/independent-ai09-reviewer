#!/usr/bin/env python3
"""PUBLIC SYNTHETIC EXPERIMENT ONLY. Never accepts source, keys or receipts."""
import hashlib,json,os,pathlib,shutil,subprocess,sys,tempfile,time,uuid

IMAGE='python@sha256:4cea12ab7d78a3312c85f8cab19b6971d4fe9704da25443986c0bc20a6678850'
TMPFS='rw,noexec,nosuid,nodev,size=16777216,mode=1777'
ROOT=pathlib.Path(__file__).resolve().parents[1]
GUEST=ROOT/'tests'/'fixtures'/'sandbox_guest.py'

def wait_for_ready(read_ready,timeout_seconds=15):
    deadline=time.monotonic()+timeout_seconds
    while time.monotonic()<deadline:
        if read_ready():return
        time.sleep(0.1)
    raise TimeoutError('SYNTHETIC_GUEST_NOT_READY')

def validate_logs(result):
    if result.returncode==0 and not result.stdout and not result.stderr:return
    expected='Error response from daemon: configured logging driver does not support reading'
    if result.returncode!=0 and not result.stdout and result.stderr.strip()==expected:return
    raise ValueError('UNEXPECTED_CONTAINER_LOG_EXPORT')

def validate_inspection(info,image_id,mounts):
    """Reject an effective container config that weakens this experiment."""
    host=info['HostConfig'];config=info['Config']
    expected={'ReadonlyRootfs':True,'NetworkMode':'none','CapDrop':['ALL'],
              'PidsLimit':32,'Memory':134217728,'MemorySwap':134217728,
              'NanoCpus':1000000000,'Privileged':False}
    if info['Image']!=image_id or config['User']!='65534:65534':
        raise ValueError('UNEXPECTED_IDENTITY')
    for key,value in expected.items():
        if host.get(key)!=value:raise ValueError('UNSAFE_EFFECTIVE_CONFIG')
    if (host.get('CapAdd') or host.get('GroupAdd') or host.get('Devices') or
        host.get('DeviceRequests') or host.get('PortBindings') or
        host.get('PidMode') not in ('',None) or
        host.get('IpcMode')!='private' or host.get('CgroupnsMode')=='host' or
        host.get('SecurityOpt')!=['no-new-privileges'] or
        host.get('LogConfig',{}).get('Type')!='none' or
        host.get('LogConfig',{}).get('Config') not in (None,{}) or
        host.get('Tmpfs')!={'/scratch':TMPFS}):
        raise ValueError('UNSAFE_HOST_ACCESS')
    for item in config.get('Env',[]):
        key=item.partition('=')[0]
        if key.startswith(('AI09_','GITHUB_','ACTIONS_','RUNNER_')):
            raise ValueError('FORBIDDEN_ENVIRONMENT')
    actual={}
    for mount in info['Mounts']:
        if mount['Type']=='tmpfs' and mount['Destination']=='/scratch':continue
        if mount['Type']!='bind' or mount['RW'] is not False:
            raise ValueError('UNEXPECTED_MOUNT')
        actual[mount['Destination']]=mount['Source']
    if actual!=mounts or len(actual)!=len(mounts):
        raise ValueError('UNEXPECTED_MOUNT')

def experiment():
    if sys.platform!='linux' or not shutil.which('docker'):
        raise RuntimeError('LINUX_DOCKER_REQUIRED')
    host_env=dict(os.environ)
    host_env.update(AI09_BUNDLE_KEY_B64='SYNTHETIC-NOT-A-KEY',
                    GITHUB_ENV='/synthetic-command-file',
                    GITHUB_STEP_SUMMARY='/synthetic-summary',
                    ACTIONS_RUNTIME_TOKEN='SYNTHETIC-NOT-A-TOKEN')
    def docker(*args,timeout=15,check=True):
        result=subprocess.run(['docker',*args],env=host_env,capture_output=True,
                              text=True,timeout=timeout)
        if len(result.stdout)+len(result.stderr)>65_536:
            raise RuntimeError('UNEXPECTED_DOCKER_OUTPUT_SIZE')
        if check and result.returncode:raise RuntimeError('DOCKER_OPERATION_FAILED')
        return result
    docker('version','--format','{{.Server.Version}}')
    docker('pull',IMAGE,timeout=180)
    image_id=json.loads(docker('image','inspect',IMAGE).stdout)[0]['Id']
    with tempfile.TemporaryDirectory(prefix='ai09-public-synthetic-') as directory:
        base=pathlib.Path(directory);base.chmod(0o755)
        inputs=base/'input';inputs.mkdir(mode=0o755)
        canary=inputs/'canary';canary.write_bytes(b'PUBLIC-SYNTHETIC-INPUT');canary.chmod(0o444)
        hidden=base/'host-only';hidden.write_bytes(b'PUBLIC-SYNTHETIC-HOST-ONLY')
        before=hashlib.sha256(canary.read_bytes()+hidden.read_bytes()).digest()
        mounts={'/probe.py':str(GUEST),'/input':str(inputs)}
        for mode in ('normal','hang'):
            name='ai09-synthetic-'+uuid.uuid4().hex
            created=False
            try:
                args=['create','--name',name,'--pull=never','--log-driver=none',
                      '--network=none','--user=65534:65534','--read-only',
                      '--cap-drop=ALL','--security-opt=no-new-privileges',
                      '--pids-limit=32','--memory=128m','--memory-swap=128m','--cpus=1',
                      '--ipc=private','--ulimit','fsize=1048576:1048576',
                      '--tmpfs','/scratch:'+TMPFS]
                for destination,source in mounts.items():
                    args+=['--mount',f'type=bind,source={source},target={destination},readonly']
                args += [IMAGE,'python','-I','-B','/probe.py',mode,str(hidden)]
                docker(*args)
                created=True
                info=json.loads(docker('inspect',name).stdout)[0]
                validate_inspection(info,image_id,mounts)
                docker('start',name)
                def ready():
                    result=docker('exec',name,'/bin/cat','/scratch/ready',check=False,timeout=5)
                    if result.returncode:return False
                    if result.stdout!='PUBLIC-SYNTHETIC-READY':
                        raise RuntimeError('INVALID_READINESS')
                    return True
                wait_for_ready(ready)
                if mode=='normal':
                    docker('exec',name,'python','-I','-c',
                           "from pathlib import Path; Path('/scratch/release').touch()")
                    if docker('wait',name,timeout=30).stdout.strip()!='0':
                        raise RuntimeError('GUEST_CHECK_FAILED')
                else:
                    try:docker('wait',name,timeout=3)
                    except subprocess.TimeoutExpired:pass
                    else:raise RuntimeError('TIMEOUT_FIXTURE_DID_NOT_RUN')
                    docker('kill',name)
                    docker('wait',name)
                state=json.loads(docker('inspect',name).stdout)[0]['State']
                if state['Running'] or state['Pid']!=0 or state['Status']!='exited':
                    raise RuntimeError('DESCENDANTS_NOT_STOPPED')
                logs=docker('logs',name,check=False)
                validate_logs(logs)
            finally:
                # Names are random and created exclusively by this synthetic probe.
                docker('rm','--force',name,check=created)
        if hashlib.sha256(canary.read_bytes()+hidden.read_bytes()).digest()!=before:
            raise RuntimeError('HOST_CANARY_CHANGED')

def main():
    try:experiment()
    except Exception:
        print('SYNTHETIC_SANDBOX_PROBE=FAIL; PRIVATE_RUNTIME_APPROVED=false')
        return 2
    print('SYNTHETIC_SANDBOX_PROBE=PASS; PRIVATE_RUNTIME_APPROVED=false; FIXED_SUBJECT_RECEIPTS=0')
    return 0

if __name__=='__main__':raise SystemExit(main())
