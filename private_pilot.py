"""Trusted one-shot coordinator/child connection; workflow admission stays HOLD.

The coordinator's environment already contains its step-scoped key. Only its
explicitly sanitized child/PUBLIC download path is key-free before READY.
Trusted host/kernel/daemon/same UID are outside this boundary. No zeroization,
power-loss, asynchronous-daemon or cryptographic execution attestation is claimed.
"""
import base64
import contextlib
import dataclasses
import os
import pathlib
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
import uuid

import data_driver as driver
import pilot_host as host
import public_runner
import runtime_assets as assets
import sealed_input

ROOT = pathlib.Path(__file__).resolve().parent
REPOSITORY = 'haji84/independent-ai09-reviewer'
WORKFLOW_PATH = '.github/workflows/ai09-public-safe-pilot.yml'
OBSERVATION_PREFIX = 'AI09_HOST_OBSERVATION='
MAX_CIPHERTEXT = min(public_runner.MAX_ENCRYPTED,
    driver.MAX_PACKET + len(public_runner.MAGIC) + 12 + 16)
_MIN_CIPHERTEXT = len(public_runner.MAGIC) + 12 + 16 + 1
_FRAME_MAGIC = b'AI09PIPE1\x00'
_WORK_SECONDS = 540
_CLEANUP_SECONDS = 600
_TERM_GRACE_SECONDS = 2
_KILL_GRACE_SECONDS = 2
_READY_KEYS = ('v','kind','nonce','container_name','work_deadline_ns','cleanup_deadline_ns')
_DONE_KEYS = ('v','kind','nonce','ciphertext_sha256','ciphertext_bytes',
              'observed_responses','launch_sha256','host_start_ns','host_end_ns')
OBSERVATION_KEYS = ('schema','repository','run_id','attempt','commit','input_class',
    'input_ciphertext_sha256','input_ciphertext_bytes','output_ciphertext_sha256',
    'output_ciphertext_bytes','launch_sha256','host_start_ns','host_end_ns','observed_responses')


def _need(value):
    driver.require(value, 'PRIVATE_PILOT_FAILED')


def _positive(value):
    return type(value) is int and 0 < value < 2**63


def _hash(value, size=64):
    return type(value) is str and re.fullmatch('[0-9a-f]{'+str(size)+'}',value) is not None


def _run_id(value):
    return type(value) is str and re.fullmatch('[1-9][0-9]{0,19}',value) is not None


def validate_observation(value):
    """Validate public host metadata; this does not authenticate its supplier."""
    driver.exact_keys(value,OBSERVATION_KEYS)
    _need(value['schema']=='AI09-HOST-OBSERVATION-v1' and value['repository']==REPOSITORY
          and value['input_class']=='FROZEN_DATA_ONLY' and _run_id(value['run_id'])
          and type(value['attempt']) is int and value['attempt']==1 and _hash(value['commit'],40))
    for name in ('input_ciphertext_sha256','output_ciphertext_sha256','launch_sha256'):
        _need(_hash(value[name]))
    for name,cap in (('input_ciphertext_bytes',MAX_CIPHERTEXT),
                     ('output_ciphertext_bytes',public_runner.MAX_ENCRYPTED)):
        _need(_positive(value[name]) and _MIN_CIPHERTEXT<=value[name]<=cap)
    _need(_positive(value['host_start_ns']) and _positive(value['host_end_ns'])
          and value['host_start_ns']<value['host_end_ns']
          and type(value['observed_responses']) is int and value['observed_responses']==8)
    _need(len(driver.encode_json(value))<=2048)
    return value


@dataclasses.dataclass(frozen=True,repr=False)
class _Context:
    run_id: str
    attempt: int
    commit: str
    input_sha: str
    input_bytes: int
    runner_temp: pathlib.Path


@dataclasses.dataclass(repr=False)
class _Session:
    work_deadline: float
    cleanup_deadline: float
    container_name: str | None = None


def _context():
    # Named public fields only. Never copy the coordinator's general environment.
    fields={name:os.environ.get(name) for name in (
        'GITHUB_REPOSITORY','GITHUB_REF','GITHUB_EVENT_NAME','GITHUB_ACTOR','GITHUB_RUN_ID',
        'GITHUB_RUN_ATTEMPT','GITHUB_SHA','RUNNER_TEMP','AI09_APPROVED_MAIN_SHA',
        'AI09_INPUT_CIPHERTEXT_SHA256','AI09_INPUT_CIPHERTEXT_BYTES')}
    _need(fields['GITHUB_REPOSITORY']==REPOSITORY and fields['GITHUB_REF']=='refs/heads/main'
          and fields['GITHUB_EVENT_NAME']=='workflow_dispatch' and fields['GITHUB_ACTOR']=='haji84'
          and fields['GITHUB_RUN_ATTEMPT']=='1' and _run_id(fields['GITHUB_RUN_ID'])
          and _hash(fields['GITHUB_SHA'],40) and fields['GITHUB_SHA']==fields['AI09_APPROVED_MAIN_SHA']
          and _hash(fields['AI09_INPUT_CIPHERTEXT_SHA256']))
    size=fields['AI09_INPUT_CIPHERTEXT_BYTES']
    _need(type(size) is str and re.fullmatch('[1-9][0-9]{0,6}',size) is not None)
    size=int(size);_need(_MIN_CIPHERTEXT<=size<=MAX_CIPHERTEXT)
    directory=fields['RUNNER_TEMP']
    _need(type(directory) is str and directory.startswith('/') and len(directory)<=4096)
    return _Context(fields['GITHUB_RUN_ID'],1,fields['GITHUB_SHA'],
                    fields['AI09_INPUT_CIPHERTEXT_SHA256'],size,pathlib.Path(directory))


def _dir_identity(info):
    return info.st_dev,info.st_ino,info.st_mode,info.st_uid


@contextlib.contextmanager
def _directory_chain(path,deadline):
    """Retain every root-to-directory descriptor/name relation for later checks."""
    text=os.fspath(path)
    _need(type(text) is str and text.startswith('/') and len(text)<=4096)
    parts=text.split('/')[1:]
    _need(all(part not in ('','.','..') for part in parts))
    flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
    descriptors=[];links=[]
    try:
        fd=os.open('/',flags);descriptors.append(fd)
        root=_dir_identity(os.fstat(fd))
        for name in parts:
            assets.remaining(deadline)
            child=os.open(name,flags,dir_fd=fd);descriptors.append(child)
            info=os.fstat(child);_need(stat.S_ISDIR(info.st_mode))
            links.append((fd,name,child,_dir_identity(info)));fd=child
        def recheck():
            assets.remaining(deadline)
            _need(_dir_identity(os.stat('/',follow_symlinks=False))==root
                  and _dir_identity(os.fstat(descriptors[0]))==root)
            for parent,name,child,identity in links:
                _need(_dir_identity(os.fstat(child))==identity and
                      _dir_identity(os.stat(name,dir_fd=parent,follow_symlinks=False))==identity)
            assets.remaining(deadline)
        recheck();yield fd,recheck
    finally:
        for fd in reversed(descriptors):os.close(fd)


def _read_verified(path,expected_sha,expected_size,deadline,*,private=False):
    """Read bounded ciphertext through stable no-follow descriptors; no extraction."""
    _need(_hash(expected_sha) and _positive(expected_size) and expected_size<=public_runner.MAX_ENCRYPTED)
    path=pathlib.Path(path)
    with _directory_chain(path.parent,deadline) as (parent,recheck):
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=parent)
        try:
            initial=os.fstat(fd)
            _need(stat.S_ISREG(initial.st_mode) and initial.st_uid==os.geteuid()
                  and initial.st_nlink==1 and initial.st_size==expected_size
                  and not stat.S_IMODE(initial.st_mode)&0o022
                  and (not private or stat.S_IMODE(initial.st_mode)==0o600))
            identity=host._identity(initial);data=bytearray()
            while True:
                assets.remaining(deadline)
                block=os.read(fd,min(65_536,expected_size-len(data)+1))
                assets.remaining(deadline)
                if not block:break
                data.extend(block);_need(len(data)<=expected_size)
            _need(host._identity(os.fstat(fd))==identity
                  and host._identity(os.stat(path.name,dir_fd=parent,follow_symlinks=False))==identity)
            recheck();raw=bytes(data)
            _need(len(raw)==expected_size and driver.digest(raw)==expected_sha)
            assets.remaining(deadline)
            return raw
        finally:os.close(fd)


@contextlib.contextmanager
def _output_directory(context,deadline):
    with _directory_chain(context.runner_temp,deadline) as (parent,recheck):
        info=os.fstat(parent)
        _need(info.st_uid==os.geteuid() and not stat.S_IMODE(info.st_mode)&0o022)
        name=f'ai09-private-pilot-{context.run_id}-{context.attempt}'
        os.mkdir(name,0o700,dir_fd=parent)
        fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
        try:
            initial=os.fstat(fd);identity=_dir_identity(initial)
            _need(initial.st_uid==os.geteuid() and stat.S_IMODE(initial.st_mode)==0o700)
            def check():
                recheck()
                _need(_dir_identity(os.fstat(fd))==identity and
                      _dir_identity(os.stat(name,dir_fd=parent,follow_symlinks=False))==identity)
            check();yield context.runner_temp/name,check
        finally:os.close(fd)


def _read_input(context,deadline):
    return _read_verified(ROOT/'sealed/ai09-private-bundle.aesgcm',
                          context.input_sha,context.input_bytes,deadline)


def _read_key():
    text=os.environ.get('AI09_BUNDLE_KEY_B64')
    _need(type(text) is str and re.fullmatch('[A-Za-z0-9+/]{43}=',text) is not None)
    key=base64.b64decode(text,validate=True)
    _need(len(key)==32 and base64.b64encode(key).decode('ascii')==text)
    return key


def _strict_line(raw,keys,cap):
    _need(0<len(raw)+1<=cap)
    value=driver.parse_json(raw,cap);driver.exact_keys(value,keys)
    _need(driver.encode_json(value)==raw and type(value['v']) is int and value['v']==1)
    return value


def _ready(raw,nonce,session):
    value=_strict_line(raw,_READY_KEYS,512)
    _need(value['kind']=='READY' and value['nonce']==nonce
          and type(value['container_name']) is str
          and re.fullmatch('ai09-model-[0-9a-f]{32}',value['container_name']) is not None
          and _positive(value['work_deadline_ns']) and _positive(value['cleanup_deadline_ns'])
          and 0<value['cleanup_deadline_ns']-value['work_deadline_ns']<=60_001_000_000)
    session.container_name=value['container_name']
    session.work_deadline=min(session.work_deadline,value['work_deadline_ns']/1_000_000_000)
    session.cleanup_deadline=min(session.cleanup_deadline,value['cleanup_deadline_ns']/1_000_000_000)
    assets.remaining(session.work_deadline)
    return value


def _done(raw,nonce):
    value=_strict_line(raw,_DONE_KEYS,1024)
    _need(value['kind']=='DONE' and value['nonce']==nonce and _hash(value['ciphertext_sha256'])
          and _positive(value['ciphertext_bytes'])
          and _MIN_CIPHERTEXT<=value['ciphertext_bytes']<=public_runner.MAX_ENCRYPTED
          and type(value['observed_responses']) is int and value['observed_responses']==8
          and _hash(value['launch_sha256']) and _positive(value['host_start_ns'])
          and _positive(value['host_end_ns']) and value['host_start_ns']<value['host_end_ns'])
    return value


def _exchange(process,context,nonce,session):
    ready=None;done=None;frame=None;offset=0;input_closed=False
    pending=bytearray();total=0;stderr_count=0;open_reads={'stdout','stderr'}
    with selectors.DefaultSelector() as selector:
        for stream in (process.stdin,process.stdout,process.stderr):os.set_blocking(stream.fileno(),False)
        selector.register(process.stdout,selectors.EVENT_READ,'stdout')
        selector.register(process.stderr,selectors.EVENT_READ,'stderr')
        while True:
            events=selector.select(assets.remaining(session.work_deadline))
            _need(events)
            for key,_ in events:
                stream=key.fileobj;label=key.data
                if label=='stdin':
                    try:count=os.write(stream.fileno(),frame[offset:offset+65_536])
                    except BlockingIOError:continue
                    _need(count>0);offset+=count
                    if offset==len(frame):
                        selector.unregister(stream);stream.close();input_closed=True;frame=b''
                    continue
                cap=(4096-total) if label=='stdout' else (1024-stderr_count)
                try:block=os.read(stream.fileno(),max(1,cap+1))
                except BlockingIOError:continue
                if not block:
                    selector.unregister(stream);open_reads.remove(label)
                    if label=='stdout':_need(not pending and done is not None)
                    continue
                if label=='stderr':
                    stderr_count+=len(block);_need(stderr_count<=1024)
                    _need(False)  # Count/discard; any stderr prevents readiness.
                total+=len(block);_need(total<=4096);pending.extend(block)
                while b'\n' in pending:
                    line,_,rest=pending.partition(b'\n');pending=bytearray(rest)
                    if ready is None:ready=_ready(bytes(line),nonce,session)
                    else:
                        _need(input_closed and done is None)
                        done=_done(bytes(line),nonce)
                _need(len(pending)<(512 if ready is None else 1024))
                if ready is not None and frame is None:_need(not pending)
            if ready is not None and frame is None:
                # Drain already queued second frames/stderr before secret lookup.
                if selector.select(0):continue
                _need('stdout' in open_reads and process.poll() is None)
                ciphertext=_read_input(context,session.work_deadline)
                assets.remaining(session.work_deadline)
                key=_read_key();assets.remaining(session.work_deadline)
                frame=(_FRAME_MAGIC+bytes.fromhex(nonce)+key+len(ciphertext).to_bytes(8,'big')+ciphertext)
                selector.register(process.stdin,selectors.EVENT_WRITE,'stdin')
            if not open_reads:
                _need(done is not None and input_closed)
                _need(process.wait(timeout=assets.remaining(session.work_deadline))==0)
                return done


def _abort(process,session):
    """Best-effort bounded cleanup, never evidence of safe asynchronous completion."""
    clean=True
    try:
        if process.stdin and not process.stdin.closed:process.stdin.close()
        try:os.killpg(process.pid,signal.SIGTERM)
        except ProcessLookupError:pass
        if process.poll() is None:
            try:process.wait(timeout=assets.remaining(session.cleanup_deadline,_TERM_GRACE_SECONDS))
            except subprocess.TimeoutExpired:
                try:os.killpg(process.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                process.wait(timeout=assets.remaining(session.cleanup_deadline,_KILL_GRACE_SECONDS))
    except BaseException:
        clean=False
        try:os.killpg(process.pid,signal.SIGKILL)
        except ProcessLookupError:pass
    if session.container_name is not None:
        try:host._remove_container(session,session.container_name)
        except BaseException:clean=False
    return clean


def coordinate() -> bytes:
    """Return only verified canonical public metadata; failures are fixed codes."""
    process=None;session=None;old_term=None
    try:
        context=_context();start=time.monotonic()
        session=_Session(start+_WORK_SECONDS,start+_CLEANUP_SECONDS)
        def interrupted(signum,frame):raise driver.GateError('PRIVATE_PILOT_INTERRUPTED')
        old_term=signal.signal(signal.SIGTERM,interrupted)
        with _output_directory(context,session.work_deadline) as (output,recheck):
            nonce=uuid.uuid4().hex
            process=subprocess.Popen([sys.executable,'-I','-B',str(ROOT/'tools/private_pilot.py'),
                '--child',context.run_id,str(context.attempt),context.commit,str(output),nonce],
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0,
                env=assets.public_fetch_environment(),close_fds=True,start_new_session=True)
            done=_exchange(process,context,nonce,session)
            actual=_read_verified(output/host.EVIDENCE_FILENAME,done['ciphertext_sha256'],
                                  done['ciphertext_bytes'],session.work_deadline,private=True)
            recheck();assets.remaining(session.work_deadline)
            observation={'schema':'AI09-HOST-OBSERVATION-v1','repository':REPOSITORY,
                'run_id':context.run_id,'attempt':context.attempt,'commit':context.commit,
                'input_class':'FROZEN_DATA_ONLY','input_ciphertext_sha256':context.input_sha,
                'input_ciphertext_bytes':context.input_bytes,'output_ciphertext_sha256':driver.digest(actual),
                'output_ciphertext_bytes':len(actual),'observed_responses':8,
                'launch_sha256':done['launch_sha256'],'host_start_ns':done['host_start_ns'],
                'host_end_ns':done['host_end_ns']}
            raw=driver.encode_json(validate_observation(observation))
            recheck();assets.remaining(session.work_deadline)
            return raw
    except BaseException:
        cleanup=True
        if process is not None:cleanup=_abort(process,session)
        code='CLEANUP_UNVERIFIED' if not cleanup or (session and session.container_name) else 'PRIVATE_PILOT_FAILED'
        raise driver.GateError(code) from None
    finally:
        if old_term is not None:signal.signal(signal.SIGTERM,old_term)
        if process is not None:
            for stream in (process.stdin,process.stdout,process.stderr):
                if stream is not None and not stream.closed:stream.close()


def _read_exact(fd,count,deadline):
    data=bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(fd,selectors.EVENT_READ)
        while len(data)<count:
            _need(selector.select(assets.remaining(deadline)))
            try:block=os.read(fd,min(65_536,count-len(data)))
            except BlockingIOError:continue
            _need(block);data.extend(block);assets.remaining(deadline)
    return bytes(data)


def _read_frame(fd,nonce,deadline):
    os.set_blocking(fd,False)
    header=_read_exact(fd,len(_FRAME_MAGIC)+16+32+8,deadline)
    prefix=len(_FRAME_MAGIC)
    _need(header[:prefix]==_FRAME_MAGIC and header[prefix:prefix+16]==bytes.fromhex(nonce))
    size=int.from_bytes(header[-8:],'big');_need(_MIN_CIPHERTEXT<=size<=MAX_CIPHERTEXT)
    ciphertext=_read_exact(fd,size,deadline)
    with selectors.DefaultSelector() as selector:
        selector.register(fd,selectors.EVENT_READ)
        _need(selector.select(assets.remaining(deadline)))
        _need(os.read(fd,1)==b'')
    assets.remaining(deadline)
    return header[prefix+16:prefix+48],ciphertext


def _write_control(value,deadline):
    raw=driver.encode_json(value)+b'\n';_need(len(raw)<=512 if value['kind']=='READY' else len(raw)<=1024)
    os.set_blocking(1,False);offset=0
    with selectors.DefaultSelector() as selector:
        selector.register(1,selectors.EVENT_WRITE)
        while offset<len(raw):
            _need(selector.select(assets.remaining(deadline)))
            try:count=os.write(1,raw[offset:])
            except BlockingIOError:continue
            _need(count>0);offset+=count


def child_main(run_id,attempt,commit,output_directory,nonce):
    old=None
    try:
        _need(_run_id(run_id) and attempt=='1' and _hash(commit,40) and _hash(nonce,32))
        def interrupted(signum,frame):raise driver.GateError('PRIVATE_PILOT_INTERRUPTED')
        old=signal.signal(signal.SIGTERM,interrupted)
        with host.prepare_runtime() as prepared:
            info=host.prepared_cleanup_info(prepared)
            _write_control({'v':1,'kind':'READY','nonce':nonce,'container_name':info.container_name,
                'work_deadline_ns':int(info.work_deadline*1_000_000_000),
                'cleanup_deadline_ns':int(info.cleanup_deadline*1_000_000_000)},info.work_deadline)
            key,ciphertext=_read_frame(0,nonce,info.work_deadline)
            opened=sealed_input.open_frozen_input(ciphertext,key);assets.remaining(info.work_deadline)
            result=host.run_frozen_pilot(prepared,opened.archive_raw,opened.plan_raw,key,
                run_id=run_id,attempt=1,commit=commit,output_directory=pathlib.Path(output_directory))
            assets.remaining(info.work_deadline)
        _write_control({'v':1,'kind':'DONE','nonce':nonce,'ciphertext_sha256':result.ciphertext_sha256,
            'ciphertext_bytes':result.ciphertext_bytes,'observed_responses':result.observed_responses,
            'launch_sha256':result.launch_sha256,'host_start_ns':result.host_start_ns,
            'host_end_ns':result.host_end_ns},info.work_deadline)
        return 0
    except BaseException:return 2
    finally:
        if old is not None:signal.signal(signal.SIGTERM,old)


def main(argv=None):
    args=sys.argv[1:] if argv is None else argv
    if len(args)==6 and args[0]=='--child':return child_main(*args[1:])
    try:
        _need(not args)
        print(OBSERVATION_PREFIX+coordinate().decode('ascii'))
        return 0
    except BaseException as error:
        code=str(error)
        print(code if code in ('PRIVATE_PILOT_FAILED','CLEANUP_UNVERIFIED') else 'PRIVATE_PILOT_FAILED')
        return 2
