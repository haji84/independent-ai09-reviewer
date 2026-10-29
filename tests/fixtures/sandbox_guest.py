"""Public hostile fixture. It never receives real source, keys or model data."""
import errno,os,pathlib,resource,signal,socket,sys,time

assert os.getuid()==65534 and os.getgid()==65534
for key in os.environ:
    assert not key.startswith(('AI09_','GITHUB_','ACTIONS_','RUNNER_'))
environ=pathlib.Path('/proc/self/environ').read_bytes()
assert b'SYNTHETIC-NOT-A-KEY' not in environ
assert b'SYNTHETIC-NOT-A-TOKEN' not in environ
status=pathlib.Path('/proc/self/status').read_text()
assert 'CapEff:\t0000000000000000' in status
assert 'NoNewPrivs:\t1' in status
assert 'Seccomp:\t2' in status
assert set(os.listdir('/sys/class/net'))=={'lo'}
assert not pathlib.Path('/var/run/docker.sock').exists()
assert not pathlib.Path('/run/containerd/containerd.sock').exists()
assert not pathlib.Path(sys.argv[2]).exists()
assert not pathlib.Path('/github').exists()

def denied(operation):
    try:operation()
    except OSError:return
    raise AssertionError('SYNTHETIC_OPERATION_WAS_ALLOWED')

denied(lambda:os.setuid(0))
denied(lambda:pathlib.Path('/etc/ai09-synthetic').write_text('public'))
canary=pathlib.Path('/input/canary')
denied(lambda:canary.write_text('tamper'))
denied(lambda:canary.rename('/input/renamed'))
denied(lambda:canary.unlink())
denied(lambda:pathlib.Path('/input/new-file').write_text('public'))
assert canary.read_bytes()==b'PUBLIC-SYNTHETIC-INPUT'
link=pathlib.Path('/scratch/symlink');link.symlink_to(canary)
denied(lambda:link.write_text('tamper'))

with socket.socket() as server:
    server.bind(('127.0.0.1',0));server.listen(1)
    with socket.create_connection(server.getsockname(),timeout=1) as client:
        peer,_=server.accept();peer.close()
for family,address in ((socket.AF_INET,('198.51.100.1',9)),
                       (socket.AF_INET6,('2001:db8::1',9))):
    try:
        with socket.socket(family,socket.SOCK_STREAM) as client:
            client.settimeout(1)
            try:client.connect(address)
            except OSError as error:
                assert error.errno in (errno.ENETUNREACH,errno.EHOSTUNREACH,errno.EAFNOSUPPORT)
            else:raise AssertionError('SYNTHETIC_NETWORK_ESCAPE')
    except OSError as error:assert error.errno==errno.EAFNOSUPPORT

signal.signal(signal.SIGXFSZ,signal.SIG_IGN)
denied(lambda:pathlib.Path('/scratch/oversize').write_bytes(b'P'*2_000_000))
assert pathlib.Path('/scratch/oversize').stat().st_size<=1_048_576
assert resource.getrlimit(resource.RLIMIT_FSIZE)==(1_048_576,1_048_576)
# A synthetic workflow command must never be attached to the Actions log.
print('::warning::PUBLIC-SYNTHETIC-STDOUT-CANARY',flush=True)
print('PUBLIC-SYNTHETIC-STDERR-CANARY',file=sys.stderr,flush=True)

# Child acknowledges its TERM handler before PID1 signals ready to the host.
read_fd,write_fd=os.pipe()
child=os.fork()
if child==0:
    os.close(read_fd)
    signal.signal(signal.SIGTERM,signal.SIG_IGN)
    os.write(write_fd,b'READY');os.close(write_fd)
    time.sleep(90)
    os._exit(0)
os.close(write_fd)
assert os.read(read_fd,5)==b'READY';os.close(read_fd)
if sys.argv[1]=='hang':signal.signal(signal.SIGTERM,signal.SIG_IGN)
pathlib.Path('/scratch/ready').write_text('PUBLIC-SYNTHETIC-READY')
if sys.argv[1]=='hang':
    time.sleep(90)
else:
    deadline=time.monotonic()+30
    while not pathlib.Path('/scratch/release').exists():
        assert time.monotonic()<deadline
        time.sleep(0.1)
    os._exit(0)
