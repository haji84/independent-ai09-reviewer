"""Trusted Linux host for bounded observations and verified ciphertext export.

Preparation receives no source or key. Its opaque, single-use handle is valid
only within that context and its original deadline. This is not an admission
gate, model attestation or authority to run private inputs. No private CLI or
workflow invokes it. The host process, reviewed code, Docker daemon and private
output directory are trusted; this does not contain a hostile same-user host.
"""
import contextlib
import dataclasses
import importlib.util
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid
import weakref

import context_probe
import data_driver as driver
import frozen_plan
import pilot_batch
import public_runner
import runtime_assets as assets
from confidential_capture import capture

ROOT = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('sandbox_policy', ROOT/'tools'/'sandbox_probe.py')
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)
EVIDENCE_FILENAME = 'ai09-observed-evidence.aesgcm'
PURPOSE = b'CONFIDENTIAL-REVIEW-EVIDENCE'
GUEST_ERRORS = {'PUBLIC_MODEL_INPUT_REJECTED', 'PUBLIC_MODEL_STARTUP_FAILED',
    'PUBLIC_MODEL_INVENTORY_MISMATCH', 'PUBLIC_MODEL_TRANSPORT_FAILED',
    'PUBLIC_MODEL_RESPONSE_REJECTED', 'PUBLIC_MODEL_CONTEXT_REJECTION_FAILED'}
SAFE_ERRORS = {'LINUX_DOCKER_ZSTD_REQUIRED', 'PUBLIC_DISK_BUDGET', 'PUBLIC_RUNTIME_DEADLINE',
    'PUBLIC_ASSET_DOWNLOAD_FAILED', 'PUBLIC_ASSET_MISMATCH', 'PUBLIC_ASSET_URL_BLOCKED',
    'PUBLIC_TAR_UNSUPPORTED', 'PUBLIC_TAR_LIMIT', 'PUBLIC_CPU_LIMIT', 'PUBLIC_CPU_INCOMPLETE',
    'PUBLIC_TAR_PATH', 'PUBLIC_TAR_HEADER', 'PUBLIC_TAR_TRUNCATED', 'PUBLIC_TAR_ALIAS',
    'PUBLIC_TAR_COLLISION', 'PUBLIC_TAR_DUPLICATE', 'PUBLIC_TAR_TERMINATOR', 'PUBLIC_TAR_TRAILING',
    'PUBLIC_TAR_DECODE_FAILED', 'MODEL_MANIFEST_MISMATCH', 'PUBLIC_DOCKER_FAILED',
    'CAPTURE_EXIT', 'CAPTURE_TIMEOUT', 'CAPTURE_LIMIT', 'CAPTURE_FAILED', 'CAPTURE_CLEANUP_FAILED',
    'CONTAINER_STOP_UNVERIFIED', 'INVALID_OBSERVED_BATCH', 'PREPARED_RUNTIME_UNAVAILABLE',
    'HOST_OPERATION_FAILED', 'HOST_CLEANUP_UNVERIFIED', 'EVIDENCE_EXPORT_FAILED',
    'FROZEN_SOURCE_HASH_MISMATCH', 'FROZEN_PLAN_HASH_MISMATCH', 'INVALID_FROZEN_PLAN',
    'FROZEN_PLAN_COVERAGE', 'FROZEN_PLAN_CANONICAL_HASH_MISMATCH', 'FROZEN_PLAN_ENCODING',
    'FROZEN_PLAN_LINE_CONVENTION', 'ARCHIVE_SIZE_OR_TYPE', 'PLAN_SIZE_OR_TYPE',
    context_probe.CODE} | GUEST_ERRORS | policy.SAFE_ERRORS


def _safe(error):
    code = str(error)
    return driver.GateError(code if code in SAFE_ERRORS else 'HOST_OPERATION_FAILED')


@dataclasses.dataclass(frozen=True, repr=False)
class ExportResult:
    ciphertext_sha256: str
    ciphertext_bytes: int
    observed_responses: int = dataclasses.field(default=8, init=False)
    fixed_subject_receipts: int = dataclasses.field(default=0, init=False)

    def __repr__(self):
        return 'ExportResult()'


@dataclasses.dataclass(frozen=True, repr=False)
class PilotResult(ExportResult):
    launch_sha256: str
    packet_sha256: str
    context_rejection_sha256: str
    context_rejection_tokens: int
    elapsed_seconds: float

    def __repr__(self):
        return 'PilotResult()'


class _PreparedRuntime:
    __slots__ = ('__weakref__',)

    def __repr__(self):
        return 'PreparedRuntime()'


@dataclasses.dataclass(repr=False)
class _Runtime:
    started: float
    work_deadline: float
    cleanup_deadline: float
    image_id: str
    runtime: pathlib.Path
    runtime_hashes: dict
    models: pathlib.Path
    manifest: pathlib.Path
    blobs: tuple
    mounts: dict
    code_hashes: dict


_prepared = weakref.WeakKeyDictionary()


def _docker(state, *args, check=True, cleanup=False):
    result = subprocess.run(['docker', *args], env={'PATH':os.defpath},
        stdin=subprocess.DEVNULL, capture_output=True, text=True,
        timeout=assets.remaining(state.cleanup_deadline if cleanup else state.work_deadline, 15))
    driver.require(len(result.stdout)+len(result.stderr) <= 65_536 and
                   (not check or result.returncode == 0), 'PUBLIC_DOCKER_FAILED')
    return result


@contextlib.contextmanager
def prepare_runtime():
    """Prefetch only pinned PUBLIC assets; yield one host-owned execution handle.

    Call this before obtaining private input/key. Handles have no serializable
    configuration and are accepted only by object identity in this context.
    Python introspection or malicious code in this host is outside the boundary.
    """
    token = None
    try:
        if sys.platform != 'linux' or not shutil.which('docker') or not shutil.which('zstd'):
            raise driver.GateError('LINUX_DOCKER_ZSTD_REQUIRED')
        start = time.monotonic()
        driver.require(shutil.disk_usage(tempfile.gettempdir()).free >= 8*1024**3, 'PUBLIC_DISK_BUDGET')
        with tempfile.TemporaryDirectory(prefix='ai09-public-model-') as directory:
            base = pathlib.Path(directory); base.chmod(0o755)
            state = _Runtime(start, start+540, start+600, '', base/'runtime', {},
                             base/'models', base/'manifest', (), {}, {})
            state.image_id = json.loads(_docker(state, 'image', 'inspect', policy.IMAGE).stdout)[0]['Id']
            archive = base/'ollama.tar.zst'
            assets.download(assets.OLLAMA_URL, archive, assets.OLLAMA_SIZE, assets.OLLAMA_SHA, state.work_deadline)
            assets.download(assets.MANIFEST_URL, state.manifest, assets.MANIFEST_SIZE, assets.MODEL_SHA, state.work_deadline)
            manifest = state.manifest.read_bytes(); state.blobs = assets.model_blobs(manifest)
            (state.models/'blobs').mkdir(parents=True, mode=0o755)
            for digest, size in state.blobs:
                assets.download('https://registry.ollama.ai/v2/library/qwen3/blobs/sha256:'+digest,
                    state.models/'blobs'/('sha256-'+digest), size, digest, state.work_deadline)
            state.manifest = state.models/'manifests'/'registry.ollama.ai'/'library'/'qwen3'/'1.7b'
            state.manifest.parent.mkdir(parents=True, mode=0o755)
            with state.manifest.open('xb') as output: output.write(manifest)
            state.manifest.chmod(0o444)
            state.runtime_hashes = assets.stage_cpu(archive, state.runtime, state.work_deadline)
            state.mounts = {'/opt/runtime':str(state.runtime), '/models':str(state.models),
                            '/guest.py':str(ROOT/'tests'/'fixtures'/'model_guest.py')}
            for name in ('data_driver.py', 'loopback_client.py', 'runtime_assets.py', 'context_probe.py', 'pilot_batch.py'):
                state.mounts['/code/'+name] = str(ROOT/name)
            state.code_hashes = {target:driver.digest(pathlib.Path(path).read_bytes())
                for target, path in state.mounts.items() if target.startswith('/code/') or target == '/guest.py'}
            _reverify(state)
            token = _PreparedRuntime(); _prepared[token] = state
            yield token
    except BaseException as error:
        raise _safe(error) from None
    finally:
        if token is not None: _prepared.pop(token, None)


def _consume(prepared):
    driver.require(type(prepared) is _PreparedRuntime and prepared in _prepared,
                   'PREPARED_RUNTIME_UNAVAILABLE')
    state = _prepared.pop(prepared)  # Single attempt, including expiration/failure.
    assets.remaining(state.work_deadline)
    return state


def _reverify(state):
    for name, digest in state.runtime_hashes.items():
        path = state.runtime/name
        assets.verify_file(path, path.stat().st_size, digest, state.work_deadline)
    for digest, size in state.blobs:
        assets.verify_file(state.models/'blobs'/('sha256-'+digest), size, digest, state.work_deadline)
    assets.verify_file(state.manifest, assets.MANIFEST_SIZE, assets.MODEL_SHA, state.work_deadline)
    for target, digest in state.code_hashes.items():
        path = pathlib.Path(state.mounts[target])
        assets.verify_file(path, path.stat().st_size, digest, state.work_deadline)
    assets.remaining(state.work_deadline)


@contextlib.contextmanager
def staged_batch(batch):
    """Mount exactly one data file, never its private parent or original ZIP."""
    raw = pilot_batch.encode_batch(batch)
    with tempfile.TemporaryDirectory(prefix='ai09-batch-data-') as directory:
        parent = pathlib.Path(directory); parent.chmod(0o700)
        path = parent/'batch.json'
        with path.open('xb') as output: output.write(raw)
        path.chmod(0o444)
        yield path


def validate_public_packet(raw, expected, host_start, host_end):
    """Compatibility name: validates observation/negative probe, not classification."""
    value = driver.parse_json(raw, driver.MAX_PACKET)
    if type(value) is dict and set(value) == {'error'} and type(value['error']) is str and value['error'] in GUEST_ERRORS:
        raise driver.GateError(value['error'])
    verified = pilot_batch.verify_observation(raw, expected, host_start, host_end)
    tokens = context_probe.verify_rejection(value['context_rejection'], expected,
        not_before=value['exchanges'][-1]['finished_ns'], not_after=host_end)
    return verified, tokens, driver.digest(driver.encode_json(value['context_rejection']))


def _remove_container(state, name):
    """An uncertain create needs removal and a point-in-time absence check.

    This observes the trusted daemon's current listing; it does not establish
    that an asynchronous create could never complete after that observation.
    """
    try:
        _docker(state, 'rm', '--force', name, check=False, cleanup=True)
        remaining = _docker(state, 'ps', '--all', '--quiet', '--filter', 'name=^/'+name+'$', cleanup=True)
        driver.require(not remaining.stdout.strip(), 'HOST_CLEANUP_UNVERIFIED')
    except BaseException:
        raise driver.GateError('HOST_CLEANUP_UNVERIFIED') from None


def _observe(state, expected, input_class):
    _reverify(state)
    with staged_batch(expected) as input_path:
        mounts = dict(state.mounts, **{'/input/batch.json':str(input_path)})
        launch = {'image':state.image_id, 'runtime':state.runtime_hashes,
            'driver':state.code_hashes, 'ollama_archive':assets.OLLAMA_SHA, 'model':assets.MODEL_SHA,
            'model_blobs':state.blobs, 'context':expected.context(), 'input_class':input_class,
            'staged_input_sha':driver.digest(pilot_batch.encode_batch(expected))}
        name = 'ai09-model-'+uuid.uuid4().hex
        try:
            args = ['create', '--name', name, '--pull=never', '--log-driver=none', '--network=none',
                '--user=65534:65534', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
                '--pids-limit=128', '--memory=4g', '--memory-swap=4g', '--cpus=2', '--ipc=private',
                '--ulimit', 'fsize=1048576:1048576', '--tmpfs', '/scratch:'+policy.MODEL_TMPFS]
            for target, path in mounts.items(): args += ['--mount', f'type=bind,source={path},target={target},readonly']
            args += [policy.IMAGE, 'python', '-I', '-B', '/guest.py', expected.run_id, str(expected.attempt), expected.commit]
            _docker(state, *args)
            inspection = json.loads(_docker(state, 'inspect', name).stdout)[0]
            policy.validate_inspection(inspection, state.image_id, mounts, profile='public-model')
            fields = (*policy.EFFECTIVE_FIELDS, 'SecurityOpt', 'LogConfig', 'Tmpfs', 'IpcMode')
            launch['container_id'] = inspection['Id']
            launch['inspection'] = {field:inspection['HostConfig'].get(field) for field in fields}
            # Canonical deep copy is controlled solely by this host, never guest output.
            launch = driver.parse_json(driver.encode_json(launch))
            def stop():
                _docker(state, 'kill', name, check=False, cleanup=True)
                _docker(state, 'wait', name, cleanup=True)
                status = json.loads(_docker(state, 'inspect', name, cleanup=True).stdout)[0]['State']
                return status['Running'] is False and status['Pid'] == 0 and status['Status'] == 'exited'
            host_start = time.time_ns()
            raw = capture(['docker', 'start', '--attach', name], {'PATH':os.defpath}, stop,
                timeout=assets.remaining(state.work_deadline, 480), max_bytes=driver.MAX_PACKET)
            host_end = time.time_ns()
            policy.validate_logs(_docker(state, 'logs', name, check=False, cleanup=True))
            assets.remaining(state.work_deadline)
        finally:
            # Do not gate this on a successful create response: its outcome may be ambiguous.
            # Cleanup failure overrides an earlier failure and prevents seal/export.
            _remove_container(state, name)
    return raw, launch, host_start, host_end


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mode, info.st_uid,
            info.st_nlink, info.st_mtime_ns, info.st_ctime_ns)


def _regular(info, size):
    driver.require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600 and
        info.st_uid == os.geteuid() and info.st_nlink == 1 and info.st_size == size, 'EVIDENCE_EXPORT_FAILED')


@contextlib.contextmanager
def _private_directory(directory, deadline):
    """Keep and revalidate every root-to-output directory/name relationship."""
    path = os.fspath(directory)
    driver.require(type(path) is str and path.startswith('/') and len(path) <= 4096,
                   'EVIDENCE_EXPORT_FAILED')
    parts = path.split('/')[1:]
    driver.require(parts and all(part not in ('', '.', '..') for part in parts), 'EVIDENCE_EXPORT_FAILED')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    def directory_identity(info):
        return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)
    with contextlib.ExitStack() as stack:
        root = os.open('/', flags); stack.callback(os.close, root)
        root_identity = directory_identity(os.fstat(root))
        parent = root; relationships = []
        for part in parts:
            assets.remaining(deadline)
            child = os.open(part, flags, dir_fd=parent); stack.callback(os.close, child)
            relationships.append((parent, part, child, directory_identity(os.fstat(child))))
            parent = child
        descriptor = parent
        info = os.fstat(descriptor)
        driver.require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700 and
                       info.st_uid == os.geteuid(), 'EVIDENCE_EXPORT_FAILED')
        def check_entry():
            assets.remaining(deadline)
            driver.require(directory_identity(os.fstat(root)) == root_identity and
                           directory_identity(os.stat('/', follow_symlinks=False)) == root_identity,
                           'EVIDENCE_EXPORT_FAILED')
            for parent_fd, name, child_fd, expected in relationships:
                assets.remaining(deadline)
                current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                driver.require(directory_identity(current) == expected and
                               directory_identity(os.fstat(child_fd)) == expected,
                               'EVIDENCE_EXPORT_FAILED')
            current = os.fstat(descriptor)
            driver.require((current.st_dev, current.st_ino, current.st_mode, current.st_uid) ==
                           (info.st_dev, info.st_ino, info.st_mode, info.st_uid), 'EVIDENCE_EXPORT_FAILED')
            assets.remaining(deadline)
        check_entry()
        yield descriptor, check_entry
        check_entry()


def _export_evidence(payload, key, verify, directory, deadline):
    """Only ciphertext touches disk; success follows authenticated actual readback.

    Existing names are never replaced, removed or accepted. A failed/ambiguous
    write can leave encrypted partial bytes; retry requires a new trusted output
    directory. fsync is checked, but power-loss atomicity and interruption of a
    blocked filesystem syscall are not promised. The semantic verifier is an
    internal trusted-host closure, not a callback accepted from model output.
    """
    try:
        assets.remaining(deadline)
        driver.require(type(payload) is bytes and 0 < len(payload) <= driver.MAX_PACKET and
                       type(key) is bytes and len(key) == 32, 'EVIDENCE_EXPORT_FAILED')
        original = verify(payload)
        encrypted = public_runner.seal(payload, key, PURPOSE)
        driver.require(type(encrypted) is bytes and 0 < len(encrypted) <= public_runner.MAX_ENCRYPTED,
                       'EVIDENCE_EXPORT_FAILED')
        replay = verify(public_runner.unseal(encrypted, key, PURPOSE))
        driver.require(replay.payload == original.payload and replay.observed_responses == 8 and
                       replay.fixed_subject_receipts == 0, 'EVIDENCE_EXPORT_FAILED')
        digest = driver.digest(encrypted)
        assets.remaining(deadline)
        with _private_directory(directory, deadline) as (directory_fd, check_directory), contextlib.ExitStack() as stack:
            writer = os.open(EVIDENCE_FILENAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory_fd)
            stack.callback(os.close, writer)
            os.fchmod(writer, 0o600)
            _regular(os.fstat(writer), 0)
            position = 0
            while position < len(encrypted):
                assets.remaining(deadline)
                block = memoryview(encrypted)[position:position+65_536]
                count = os.write(writer, block)
                driver.require(type(count) is int and 0 < count <= len(block), 'EVIDENCE_EXPORT_FAILED')
                position += count
                assets.remaining(deadline)
            os.fsync(writer); assets.remaining(deadline)
            written = os.fstat(writer); _regular(written, len(encrypted))
            os.fsync(directory_fd); assets.remaining(deadline)
            reader = os.open(EVIDENCE_FILENAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                             os.O_CLOEXEC, dir_fd=directory_fd)
            stack.callback(os.close, reader)
            def check_file():
                assets.remaining(deadline)
                for current in (os.fstat(writer), os.fstat(reader),
                        os.stat(EVIDENCE_FILENAME, dir_fd=directory_fd, follow_symlinks=False)):
                    _regular(current, len(encrypted))
                    driver.require(_identity(current) == _identity(written), 'EVIDENCE_EXPORT_FAILED')
                check_directory()
            check_file()
            recovered = bytearray()
            while True:
                assets.remaining(deadline)
                block = os.read(reader, min(65_536, len(encrypted)-len(recovered)+1))
                assets.remaining(deadline)
                if not block: break
                recovered.extend(block)
                driver.require(len(recovered) <= len(encrypted), 'EVIDENCE_EXPORT_FAILED')
            actual = bytes(recovered)
            driver.require(len(actual) == len(encrypted) and driver.digest(actual) == digest,
                           'EVIDENCE_EXPORT_FAILED')
            verified = verify(public_runner.unseal(actual, key, PURPOSE))
            driver.require(verified.payload == original.payload and verified.observed_responses == 8 and
                           verified.fixed_subject_receipts == 0, 'EVIDENCE_EXPORT_FAILED')
            check_file()
        assets.remaining(deadline)
        return ExportResult(digest, len(encrypted))
    except BaseException:
        # OS exception messages can contain private paths or attacker-controlled text.
        raise driver.GateError('EVIDENCE_EXPORT_FAILED') from None


def _run(state, expected, input_class, key, output_directory, envelope, verify):
    driver.require(type(key) is bytes and len(key) == 32, 'EVIDENCE_EXPORT_FAILED')
    raw, launch, start, end = _observe(state, expected, input_class)
    verified, tokens, rejection_hash = validate_public_packet(raw, expected, start, end)
    assets.remaining(state.work_deadline)
    payload = envelope(raw, launch, start, end)
    result = _export_evidence(payload, key, lambda content:verify(content, launch, start, end),
                              output_directory, state.work_deadline)
    assets.remaining(state.work_deadline)
    return PilotResult(result.ciphertext_sha256, result.ciphertext_bytes,
        driver.digest(driver.encode_json(launch)), driver.digest(verified.payload),
        rejection_hash, tokens, round(time.monotonic()-state.started, 2))


def run_public_pilot(prepared, *, run_id, attempt, commit, output_directory):
    """Fixed PUBLIC toy inputs and public test key only; no caller input override."""
    try:
        state = _consume(prepared)
        chunks = tuple(driver.Chunk(f'{i:03}', f'PUBLIC{i}.py', 1,
            b'def add(a, b):\n    return a + b\n') for i in range(8))
        expected = driver.Batch(run_id, attempt, commit, driver.digest(b'PUBLIC-TOY-SOURCE'),
                                driver.digest(b'PUBLIC-TOY-NO-PLAN'), chunks)
        return _run(state, expected, 'PUBLIC_SYNTHETIC', bytes(range(32)), output_directory,
            lambda raw, launch, start, end:pilot_batch.evidence_envelope(raw, expected, launch, start, end),
            lambda payload, launch, start, end:pilot_batch.verify_evidence(payload, expected, launch, start, end))
    except BaseException as error:
        raise _safe(error) from None


def run_frozen_pilot(prepared, archive_raw, plan_raw, key, *, run_id, attempt, commit, output_directory):
    """Separate data-only library path, without private activation/admission.

    Obtain the prepared handle before reading private bytes/key. All 104 spans
    are freshly verified before selecting 000..007; callers supply no Batch,
    VerifiedPlan, hash/selection/classification override. No workflow calls this.
    """
    try:
        state = _consume(prepared)
        expected = frozen_plan.prepare_pilot_batch(archive_raw, plan_raw, run_id=run_id, attempt=attempt, commit=commit)
        def envelope(raw, launch, start, end):
            return pilot_batch.frozen_evidence_envelope(raw, archive_raw, plan_raw, run_id=run_id,
                attempt=attempt, commit=commit, launch=launch, host_start=start, host_end=end)
        def verify(payload, launch, start, end):
            return pilot_batch.verify_frozen_evidence(payload, archive_raw, plan_raw, run_id=run_id,
                attempt=attempt, commit=commit, launch=launch, host_start=start, host_end=end)
        return _run(state, expected, 'FROZEN_DATA_ONLY', key, output_directory, envelope, verify)
    except BaseException as error:
        raise _safe(error) from None
