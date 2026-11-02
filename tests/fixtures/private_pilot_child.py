"""PUBLIC-only process fixture. Never selected by the production dispatcher."""
import base64
import contextlib
import io
import os
import pathlib
import signal
import sys
import time
import zipfile
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT/'tests'))

import data_driver as driver
import frozen_plan
import pilot_host as host
import public_runner
import sealed_input
import source_archive
from test_frozen_plan import fixture, encode
from test_pilot_host import FakeRuntime

KEY = bytes(range(32))


def public_inputs():
    archive, plan, _ = fixture()
    stream = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(archive)) as source, zipfile.ZipFile(stream, 'w') as target:
        for entry in source.infolist():
            info = zipfile.ZipInfo(entry.filename, (2020, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            target.writestr(info, source.read(entry))
    archive = stream.getvalue(); plan['archive_sha256'] = driver.digest(archive)
    # More than ordinary pipe capacity; original bytes remain exact in transit.
    return archive, encode(plan)+b' '*90_000


def main():
    import private_pilot as private
    mode = sys.argv[1]
    if mode == 'coordinator-term':
        from test_private_pilot import public_connection
        with public_connection() as fixture:
            read=private._read_key
            def terminated():
                os.kill(os.getpid(),signal.SIGTERM)
                return read()
            with patch.object(private,'_read_key',terminated):
                try:private.coordinate()
                except driver.GateError:
                    if all(p.poll() is not None for p in fixture['processes']) and fixture['commands']:
                        os.write(1,b'FIXTURE_CANCELLED_AND_REAPED');return 0
            return 2
    if mode == 'read-frame':
        try:
            key, cipher = private._read_frame(0, '1'*32, time.monotonic()+0.3)
            os.write(1, driver.encode_json({'key_bytes':len(key),'cipher_bytes':len(cipher)}))
            return 0
        except BaseException:
            os.write(1, b'FIXTURE_FRAME_REJECTED'); return 2
    run_id, attempt, commit, output, nonce = sys.argv[2:]
    if any(name in os.environ for name in
           ('AI09_BUNDLE_KEY_B64','GITHUB_TOKEN','GITHUB_OUTPUT','GITHUB_ENV','UNRELATED')):
        return 10
    if mode == 'silent-exit': return 0
    if mode == 'silent-stall': time.sleep(10); return 0
    ready = {'v':1,'kind':'READY','nonce':nonce,'container_name':'ai09-model-'+nonce,
             'work_deadline_ns':time.monotonic_ns()+540_000_000_000,
             'cleanup_deadline_ns':time.monotonic_ns()+600_000_000_000}
    if mode in ('wrong-nonce','duplicate-ready','extra-ready','noncanonical-ready',
                'boolean-deadline','overlong-ready','early-done','stdout-flood',
                'stderr-flood','stderr-ready','stalled-reader','hard-kill','duplex-flood'):
        if mode == 'wrong-nonce': ready['nonce'] = '0'*32
        if mode == 'extra-ready': ready['extra'] = True
        if mode == 'boolean-deadline': ready['work_deadline_ns'] = True
        raw = driver.encode_json(ready)+b'\n'
        if mode == 'duplicate-ready': raw *= 2
        if mode == 'noncanonical-ready': raw = b' '+raw
        if mode == 'overlong-ready': raw = b'X'*513
        if mode == 'early-done': raw = b'{"kind":"DONE"}\n'
        if mode == 'stdout-flood': raw = b'PUBLIC-CONTROL-CANARY'*500
        if mode in ('stderr-flood','stderr-ready'):
            os.write(2, b'PUBLIC-STDERR-CANARY'*(200 if mode=='stderr-flood' else 1))
        if mode == 'hard-kill': signal.signal(signal.SIGTERM, signal.SIG_IGN)
        os.write(1, raw)
        if mode == 'duplex-flood': os.write(1, b'PUBLIC-CONTROL-CANARY'*10_000)
        time.sleep(10); return 0
    archive, plan = public_inputs()
    fake = FakeRuntime()
    if mode == 'ambiguous-create': fake.ambiguous_create = True
    if mode == 'cleanup-failure': fake.bad_cleanup = True
    if mode == 'stop-failure': fake.bad_stop = True
    if mode == 'logs-failure': fake.bad_logs = True
    real_command = fake.command
    def command(args, **kwargs):
        result = real_command(args, **kwargs)
        if mode == 'crash-after-create' and args[1] == 'create': os._exit(3)
        return result
    fake.command = command
    if mode == 'slow-prepare':
        real_download = fake.download
        def download(*args, **kwargs):
            time.sleep(10); return real_download(*args, **kwargs)
        fake.download = download
    if mode == 'slow-capture':
        real_capture = fake.capture
        def capture(*args, **kwargs):
            time.sleep(10); return real_capture(*args, **kwargs)
        fake.capture = capture
    send = private._write_control
    def control(value, deadline):
        if value['kind'] == 'DONE':
            if mode == 'bad-done': value = dict(value, observed_responses=7)
            send(value, deadline)
            if mode == 'extra-done': send(value, deadline)
            if mode == 'stdout-after-done': os.write(1, b'PUBLIC-EXTRA-OUTPUT')
            if mode == 'stderr-after-done': os.write(2, b'PUBLIC-STDERR-CANARY')
            if mode == 'mutated-output':
                path=pathlib.Path(output)/host.EVIDENCE_FILENAME
                data=path.read_bytes();path.write_bytes(data[:-1]+bytes([data[-1]^1]))
            if mode == 'missing-output': (pathlib.Path(output)/host.EVIDENCE_FILENAME).unlink()
            if mode in ('symlink-output','hardlink-output'):
                path=pathlib.Path(output)/host.EVIDENCE_FILENAME
                original=path.with_name('original-ciphertext');path.rename(original)
                if mode=='symlink-output':path.symlink_to(original)
                else:os.link(original,path)
            if mode == 'stall-after-done': time.sleep(10)
        else: send(value, deadline)
    with fake.install(), patch.object(source_archive,'FROZEN_SHA',driver.digest(archive)), \
         patch.object(frozen_plan,'FROZEN_PLAN_SHA',driver.digest(plan)), \
         patch.object(private,'_write_control',control), contextlib.ExitStack() as stack:
        # The legacy PUBLIC FakeRuntime helper adds its own fake env canary.
        # Remove that fixture-only injection before preparation, not production env.
        os.environ.pop('AI09_BUNDLE_KEY_B64',None)
        if mode == 'slow-decode':
            decode=sealed_input.open_frozen_input
            def delayed_decode(*args): time.sleep(10); return decode(*args)
            stack.enter_context(patch.object(sealed_input,'open_frozen_input',delayed_decode))
        if mode == 'slow-fsync':
            fsync=os.fsync
            def delayed_fsync(fd): time.sleep(10); return fsync(fd)
            stack.enter_context(patch.object(os,'fsync',delayed_fsync))
        code=private.child_main(run_id, attempt, commit, output, nonce)
    return 7 if mode=='nonzero-exit' else code


if __name__ == '__main__':
    try: raise SystemExit(main())
    except Exception: raise SystemExit(2)
