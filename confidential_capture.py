"""Linux binary capture. No output is released until host teardown succeeds.

The trusted caller owns the Docker identity and must kill/wait/inspect it in
stop_and_verify. Killing the CLI/process group alone is not Docker containment.
This module cannot attest that callback or enable production/private execution.
"""
import os
import selectors
import signal
import subprocess
import sys
import time


class CaptureError(RuntimeError):
    pass


def capture(argv, env, stop_and_verify, *, timeout=60, max_bytes=2_000_000):
    if sys.platform != 'linux':
        raise CaptureError('LINUX_CAPTURE_REQUIRED')
    if not (0 < timeout <= 600 and type(max_bytes) is int and 0 < max_bytes <= 2_000_000):
        raise CaptureError('INVALID_CAPTURE_LIMIT')
    process = None
    payload = bytearray()
    failure = None
    deadline = time.monotonic() + timeout
    try:
        process = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   start_new_session=True, close_fds=True)
        os.set_blocking(process.stdout.fileno(), False)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            eof = False
            while not eof or process.poll() is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise CaptureError('CAPTURE_TIMEOUT')
                if eof:
                    time.sleep(min(0.01, remaining))
                    continue
                for key, _ in selector.select(min(0.1, remaining)):
                    block = os.read(key.fd, min(65_536, max_bytes-len(payload)+1))
                    if not block:
                        selector.unregister(key.fileobj)
                        eof = True
                        break
                    if len(payload) + len(block) > max_bytes:
                        raise CaptureError('CAPTURE_LIMIT')
                    payload.extend(block)
        if process.returncode != 0:
            raise CaptureError('CAPTURE_EXIT')
    except CaptureError as error:
        failure = str(error)
    except BaseException:
        # Do not leak argv, server content, environment or exception details.
        failure = 'CAPTURE_FAILED'
    finally:
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError:
                failure = 'CAPTURE_CLEANUP_FAILED'
            try:
                process.wait(timeout=2)
                process.stdout.close()
            except (OSError, subprocess.TimeoutExpired):
                failure = 'CAPTURE_CLEANUP_FAILED'
        try:
            stopped = stop_and_verify()
        except BaseException:
            stopped = False
        if stopped is not True:
            failure = 'CONTAINER_STOP_UNVERIFIED'
    if failure:
        payload.clear()
        raise CaptureError(failure)
    return bytes(payload)
