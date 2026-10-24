"""Only public canaries. Linux CI is required for process containment tests."""
import os
import pathlib
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from confidential_capture import CaptureError, capture


class PlatformCaptureTest(unittest.TestCase):
    def test_windows_capture_fails_before_starting_process(self):
        with patch('confidential_capture.sys.platform', 'win32'):
            with patch('confidential_capture.subprocess.Popen') as spawn:
                with self.assertRaisesRegex(CaptureError, '^LINUX_CAPTURE_REQUIRED$'):
                    capture(['unused'], {}, lambda: True)
                spawn.assert_not_called()


@unittest.skipUnless(sys.platform == 'linux', 'Linux-only containment; mandatory Linux CI')
class LinuxCaptureTest(unittest.TestCase):
    def run_capture(self, code, stop=lambda: True, **kwargs):
        return capture([sys.executable, '-I', '-c', code], {'PATH':os.defpath}, stop,
                       timeout=kwargs.pop('timeout', 1), **kwargs)

    def test_output_returns_only_after_positive_stop_verification(self):
        calls = []
        def stop():
            calls.append('STOPPED')
            return True
        self.assertEqual(self.run_capture("print('PUBLIC-SYNTHETIC')", stop), b'PUBLIC-SYNTHETIC\n')
        self.assertEqual(calls, ['STOPPED'])

    def test_uncertain_or_throwing_teardown_never_returns_payload(self):
        def broken(): raise RuntimeError('PRIVATE-MUST-NOT-ESCAPE')
        for stop in (lambda: False, lambda: None, lambda: 1, broken):
            with self.subTest(stop=stop):
                with self.assertRaisesRegex(CaptureError, '^CONTAINER_STOP_UNVERIFIED$'):
                    self.run_capture("print('PUBLIC-SYNTHETIC')", stop)

    def test_timeout_and_oversize_stop_worker_and_suppress_stderr(self):
        for code, error in [("import time;time.sleep(20)", 'CAPTURE_TIMEOUT'),
                            ("import os;os.write(1,b'x'*10000)", 'CAPTURE_LIMIT'),
                            ("import sys;sys.stderr.write('PRIVATE'*100000);sys.exit(7)", 'CAPTURE_EXIT')]:
            calls = []
            with self.subTest(error=error):
                with self.assertRaisesRegex(CaptureError, '^'+error+'$'):
                    self.run_capture(code, lambda: calls.append(True) or True, max_bytes=1000)
                self.assertEqual(calls, [True])

    def test_inherited_pipe_child_cannot_extend_deadline(self):
        code = "import os,time;pid=os.fork();time.sleep(20) if pid==0 else os._exit(0)"
        start = time.monotonic()
        with self.assertRaisesRegex(CaptureError, '^CAPTURE_TIMEOUT$'):
            self.run_capture(code, timeout=0.25)
        self.assertLess(time.monotonic()-start, 3)

    def test_background_child_is_killed_even_after_parent_success(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = pathlib.Path(directory)/'public-marker'
            code = ("import os,time,pathlib;pid=os.fork();"
                    "os.close(1) if pid==0 else None;"
                    "time.sleep(0.6) if pid==0 else None;"
                    f"pathlib.Path({str(marker)!r}).touch() if pid==0 else None")
            self.run_capture(code)
            time.sleep(0.8)
            self.assertFalse(marker.exists())


if __name__ == '__main__': unittest.main()
