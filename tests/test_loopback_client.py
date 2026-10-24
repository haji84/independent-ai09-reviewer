"""Fake loopback HTTP, including adversarial slow and oversized bodies."""
import socket
import threading
import time
import unittest

from data_driver import GateError
from loopback_client import post_json


class LoopbackClientTest(unittest.TestCase):
    def serve(self, reply):
        server = socket.socket()
        server.bind(('127.0.0.1', 0)); server.listen(1)
        port = server.getsockname()[1]
        def run():
            try:
                with server:
                    conn, _ = server.accept()
                    with conn:
                        conn.settimeout(2)
                        conn.recv(65536)
                        try: reply(conn)
                        except OSError: pass
            except OSError: pass
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        self.addCleanup(lambda: thread.join(3))
        return port

    def call(self, port, seconds=1):
        return post_json(b'{}', port=port, deadline=time.monotonic()+seconds)

    def test_length_and_chunked_response_bodies_are_recorded_exactly(self):
        replies = [b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}',
                   b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n']
        for reply in replies:
            self.assertEqual(self.call(self.serve(lambda conn: conn.sendall(reply))), b'{}')

    def test_slow_header_and_body_have_overall_deadline(self):
        for prefix in (b'', b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n'):
            def reply(conn):
                conn.sendall(prefix)
                for _ in range(50):
                    conn.sendall(b'x'); time.sleep(0.02)
            start = time.monotonic()
            with self.assertRaisesRegex(GateError, '^MODEL_TRANSPORT_FAILED$'):
                self.call(self.serve(reply), seconds=0.15)
            self.assertLess(time.monotonic()-start, 0.8)

    def test_redirect_duplicate_length_oversize_and_bad_type_are_rejected(self):
        replies = [b'HTTP/1.1 302 Found\r\nLocation: https://example.com/\r\n\r\n',
                   b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}',
                   b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 9999999\r\n\r\n',
                   b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 2\r\n\r\n{}',
                   b'HTTP/1.1 200 OK\r\nX: '+b'x'*20000+b'\r\n\r\n']
        for reply in replies:
            with self.assertRaises(GateError):
                self.call(self.serve(lambda conn: conn.sendall(reply)))


if __name__ == '__main__': unittest.main()
