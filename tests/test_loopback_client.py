"""Fake loopback HTTP, including adversarial slow and oversized bodies."""
import socket
import threading
import time
import unittest

from data_driver import GateError
from loopback_client import get_json, post_json
import loopback_client as transport


class LoopbackClientTest(unittest.TestCase):
    def rejection(self,port,seconds=1):
        operation=getattr(transport,'post_context_rejection',None)
        self.assertTrue(callable(operation),'400-only bounded diagnostic path is missing')
        return operation(b'{}',port=port,deadline=time.monotonic()+seconds)

    def test_rejection_transport_requires_400_and_keeps_normal_post_200_only(self):
        for status in (200,400,500,302):
            reply=f'HTTP/1.1 {status} PUBLIC\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}'.encode()
            if status==400:
                self.assertEqual(self.rejection(self.serve(lambda conn:conn.sendall(reply))),b'{}')
                with self.assertRaises(GateError):self.call(self.serve(lambda conn:conn.sendall(reply)))
            else:
                with self.assertRaises(GateError):self.rejection(self.serve(lambda conn:conn.sendall(reply)))

    def test_rejection_transport_keeps_body_limits_and_total_deadline(self):
        reply=b'HTTP/1.1 400 PUBLIC\r\nContent-Type: application/json\r\nContent-Length: 999999\r\n\r\n'
        with self.assertRaises(GateError):self.rejection(self.serve(lambda conn:conn.sendall(reply)))
        def slow(conn):
            conn.sendall(b'HTTP/1.1 400 PUBLIC\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n')
            for _ in range(50):conn.sendall(b'x');time.sleep(0.02)
        started=time.monotonic()
        with self.assertRaises(GateError):self.rejection(self.serve(slow),seconds=0.15)
        self.assertLess(time.monotonic()-started,0.8)

    def test_inventory_get_is_allowlisted(self):
        def reply(conn):
            conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}')
        self.assertEqual(get_json('/api/version',port=self.serve(reply),deadline=time.monotonic()+1),b'{}')
        with self.assertRaises(GateError):get_json('/api/pull',port=1,deadline=time.monotonic()+1)
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

    def test_chunked_separator_and_final_terminator_are_mandatory(self):
        prefix = b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}'
        for suffix in (b'XX0\r\n\r\n', b'\r\n0\r\n'):
            with self.subTest(suffix=suffix):
                with self.assertRaisesRegex(GateError, '^MODEL_TRANSPORT_FAILED$'):
                    self.call(self.serve(lambda conn: conn.sendall(prefix+suffix)))


if __name__ == '__main__': unittest.main()
