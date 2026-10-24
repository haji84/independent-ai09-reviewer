"""Bounded Ollama JSON body transport on numeric IPv4 loopback only.

No DNS, proxies, redirects, credentials or provider fallback. A monotonic
deadline spans connect, headers and body, including a peer sending slowly.
HTTP metadata is not model provenance; production launch remains blocked.
"""
import http.client
import io
import re
import socket
import time

from data_driver import GateError, MAX_JSON, MAX_RESPONSE, require


class _DeadlineIO(io.RawIOBase):
    def __init__(self, connection, deadline):
        self.connection = connection
        self.deadline = deadline
        self.count = 0

    def readable(self):
        return True

    def readinto(self, buffer):
        remaining = self.deadline - time.monotonic()
        require(remaining > 0, 'MODEL_TRANSPORT_FAILED')
        self.connection.settimeout(remaining)
        count = self.connection.recv_into(buffer)
        self.count += count
        require(self.count <= MAX_RESPONSE + 16_384, 'MODEL_TRANSPORT_FAILED')
        return count


class _HeaderBoundedReader(io.BufferedReader):
    def __init__(self, raw):
        super().__init__(raw)
        self.header_bytes = 0

    def readline(self, size=-1):
        line = super().readline(min(size if size >= 0 else 8193, 8193))
        self.header_bytes += len(line)
        require(self.header_bytes <= 8192, 'MODEL_TRANSPORT_FAILED')
        return line


class _ResponseSocket:
    def __init__(self, connection, deadline):
        self.reader = _HeaderBoundedReader(_DeadlineIO(connection, deadline))

    def makefile(self, *args, **kwargs):
        return self.reader


def _read_chunks(reader):
    # HTTPResponse.read() discards chunk separators without checking their
    # contents and permits EOF in the trailer. Enforce a strict bounded subset:
    # hexadecimal sizes, CRLF separators, zero chunk and final empty line.
    # Extensions/trailers are not part of this Ollama JSON transport contract.
    result = bytearray()
    while True:
        line = reader.readline(8193)
        require(re.fullmatch(b'[0-9a-fA-F]{1,6}\r\n', line), 'MODEL_TRANSPORT_FAILED')
        count = int(line[:-2], 16)
        require(len(result)+count <= MAX_RESPONSE, 'MODEL_TRANSPORT_FAILED')
        if count == 0:
            require(reader.readline(8193) == b'\r\n', 'MODEL_TRANSPORT_FAILED')
            return bytes(result)
        block = reader.read(count)
        require(len(block) == count and reader.read(2) == b'\r\n', 'MODEL_TRANSPORT_FAILED')
        result.extend(block)


def post_json(body, *, deadline, port=11434):
    """Return the exact /api/generate JSON body, never log it.

    The caller passes the same absolute deadline for every item in a batch.
    Alternate ports exist only for public synthetic tests.
    """
    require(type(body) is bytes and len(body) <= MAX_JSON, 'MODEL_TRANSPORT_FAILED')
    require(type(port) is int and 1 <= port <= 65535, 'MODEL_TRANSPORT_FAILED')
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            remaining = deadline - time.monotonic()
            require(remaining > 0, 'MODEL_TRANSPORT_FAILED')
            connection.settimeout(remaining)
            connection.connect(('127.0.0.1', port))
            connection.settimeout(max(0.001, deadline-time.monotonic()))
            connection.sendall(b'POST /api/generate HTTP/1.1\r\nHost: 127.0.0.1\r\n'
                               b'Content-Type: application/json\r\nConnection: close\r\n'
                               b'Content-Length: '+str(len(body)).encode('ascii')+b'\r\n\r\n'+body)
            response_socket = _ResponseSocket(connection, deadline)
            with http.client.HTTPResponse(response_socket) as response:
                response.begin()
                require(response.status == 200, 'MODEL_TRANSPORT_FAILED')
                headers = {}
                for key, value in response.getheaders():
                    key = key.lower()
                    require(key not in headers, 'MODEL_TRANSPORT_FAILED')
                    headers[key] = value
                require(headers.get('content-type','').split(';')[0].strip() == 'application/json',
                        'MODEL_TRANSPORT_FAILED')
                length = headers.get('content-length')
                transfer = headers.get('transfer-encoding')
                require(not (length is not None and transfer is not None), 'MODEL_TRANSPORT_FAILED')
                if length is not None:
                    require(re.fullmatch('[0-9]{1,6}', length) and int(length) <= MAX_RESPONSE,
                            'MODEL_TRANSPORT_FAILED')
                else:
                    require(transfer == 'chunked', 'MODEL_TRANSPORT_FAILED')
                raw = (_read_chunks(response.fp) if transfer == 'chunked'
                       else response.read(MAX_RESPONSE + 1))
                require(len(raw) <= MAX_RESPONSE and
                        (length is None or len(raw) == int(length)), 'MODEL_TRANSPORT_FAILED')
                require(time.monotonic() <= deadline, 'MODEL_TRANSPORT_FAILED')
                return raw
    except (OSError, ValueError, http.client.HTTPException):
        raise GateError('MODEL_TRANSPORT_FAILED') from None
