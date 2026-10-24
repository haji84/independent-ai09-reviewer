"""PUBLIC fake Ollama. Never accepts a private plan or actual source archive."""
import http.server
import os
import sys
import threading
import time

# Reviewed public code is mounted separately, never loaded from input data.
sys.path.insert(0, '/code')
import data_driver as driver
from loopback_client import post_json

mode = sys.argv[1]


class FakeOllama(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        assert self.path == '/api/generate'
        length = int(self.headers['Content-Length'])
        assert 0 < length <= driver.MAX_JSON
        request = driver.parse_json(self.rfile.read(length))
        prompt_data = driver.parse_json(request['prompt'].split('\n', 1)[1].encode('ascii'))
        result = driver.encode_json({
            'model':driver.MODEL, 'created_at':'2026-10-25T00:00:00Z',
            'response':driver.encode_json({'chunk_id':prompt_data['chunk_id'],
                                           'findings':[]}).decode('ascii'),
            'done':True, 'done_reason':'stop', 'total_duration':100,
            'load_duration':1, 'prompt_eval_count':2, 'prompt_eval_duration':10,
            'eval_count':3, 'eval_duration':20})
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(result)))
        self.end_headers()
        self.wfile.write(result)


chunks = tuple(driver.Chunk(f'{index:03}', 'PUBLIC.py', 1,
                            f'# PUBLIC-SYNTHETIC-{index}\n'.encode('ascii'))
               for index in range(8))
batch = driver.Batch('123', 1, 'a'*40, driver.digest(b'PUBLIC-ARCHIVE'),
                     driver.digest(b'PUBLIC-PLAN'), chunks)
server = http.server.HTTPServer(('127.0.0.1', 11434), FakeOllama)
threading.Thread(target=server.serve_forever, daemon=True).start()
deadline = time.monotonic()+15
records = []
for chunk in chunks:
    request = driver.build_request(chunk)
    response = post_json(request, deadline=deadline)
    records.append(driver.record_exchange(chunk, request, response))
packet = driver.make_packet(batch, records)
if mode == 'tamper':
    value = driver.parse_json(packet, driver.MAX_PACKET)
    value['context']['attempt'] = 2
    packet = driver.encode_json(value)
elif mode == 'oversize':
    packet = b'PUBLIC-SYNTHETIC-'*150000
elif mode == 'trailing':
    packet += b'\n{}'

# The escaped child keeps stdout open and ignores normal process-group cleanup.
# Only the host-owned Docker kill/inspect boundary can certify its termination.
if mode == 'escaped':
    if os.fork() == 0:
        os.setsid()
        time.sleep(30)
        os._exit(0)

os.write(2, b'::warning::PUBLIC-SYNTHETIC-STDERR-MUST-NOT-BE-LOGGED\n')
sys.stdout.buffer.write(packet)
sys.stdout.buffer.flush()
if mode == 'escaped':
    time.sleep(30)
