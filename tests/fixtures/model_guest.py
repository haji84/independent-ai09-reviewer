"""PUBLIC normal/context-limit cases, real Ollama; no private source or plan."""
import base64
import os
import subprocess
import sys
import time

sys.path.insert(0,'/code')
import data_driver as driver
from loopback_client import get_json,post_json,post_context_rejection
import runtime_assets as assets
import context_probe


def encode(raw):return base64.b64encode(raw).decode('ascii')


def experiment():
    error_code='PUBLIC_MODEL_STARTUP_FAILED'
    try:
        deadline=time.monotonic()+450
        environment={'PATH':'/usr/local/bin:/usr/bin:/bin','HOME':'/scratch','TMPDIR':'/scratch',
                     'LD_LIBRARY_PATH':'/opt/runtime/lib/ollama','OLLAMA_MODELS':'/models',
                     'OLLAMA_HOST':'127.0.0.1:11434','OLLAMA_NUM_PARALLEL':'1',
                     'OLLAMA_MAX_LOADED_MODELS':'1','OLLAMA_CONTEXT_LENGTH':'4096',
                     'OLLAMA_NO_CLOUD':'1','OLLAMA_LOAD_TIMEOUT':'120s'}
        server=subprocess.Popen(['/opt/runtime/bin/ollama','serve'],env=environment,
                                stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        ready_deadline=time.monotonic()+30
        while True:
            if server.poll() is not None:raise driver.GateError(error_code)
            try:
                version_before=get_json('/api/version',deadline=min(deadline,time.monotonic()+1))
                break
            except driver.GateError:
                if time.monotonic()>=ready_deadline:raise
                time.sleep(0.1)
        error_code='PUBLIC_MODEL_INVENTORY_MISMATCH'
        tags_before=get_json('/api/tags',deadline=deadline)
        assets.validate_inventory(version_before,tags_before)
        chunk=driver.Chunk('000','PUBLIC.py',1,b'def add(a, b):\n    return a + b\n')
        expected=driver.Batch(sys.argv[1],int(sys.argv[2]),sys.argv[3],
                              driver.digest(b'PUBLIC-TOY-SOURCE'),driver.digest(b'PUBLIC-TOY-NO-PLAN'),(chunk,))
        request=driver.build_request(chunk)
        error_code='PUBLIC_MODEL_TRANSPORT_FAILED'
        started=time.time_ns()
        response=post_json(request,deadline=deadline)
        finished=time.time_ns()
        error_code='PUBLIC_MODEL_RESPONSE_REJECTED'
        record=driver.record_exchange(chunk,request,response)
        error_code='PUBLIC_MODEL_CONTEXT_REJECTION_FAILED'
        rejection_request=context_probe.public_request()
        rejection_started=time.time_ns()
        rejection_response=post_context_rejection(rejection_request,deadline=deadline)
        rejection_finished=time.time_ns()
        rejection=context_probe.record_rejection(expected,rejection_request,rejection_response,
                                                  rejection_started,rejection_finished)
        error_code='PUBLIC_MODEL_INVENTORY_MISMATCH'
        version_after=get_json('/api/version',deadline=deadline)
        tags_after=get_json('/api/tags',deadline=deadline)
        assets.validate_inventory(version_after,tags_after)
        packet={'receipt_b64':encode(driver.make_packet(expected,[record])),
                'version_before':encode(version_before),'tags_before':encode(tags_before),
                'version_after':encode(version_after),'tags_after':encode(tags_after),
                'started_ns':started,'finished_ns':finished,'context_rejection':rejection}
    except BaseException:
        packet={'error':error_code}  # fixed control codes; never exception/model text
    sys.stdout.buffer.write(driver.encode_json(packet))
    sys.stdout.buffer.flush()
    # PID1 exit plus host stop/wait/inspect certifies all server descendants stop.


if __name__=='__main__':experiment()
