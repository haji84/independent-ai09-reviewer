"""Public smoke admission fails before downloading on unsupported platforms."""
import os
import base64
import importlib.util
import io
import pathlib
import subprocess
import sys
import unittest
from unittest.mock import patch

import data_driver as driver
import context_probe
import runtime_assets as assets
from test_data_driver import batch,response,packet
from test_context_probe import context_error


ROOT=pathlib.Path(__file__).resolve().parents[1]


def guest():
    spec=importlib.util.spec_from_file_location('public_model_guest',ROOT/'tests'/'fixtures'/'model_guest.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def host():
    spec=importlib.util.spec_from_file_location('public_model_host',ROOT/'tools'/'public_model_smoke.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def public_packet():
    encode=lambda raw:base64.b64encode(raw).decode('ascii')
    version=b'{"version":"0.34.0"}'
    tags=driver.encode_json({'models':[{'name':driver.MODEL,'digest':assets.MODEL_SHA}]})
    return {'receipt_b64':encode(packet()),'version_before':encode(version),'version_after':encode(version),
            'tags_before':encode(tags),'tags_after':encode(tags),'started_ns':110,'finished_ns':115,
            'context_rejection':context_probe.record_rejection(batch(),context_probe.public_request(),context_error(),120,140)}


class PublicModelSmokeTest(unittest.TestCase):
    def test_host_requires_negative_evidence_and_checks_it_after_normal_receipt(self):
        module=host();operation=getattr(module,'validate_public_packet',None)
        self.assertTrue(callable(operation),'host context rejection verification is missing')
        verified,count,proof_hash=operation(driver.encode_json(public_packet()),batch(),100,200)
        self.assertEqual(verified.fixed_subject_receipts,0);self.assertEqual(count,6000)
        self.assertTrue(driver.valid_hash(proof_hash))
        value=public_packet();value.pop('context_rejection')
        with self.assertRaises(driver.GateError):operation(driver.encode_json(value),batch(),100,200)

    def test_host_rejects_worker_pass_boolean_wrong_input_and_out_of_order_time(self):
        module=host();operation=getattr(module,'validate_public_packet',None)
        self.assertTrue(callable(operation),'host context rejection verification is missing')
        cases=[True,dict(public_packet()['context_rejection'],input_sha='d'*64),
               dict(public_packet()['context_rejection'],started_ns=114)]
        for changed in cases:
            value=public_packet();value['context_rejection']=changed
            with self.assertRaises(driver.GateError):operation(driver.encode_json(value),batch(),100,200)

    def test_guest_does_not_emit_success_when_context_rejection_is_unverified(self):
        module=guest();output=io.BytesIO()
        with patch.object(module.subprocess,'Popen') as process,\
             patch.object(module,'get_json',return_value=b'{}'),\
             patch.object(module.assets,'validate_inventory'),\
             patch.object(module,'post_json',return_value=response()),\
             patch.object(module,'post_context_rejection',create=True,side_effect=driver.GateError('PRIVATE-CANARY')),\
             patch.object(module.sys,'argv',['guest.py','123','1','a'*40]),\
             patch.object(module.sys,'stdout') as stdout:
            process.return_value.poll.return_value=None;stdout.buffer=output
            module.experiment()
        self.assertEqual(driver.parse_json(output.getvalue()),{'error':'PUBLIC_MODEL_CONTEXT_REJECTION_FAILED'})

    def test_transport_and_schema_errors_use_distinct_fixed_codes_without_raw_text(self):
        module=guest()
        for failure,expected in ((driver.GateError('PRIVATE-CANARY'),'PUBLIC_MODEL_TRANSPORT_FAILED'),
                                 (b'PRIVATE-CANARY','PUBLIC_MODEL_RESPONSE_REJECTED')):
            output=io.BytesIO()
            with patch.object(module.subprocess,'Popen') as process,\
                 patch.object(module,'get_json',return_value=b'{}'),\
                 patch.object(module.assets,'validate_inventory'),\
                 patch.object(module,'post_json',side_effect=failure if isinstance(failure,Exception) else None,
                              return_value=failure if type(failure) is bytes else None),\
                 patch.object(module.sys,'argv',['guest.py','123','1','a'*40]),\
                 patch.object(module.sys,'stdout') as stdout:
                process.return_value.poll.return_value=None
                stdout.buffer=output
                module.experiment()
            self.assertEqual(driver.parse_json(output.getvalue()),{'error':expected})

    def test_missing_runtime_has_only_fixed_diagnostics(self):
        path=pathlib.Path(__file__).resolve().parents[1]/'tools'/'public_model_smoke.py'
        result=subprocess.run([sys.executable,'-I',str(path)],env=dict(os.environ,PATH=''),
                              capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,2)
        self.assertEqual(result.stderr,'')
        self.assertEqual(result.stdout.splitlines(),[
            'PUBLIC_MODEL_ERROR=LINUX_DOCKER_ZSTD_REQUIRED',
            'PUBLIC_MODEL_SMOKE=FAIL; FIXED_SUBJECT_RECEIPTS=0; DESIGN_APPROVAL=HOLD'])


if __name__=='__main__':unittest.main()
