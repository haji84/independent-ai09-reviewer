"""Generated PUBLIC fixtures; actual bounded child capture and filesystem I/O."""
import base64
import contextlib
import copy
import dataclasses
import importlib.util
import json
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import confidential_capture
import context_probe
import data_driver as driver
import pilot_batch
import public_runner
import runtime_assets as assets
from test_context_probe import context_error
from test_pilot_batch import batch, launch, observation, BASE, SECOND

host = __import__('pilot_host') if importlib.util.find_spec('pilot_host') else None
KEY = bytes(range(32))
PURPOSE = b'CONFIDENTIAL-REVIEW-EVIDENCE'
CANARY = 'PRIVATE-KEY-CANARY-MUST-STAY-HOST-ONLY'


class ExportTest(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(host, 'shared host and verified ciphertext exporter are missing')
        self.temp = tempfile.TemporaryDirectory(prefix='ai09-export-test-')
        self.addCleanup(self.temp.cleanup)
        self.directory = pathlib.Path(self.temp.name)
        self.directory.chmod(0o700)
        self.raw = driver.encode_json(observation())
        self.envelope = pilot_batch.evidence_envelope(
            self.raw, batch(), launch(), BASE, BASE+20*SECOND)

    def verify(self, payload):
        return pilot_batch.verify_evidence(payload, batch(), launch(), BASE, BASE+20*SECOND)

    def export(self, **kwargs):
        return host._export_evidence(kwargs.pop('payload', self.envelope), KEY,
            self.verify, kwargs.pop('directory', self.directory),
            kwargs.pop('deadline', time.monotonic()+30))

    def test_reopened_file_is_ciphertext_and_preserves_the_complete_verified_packet(self):
        result = self.export()
        files = list(self.directory.iterdir())
        self.assertEqual([p.name for p in files], ['ai09-observed-evidence.aesgcm'])
        encrypted = files[0].read_bytes()
        self.assertNotIn(self.raw, encrypted)
        self.assertEqual(result.ciphertext_sha256, driver.digest(encrypted))
        self.assertEqual(result.ciphertext_bytes, len(encrypted))
        self.assertEqual(result.observed_responses, 8)
        self.assertEqual(result.fixed_subject_receipts, 0)
        self.assertEqual(stat.S_IMODE(files[0].stat().st_mode), 0o600)
        self.assertEqual(self.verify(public_runner.unseal(encrypted, KEY, PURPOSE)).payload, self.raw)
        self.assertNotIn(str(self.directory), repr(result))
        with self.assertRaises(dataclasses.FrozenInstanceError): result.observed_responses = 104

    def test_existing_file_symlink_and_hardlink_are_not_overwritten(self):
        target = self.directory/'ai09-observed-evidence.aesgcm'
        original = self.directory/'untouched'
        original.write_bytes(b'UNRELATED-ORIGINAL')
        for kind in ('existing', 'symlink', 'hardlink'):
            if kind == 'existing': target.write_bytes(b'UNRELATED-ORIGINAL')
            elif kind == 'symlink': target.symlink_to(original)
            else: os.link(original, target)
            with self.subTest(kind=kind), self.assertRaises(driver.GateError): self.export()
            self.assertEqual(target.read_bytes(), b'UNRELATED-ORIGINAL')
            self.assertEqual(original.read_bytes(), b'UNRELATED-ORIGINAL')
            target.unlink()

    def test_output_directory_must_be_private_and_no_component_can_be_a_symlink(self):
        self.directory.chmod(0o755)
        with self.assertRaises(driver.GateError): self.export()
        self.directory.chmod(0o700)
        with tempfile.TemporaryDirectory() as sibling:
            alias = pathlib.Path(sibling)/'alias'; alias.symlink_to(self.directory, target_is_directory=True)
            with self.assertRaises(driver.GateError): self.export(directory=alias)
            nested = self.directory/'nested'; nested.mkdir(mode=0o700)
            with self.assertRaises(driver.GateError): self.export(directory=alias/'nested')
        self.assertEqual(list(nested.iterdir()), [])

    def test_partial_writes_are_completed_and_zero_write_never_acknowledges_export(self):
        write = os.write
        with patch.object(host.os, 'write', side_effect=lambda fd, data: write(fd, data[:7])):
            result = self.export()
        self.assertEqual(result.ciphertext_bytes, (self.directory/'ai09-observed-evidence.aesgcm').stat().st_size)
        (self.directory/'ai09-observed-evidence.aesgcm').unlink()
        with patch.object(host.os, 'write', return_value=0):
            with self.assertRaisesRegex(driver.GateError, '^EVIDENCE_EXPORT_FAILED$'): self.export()

    def test_write_and_fsync_failure_leave_no_ready_result_or_raw_exception(self):
        for operation in ('write', 'fsync'):
            with self.subTest(operation=operation), patch.object(host.os, operation, side_effect=OSError(CANARY)):
                with self.assertRaisesRegex(driver.GateError, '^EVIDENCE_EXPORT_FAILED$'): self.export()
            path = self.directory/'ai09-observed-evidence.aesgcm'
            if path.exists():
                self.assertNotIn(self.raw, path.read_bytes()); path.unlink()

    def test_reopen_identity_swap_is_detected_without_deleting_replacement(self):
        real_open = os.open; replaced = []
        target = self.directory/'ai09-observed-evidence.aesgcm'
        def swapping_open(path, flags, *args, **kwargs):
            if path == target.name and not flags & os.O_CREAT:
                target.rename(self.directory/'saved-original-ciphertext')
                target.write_bytes(b'UNRELATED-REPLACEMENT'); target.chmod(0o600); replaced.append(True)
            return real_open(path, flags, *args, **kwargs)
        with patch.object(host.os, 'open', side_effect=swapping_open):
            with self.assertRaises(driver.GateError): self.export()
        self.assertTrue(replaced)
        self.assertEqual(target.read_bytes(), b'UNRELATED-REPLACEMENT')

    def test_new_hardlink_and_directory_entry_swap_are_detected(self):
        real_fsync = os.fsync
        target = self.directory/'ai09-observed-evidence.aesgcm'
        def linked(fd):
            real_fsync(fd)
            if target.exists() and not (self.directory/'alias').exists(): os.link(target, self.directory/'alias')
        with patch.object(host.os, 'fsync', side_effect=linked):
            with self.assertRaises(driver.GateError): self.export()
        target.unlink(); (self.directory/'alias').unlink()
        moved = self.directory.with_name(self.directory.name+'-moved')
        def swapped(fd):
            real_fsync(fd)
            if not moved.exists():
                self.directory.rename(moved); self.directory.mkdir(mode=0o700)
        try:
            with patch.object(host.os, 'fsync', side_effect=swapped):
                with self.assertRaises(driver.GateError): self.export()
            self.assertEqual(list(self.directory.iterdir()), [])
        finally:
            if moved.exists():
                import shutil
                shutil.rmtree(moved)

    def test_ancestor_rename_cannot_acknowledge_ciphertext_at_a_detached_path(self):
        real_fsync = os.fsync
        for level in ('outer', 'middle'):
            with self.subTest(ancestor=level):
                case = self.directory/level; case.mkdir()
                outer = case/'outer'; outer.mkdir()
                middle = outer/'middle'; middle.mkdir()
                destination = middle/'private'; destination.mkdir(mode=0o700)
                ancestor = outer if level == 'outer' else middle
                relative = destination.relative_to(ancestor)
                moved = case/'moved'; scheduled = []
                def rename_ancestor(fd):
                    real_fsync(fd)
                    if not scheduled:
                        ancestor.rename(moved)
                        ancestor.mkdir()
                        (ancestor/'unrelated').write_bytes(b'KEEP-REPLACEMENT')
                        scheduled.append(True)
                with patch.object(host.os, 'fsync', side_effect=rename_ancestor):
                    with self.assertRaisesRegex(driver.GateError, '^EVIDENCE_EXPORT_FAILED$'):
                        self.export(directory=destination)
                self.assertEqual(scheduled, [True])
                self.assertFalse((destination/host.EVIDENCE_FILENAME).exists())
                remaining = (moved/relative/host.EVIDENCE_FILENAME).read_bytes()
                self.assertTrue(remaining.startswith(public_runner.MAGIC))
                self.assertEqual((ancestor/'unrelated').read_bytes(), b'KEEP-REPLACEMENT')

    def test_corrupt_readback_and_authenticated_invalid_envelope_are_rejected(self):
        real_read = os.read
        with patch.object(host.os, 'read', side_effect=lambda fd, count: bytes(len(real_read(fd, count)))):
            with self.assertRaises(driver.GateError): self.export()
        (self.directory/'ai09-observed-evidence.aesgcm').unlink()
        bad = driver.parse_json(self.envelope, driver.MAX_PACKET); bad['host_end'] += SECOND
        real_seal = public_runner.seal
        with patch.object(host.public_runner, 'seal', side_effect=lambda content, key, purpose:
                          real_seal(driver.encode_json(bad), key, purpose)):
            with self.assertRaises(driver.GateError): self.export()
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_expired_or_oversized_export_fails_before_creating_a_file(self):
        with self.assertRaises(driver.GateError): self.export(deadline=time.monotonic()-1)
        with self.assertRaises(driver.GateError): self.export(payload=b'x'*(driver.MAX_PACKET+1))
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_deadline_expiring_during_write_never_returns_ready_metadata(self):
        clock = [100.0]; write = os.write
        def delayed_write(fd, data):
            count = write(fd, data); clock[0] = 111.0; return count
        with patch.object(host.time, 'monotonic', side_effect=lambda: clock[0]), \
             patch.object(host.os, 'write', side_effect=delayed_write):
            with self.assertRaisesRegex(driver.GateError, '^EVIDENCE_EXPORT_FAILED$'):
                self.export(deadline=110.0)
        remaining = (self.directory/'ai09-observed-evidence.aesgcm').read_bytes()
        self.assertTrue(remaining.startswith(public_runner.MAGIC))
        self.assertNotIn(self.raw, remaining)


class FakeRuntime:
    """Replace external downloads/Docker only; staging, capture, crypto and files stay real."""
    def __init__(self):
        self.commands = []; self.mounts = {}; self.present = False; self.stopped = False
        self.bad_stop = False; self.bad_logs = False; self.ambiguous_create = False
        self.bad_cleanup = False; self.input_path = None; self.key_canary = None
        self.image = 'sha256:'+'d'*64
        self.blob = b'PUBLIC-FAKE-MODEL'; self.blob_hash = driver.digest(self.blob)
        self.manifest = b'PUBLIC-FAKE-MANIFEST'
        self.archive = b'PUBLIC-FAKE-RUNTIME'
        self.runtime_dirs = []

    def download(self, url, path, size, digest, deadline):
        payload = self.archive if url == assets.OLLAMA_URL else self.manifest if url == assets.MANIFEST_URL else self.blob
        if len(payload) != size or driver.digest(payload) != digest: raise AssertionError('invalid external fixture pins')
        path.write_bytes(payload); path.chmod(0o444)

    def stage(self, archive, destination, deadline):
        if archive.read_bytes() != self.archive: raise AssertionError('invalid staged runtime')
        destination.mkdir(); self.runtime_dirs.append(destination.parent)
        binary = destination/'bin'/'ollama'; binary.parent.mkdir(); binary.write_bytes(b'PUBLIC-CPU')
        return {'bin/ollama': driver.digest(binary.read_bytes())}

    def command(self, args, **kwargs):
        if kwargs['env'] != {'PATH': os.defpath}: raise AssertionError('host environment escaped')
        if CANARY in repr((args, kwargs)): raise AssertionError('key canary escaped')
        self.commands.append(tuple(args)); op = args[1]
        output = ''
        if op == 'image': output = json.dumps([{'Id': self.image}])
        elif op == 'create':
            self.present = True
            for i, arg in enumerate(args):
                if arg == '--mount':
                    parts = dict(item.split('=', 1) for item in args[i+1].split(',') if '=' in item)
                    self.mounts[parts['target']] = parts['source']
            self.input_path = pathlib.Path(self.mounts['/input/batch.json'])
            if self.ambiguous_create: raise subprocess.TimeoutExpired(args, 15, output=CANARY)
        elif op == 'inspect':
            from test_sandbox_probe import SandboxProbeTest
            info = SandboxProbeTest().fixture(); info['Image'] = self.image; info['Id'] = '1'*64
            info['HostConfig'].update(PidsLimit=128, Memory=4294967296, MemorySwap=4294967296,
                NanoCpus=2000000000, Tmpfs={'/scratch': host.policy.MODEL_TMPFS})
            info['Mounts'] = [{'Type':'bind','Source':v,'Destination':k,'RW':False} for k,v in self.mounts.items()]
            info['State'] = {'Running': not self.stopped or self.bad_stop,
                'Pid':0 if self.stopped and not self.bad_stop else 100,
                'Status':'exited' if self.stopped and not self.bad_stop else 'running'}
            output = json.dumps([info])
        elif op == 'kill': self.stopped = True
        elif op == 'wait': output = '0\n'
        elif op == 'logs': output = CANARY if self.bad_logs else ''
        elif op == 'rm':
            if not self.bad_cleanup: self.present = False
        elif op == 'ps': output = '1'*64+'\n' if self.present else ''
        else: raise AssertionError('unexpected Docker boundary')
        return subprocess.CompletedProcess(args, 0, output, '')

    def capture(self, argv, env, stop, **kwargs):
        if argv[:3] != ['docker','start','--attach'] or env != {'PATH':os.defpath}:
            raise AssertionError('unexpected launch boundary')
        expected = pilot_batch.decode_batch(self.input_path.read_bytes())
        value = observation(); value['context'] = expected.context()
        for record, chunk in zip(value['exchanges'], expected.chunks):
            raw_response = base64.b64decode(record['response_b64'])
            record.update(driver.record_exchange(chunk, driver.build_request(chunk), raw_response))
        value['context_rejection'] = context_probe.record_rejection(expected, context_probe.public_request(),
            context_error(), BASE+18*SECOND, BASE+19*SECOND)
        raw = driver.encode_json(value)
        return confidential_capture.capture([sys.executable, '-I', '-c',
            'import sys;sys.stdout.buffer.write('+repr(raw)+')'], env, stop,
            timeout=min(kwargs['timeout'], 5), max_bytes=kwargs['max_bytes'])

    @contextlib.contextmanager
    def install(self):
        with contextlib.ExitStack() as stack:
            patches = [patch.object(host.shutil, 'which', return_value='/public-fixture/tool'),
                patch.object(host.shutil, 'disk_usage', return_value=type('Disk', (), {'free':9*1024**3})()),
                patch.object(host.assets, 'OLLAMA_SIZE', len(self.archive)),
                patch.object(host.assets, 'OLLAMA_SHA', driver.digest(self.archive)),
                patch.object(host.assets, 'MANIFEST_SIZE', len(self.manifest)),
                patch.object(host.assets, 'MODEL_SHA', driver.digest(self.manifest)),
                patch.object(host.assets, 'download', side_effect=self.download),
                patch.object(host.assets, 'model_blobs', return_value=((self.blob_hash,len(self.blob)),)),
                patch.object(host.assets, 'stage_cpu', side_effect=self.stage),
                patch.object(host.subprocess, 'run', side_effect=self.command),
                patch.object(host, 'capture', side_effect=self.capture),
                patch.object(host.time, 'time_ns', side_effect=[BASE, BASE+20*SECOND]),
                patch.dict(os.environ, {'AI09_BUNDLE_KEY_B64':CANARY})]
            for item in patches: stack.enter_context(item)
            yield self


@unittest.skipUnless(sys.platform == 'linux', 'Linux host path; mandatory Linux CI')
class HostLifecycleTest(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(host, 'shared host and verified ciphertext exporter are missing')
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.output = pathlib.Path(self.temp.name); self.output.chmod(0o700)

    def run_public(self, prepared):
        return host.run_public_pilot(prepared, run_id='123', attempt=1, commit='a'*40,
                                     output_directory=self.output)

    def test_cleanup_metadata_is_live_nonconsuming_and_uses_the_actual_container_name(self):
        info_function = getattr(host, 'prepared_cleanup_info', None)
        self.assertTrue(callable(info_function), 'prepared cleanup metadata is missing')
        fake = FakeRuntime()
        with fake.install(), host.prepare_runtime() as prepared:
            info = info_function(prepared)
            self.assertRegex(info.container_name, r'^ai09-model-[0-9a-f]{32}$')
            self.assertEqual(info.cleanup_deadline-info.work_deadline, 60)
            self.assertEqual(repr(info), 'CleanupInfo()')
            with self.assertRaises(dataclasses.FrozenInstanceError): info.container_name = 'forged'
            self.assertEqual(info_function(prepared), info)
            with patch.object(host.time, 'monotonic', return_value=info.work_deadline+1):
                with self.assertRaises(driver.GateError): info_function(prepared)
            self.run_public(prepared)
            created = next(command for command in fake.commands if command[1]=='create')
            self.assertEqual(created[created.index('--name')+1], info.container_name)
            self.assertIn(('docker','rm','--force',info.container_name), fake.commands)
            with self.assertRaises(driver.GateError): info_function(prepared)
        for token in (prepared, None, object(), host._PreparedRuntime()):
            with self.assertRaises(driver.GateError): info_function(token)

    def test_result_exposes_actual_host_epoch_observations_without_sensitive_repr(self):
        fake = FakeRuntime()
        with fake.install(), host.prepare_runtime() as prepared:
            result = self.run_public(prepared)
        self.assertEqual(getattr(result,'host_start_ns',None), BASE)
        self.assertEqual(getattr(result,'host_end_ns',None), BASE+20*SECOND)
        self.assertEqual(repr(result), 'PilotResult()')

    def test_prepare_then_single_use_execution_exports_only_after_positive_stop(self):
        fake = FakeRuntime()
        with fake.install(), host.prepare_runtime() as prepared:
            self.assertFalse(any(c[1]=='create' for c in fake.commands))
            result = self.run_public(prepared)
            self.assertEqual(result.observed_responses, 8); self.assertEqual(result.fixed_subject_receipts, 0)
            self.assertTrue(fake.stopped); self.assertFalse(fake.present)
            self.assertNotIn(CANARY, repr(result)); self.assertNotIn(str(self.output), repr(result))
            with self.assertRaisesRegex(driver.GateError, '^PREPARED_RUNTIME_UNAVAILABLE$'): self.run_public(prepared)
        self.assertTrue(all(not p.exists() for p in fake.runtime_dirs))
        self.assertFalse(fake.input_path.exists())
        self.assertEqual(len(list(self.output.iterdir())), 1)

    def test_missing_forged_expired_or_closed_runtime_cannot_start_a_container(self):
        fake = FakeRuntime()
        with fake.install():
            for value in (None, object()):
                with self.assertRaises(driver.GateError): self.run_public(value)
            with host.prepare_runtime() as prepared:
                with patch.object(host.time, 'monotonic', return_value=time.monotonic()+601):
                    with self.assertRaises(driver.GateError): self.run_public(prepared)
            with self.assertRaises(driver.GateError): self.run_public(prepared)
        self.assertFalse(any(c[1]=='create' for c in fake.commands))
        self.assertEqual(list(self.output.iterdir()), [])

    def test_unverified_stop_or_log_failure_prevents_any_ciphertext_export(self):
        for failure in ('bad_stop', 'bad_logs'):
            fake = FakeRuntime(); setattr(fake, failure, True)
            with self.subTest(failure=failure), fake.install(), host.prepare_runtime() as prepared:
                with self.assertRaises(driver.GateError) as error: self.run_public(prepared)
                self.assertNotIn(CANARY, str(error.exception))
            self.assertFalse(fake.present); self.assertEqual(list(self.output.iterdir()), [])

    def test_ambiguous_create_is_cleaned_by_unique_name_and_cleanup_failure_wins(self):
        for fail_cleanup in (False, True):
            fake = FakeRuntime(); fake.ambiguous_create = True; fake.bad_cleanup = fail_cleanup
            with self.subTest(cleanup=fail_cleanup), fake.install(), host.prepare_runtime() as prepared:
                with self.assertRaises(driver.GateError) as error: self.run_public(prepared)
                self.assertEqual(str(error.exception), 'HOST_CLEANUP_UNVERIFIED' if fail_cleanup else 'HOST_OPERATION_FAILED')
            self.assertEqual(fake.present, fail_cleanup)
            self.assertTrue(any(c[1]=='rm' for c in fake.commands))
            self.assertEqual(list(self.output.iterdir()), [])

    def test_runtime_tampering_after_preparation_fails_before_create(self):
        fake = FakeRuntime()
        with fake.install(), host.prepare_runtime() as prepared:
            (fake.runtime_dirs[0]/'runtime/bin/ollama').write_bytes(b'CHANGED')
            with self.assertRaises(driver.GateError): self.run_public(prepared)
        self.assertFalse(any(c[1]=='create' for c in fake.commands))

    def test_frozen_entry_rejects_unpinned_original_before_staging_or_inference(self):
        fake = FakeRuntime()
        with fake.install(), host.prepare_runtime() as prepared:
            with self.assertRaisesRegex(driver.GateError, '^FROZEN_SOURCE_HASH_MISMATCH$'):
                host.run_frozen_pilot(prepared, b'PUBLIC-UNPINNED', b'PUBLIC-UNPINNED-PLAN', KEY,
                    run_id='123', attempt=1, commit='a'*40, output_directory=self.output)
        self.assertFalse(any(c[1]=='create' for c in fake.commands)); self.assertEqual(list(self.output.iterdir()), [])

    def test_generated_frozen_input_uses_separate_key_and_stages_only_first_eight(self):
        import frozen_plan
        import source_archive
        from test_frozen_plan import fixture, encode
        archive, plan, _ = fixture(); plan_raw = encode(plan)
        key = b'PUBLIC-HOST-ONLY-KEY-CANARY-000!'
        self.assertEqual(len(key), 32)
        fake = FakeRuntime()
        with fake.install(), host.prepare_runtime() as prepared:
            # Pins are substituted only for public generated test data, after preparation.
            with patch.object(source_archive, 'FROZEN_SHA', driver.digest(archive)), \
                 patch.object(frozen_plan, 'FROZEN_PLAN_SHA', driver.digest(plan_raw)):
                result = host.run_frozen_pilot(prepared, archive, plan_raw, key, run_id='123',
                    attempt=1, commit='a'*40, output_directory=self.output)
        encrypted = (self.output/'ai09-observed-evidence.aesgcm').read_bytes()
        payload = driver.parse_json(public_runner.unseal(encrypted, key, PURPOSE), driver.MAX_PACKET)
        self.assertEqual(payload['schema'], 'AI09-FROZEN-OBSERVED-EVIDENCE-v1')
        self.assertEqual(payload['launch']['input_class'], 'FROZEN_DATA_ONLY')
        self.assertEqual(payload['context']['source_sha'], driver.digest(archive))
        self.assertEqual(payload['context']['plan_sha'], driver.digest(plan_raw))
        packet = driver.parse_json(base64.b64decode(payload['packet_b64']), driver.MAX_PACKET)
        self.assertEqual([x['chunk_id'] for x in packet['exchanges']], [f'{n:03}' for n in range(8)])
        self.assertEqual(result.observed_responses, 8); self.assertEqual(result.fixed_subject_receipts, 0)
        self.assertNotIn(key.decode(), repr(fake.commands))
        self.assertEqual(set(fake.mounts), {'/opt/runtime','/models','/guest.py','/code/data_driver.py',
            '/code/loopback_client.py','/code/runtime_assets.py','/code/context_probe.py',
            '/code/pilot_batch.py','/input/batch.json'})
        with self.assertRaises(Exception): public_runner.unseal(encrypted, KEY, PURPOSE)

    def test_preparation_time_is_not_reset_for_capture(self):
        fake = FakeRuntime(); capture_call = fake.capture; timeouts = []
        def bounded_capture(*args, **kwargs):
            timeouts.append(kwargs['timeout'])
            return capture_call(*args, **kwargs)
        fake.capture = bounded_capture
        clock = [100.0]
        with fake.install(), patch.object(host.time, 'monotonic', side_effect=lambda: clock[0]):
            with host.prepare_runtime() as prepared:
                clock[0] = 639.0
                self.run_public(prepared)
        self.assertEqual(timeouts, [1.0])


if __name__ == '__main__': unittest.main()
