"""PUBLIC-only owner boundary tests; generated metadata is not GitHub provenance."""
import base64
import contextlib
import copy
import dataclasses
import importlib.util
import io
import json
import os
import pathlib
import tempfile
import unittest
from unittest.mock import patch

import data_driver as driver
import frozen_plan
import pilot_host
import public_runner
import sealed_input
import source_archive
from fixtures.private_pilot_child import KEY, public_inputs
from test_private_pilot import private, public_connection

owner = __import__('tools.owner_bundle', fromlist=['owner_bundle']) if importlib.util.find_spec('tools.owner_bundle') else None
COMMIT = 'a' * 40
REPOSITORY = 'haji84/independent-ai09-reviewer'
WORKFLOW = '.github/workflows/ai09-public-safe-pilot.yml'
STAMP = '2026-10-29T02:26:56.9496507Z '
PREFIX = 'AI09_HOST_OBSERVATION='
PUBLIC_CANARY = 'PUBLIC-OWNER-ERROR-CANARY'
_CAPTURED = None


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(',', ':'), allow_nan=False).encode('ascii')


def metadata():
    # Independently supplied approved run/job identity, never read from evidence.
    return ({'id': 123, 'run_attempt': 1, 'path': WORKFLOW,
             'repository': {'full_name': REPOSITORY}, 'event': 'workflow_dispatch',
             'head_branch': 'main', 'head_sha': COMMIT,
             'status': 'completed', 'conclusion': 'success'},
            {'id': 456, 'run_id': 123, 'run_attempt': 1, 'head_sha': COMMIT,
             'head_branch': 'main', 'status': 'completed', 'conclusion': 'success',
             'name': 'isolated-pilot'})


def observation():
    return {'schema': 'AI09-HOST-OBSERVATION-v1', 'repository': REPOSITORY,
            'run_id': '123', 'attempt': 1, 'commit': COMMIT,
            'input_class': 'FROZEN_DATA_ONLY', 'input_ciphertext_sha256': 'b' * 64,
            'input_ciphertext_bytes': 1000, 'output_ciphertext_sha256': 'c' * 64,
            'output_ciphertext_bytes': 2000, 'launch_sha256': 'd' * 64,
            'host_start_ns': 1_793_238_416_000_000_000,
            'host_end_ns': 1_793_238_417_000_000_000, 'observed_responses': 8}


def log_for(value):
    raw = canonical(value).decode('ascii')
    return ('\ufeff' + STAMP + 'runner setup\n' + STAMP +
            'echo "' + PREFIX + raw + '"\n' + STAMP + PREFIX + raw + '\n').encode('utf-8')


def approved():
    return {'approved_run_id': '123', 'approved_attempt': 1, 'approved_commit': COMMIT,
            'approved_input_sha256': 'b' * 64, 'approved_input_bytes': 1000,
            'approved_job_id': 456}


def context_document(value, log):
    return {'schema': 'AI09-EXPECTED-HOST-CONTEXT-v1', 'repository': REPOSITORY,
            'workflow_path': WORKFLOW, 'run_id': '123', 'attempt': 1,
            'head_sha': COMMIT, 'run_event': 'workflow_dispatch', 'head_branch': 'main',
            'run_conclusion': 'success', 'job_id': 456, 'job_name': 'isolated-pilot',
            'job_conclusion': 'success', 'log_sha256': driver.digest(log),
            'observation_sha256': driver.digest(canonical(value)), 'observation': value}


@contextlib.contextmanager
def fixture_pins(archive, plan):
    # Match the child's independently known PUBLIC external-asset fixtures.
    # Do not derive either expected pin from the authenticated envelope.
    with patch.object(source_archive, 'FROZEN_SHA', driver.digest(archive)), \
         patch.object(frozen_plan, 'FROZEN_PLAN_SHA', driver.digest(plan)), \
         patch.object(pilot_host.assets, 'OLLAMA_SHA', driver.digest(b'PUBLIC-FAKE-RUNTIME')), \
         patch.object(pilot_host.assets, 'MODEL_SHA', driver.digest(b'PUBLIC-FAKE-MANIFEST')):
        yield


def captured_evidence():
    global _CAPTURED
    if _CAPTURED is None:
        with public_connection() as fixture:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                if private.main([]) != 0:
                    raise AssertionError('PUBLIC coordinator fixture failed')
            line = output.getvalue()
            if not line.startswith(PREFIX) or line.count('\n') != 1:
                raise AssertionError('not a single actual coordinator observation')
            log = ('\ufeff' + STAMP + line).encode('utf-8')
            run, job = metadata()
            context = owner.build_expected_context(run, job, log,
                approved_run_id='123', approved_attempt=1, approved_commit=COMMIT,
                approved_input_sha256=driver.digest(fixture['cipher']),
                approved_input_bytes=len(fixture['cipher']), approved_job_id=456)
            path = fixture['root'] / 'runner/ai09-private-pilot-123-1' / pilot_host.EVIDENCE_FILENAME
            # Retain bytes while the real temporary output still exists.
            _CAPTURED = (fixture['archive'], fixture['plan'], path.read_bytes(), context)
    return _CAPTURED


class OwnerBundleTest(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(owner, 'owner context/codec boundary is missing')

    def rejected(self, operation, *args, code=None, **kwargs):
        with self.assertRaises(driver.GateError) as caught:
            operation(*args, **kwargs)
        if code is not None:
            self.assertEqual(str(caught.exception), code)
        self.assertIsNone(caught.exception.__cause__)
        self.assertTrue(caught.exception.__suppress_context__)

    def cli(self, args):
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            code = owner.main(args)
        self.assertEqual(errors.getvalue(), '')
        self.assertNotIn(PUBLIC_CANARY, output.getvalue())
        self.assertNotIn(base64.b64encode(KEY).decode('ascii'), output.getvalue())
        return code, output.getvalue()

    def test_exact_context_keeps_numeric_api_identity_and_exact_bom_log_hash(self):
        value = observation(); log = log_for(value); run, job = metadata()
        actual = owner.build_expected_context(run, job, log, **approved())
        self.assertEqual(actual, canonical(context_document(value, log)))
        decoded = json.loads(actual)
        self.assertEqual(len(decoded), 15)
        self.assertEqual(decoded['run_id'], '123')
        self.assertNotEqual(decoded['log_sha256'], driver.digest(log[3:]))
        self.assertNotIn('runner setup', actual.decode())

    def test_metadata_run_attempt_job_and_fixed_workflow_substitutions_reject(self):
        mutations = {'run': [('id', 124), ('id', '123'), ('id', True), ('run_attempt', 2),
                    ('run_attempt', True), ('path', 'other.yml'), ('event', 'push'),
                    ('head_branch', 'feature'), ('head_sha', 'b' * 40),
                    ('status', 'in_progress'), ('conclusion', 'failure'),
                    ('repository', {'full_name': 'other/repo'})],
                     'job': [('id', 457), ('id', True), ('run_id', 124), ('run_id', '123'),
                    ('run_attempt', 2), ('run_attempt', True), ('head_sha', 'b' * 40),
                    ('head_branch', 'feature'), ('name', 'different-job'),
                    ('status', 'in_progress'), ('conclusion', 'failure')]}
        for kind, changes in mutations.items():
            for field, replacement in changes:
                run, job = metadata(); (run if kind == 'run' else job)[field] = replacement
                with self.subTest(kind=kind, field=field, value=replacement):
                    self.rejected(owner.build_expected_context, run, job, log_for(observation()),
                                  code='OWNER_CONTEXT_REJECTED', **approved())

    def test_approved_values_and_observation_identities_use_strict_types(self):
        changes = [('approved_run_id', 123), ('approved_run_id', '0123'),
                   ('approved_run_id', '1\n'), ('approved_run_id', '1' * 21),
                   ('approved_attempt', True), ('approved_attempt', 2),
                   ('approved_commit', 'A' * 40), ('approved_input_sha256', 'B' * 64),
                   ('approved_input_bytes', True), ('approved_input_bytes', 0),
                   ('approved_input_bytes', 2_000_039), ('approved_job_id', True),
                   ('approved_job_id', '456'), ('approved_job_id', 0)]
        run, job = metadata()
        for field, replacement in changes:
            arguments = approved(); arguments[field] = replacement
            with self.subTest(field=field, value=replacement):
                self.rejected(owner.build_expected_context, run, job, log_for(observation()),
                              code='OWNER_CONTEXT_REJECTED', **arguments)
        for field, replacement in [('run_id', '124'), ('attempt', 2), ('commit', 'b' * 40),
                    ('input_ciphertext_sha256', '0' * 64), ('input_ciphertext_bytes', 1001),
                    ('observed_responses', True), ('host_start_ns', True)]:
            value = observation(); value[field] = replacement
            with self.subTest(observation_field=field):
                self.rejected(owner.build_expected_context, run, job, log_for(value),
                              code='OWNER_CONTEXT_REJECTED', **approved())

    def test_only_one_whole_canonical_timestamped_observation_is_accepted(self):
        run, job = metadata(); raw = canonical(observation()).decode('ascii')
        line = STAMP + PREFIX + raw + '\n'
        invalid = ['', STAMP + 'echo "' + PREFIX + raw + '"\n', line + line,
                   PREFIX + raw + '\n', 'not-a-timestamp ' + PREFIX + raw + '\n',
                   line + STAMP + PREFIX + '{broken}\n', STAMP + PREFIX + ' ' + raw + '\n',
                   STAMP + PREFIX + raw[:-1] + ',"extra":1}\n',
                   STAMP + PREFIX + raw[:-1] + ',"attempt":1}\n',
                   STAMP + PREFIX + 'x' * 2049 + '\n',
                   STAMP + PREFIX + raw + ' trailing\n', STAMP + ' ' + PREFIX + raw + '\n',
                   '2026-99-29T02:26:56.9496507Z ' + PREFIX + raw + '\n',
                   line + ' ' + line, line + '\t' + PREFIX + raw + '\n']
        for index, log in enumerate(invalid):
            with self.subTest(case=index):
                self.rejected(owner.build_expected_context, run, job, log.encode(),
                              code='OWNER_CONTEXT_REJECTED', **approved())
        self.rejected(owner.build_expected_context, run, job, b'\xff' + line.encode(),
                      code='OWNER_CONTEXT_REJECTED', **approved())

    def test_context_hash_canonical_schema_and_redundant_commitments_precede_decryption(self):
        value = observation(); document = context_document(value, log_for(value))
        changes = [('schema', 'other'), ('repository', 'other/repo'), ('workflow_path', 'other'),
                   ('run_id', 123), ('run_id', '124'), ('attempt', True), ('head_sha', 'b' * 40),
                   ('run_event', 'push'), ('head_branch', 'feature'), ('run_conclusion', 'failure'),
                   ('job_id', True), ('job_name', 'other'), ('job_conclusion', 'failure'),
                   ('log_sha256', 'A' * 64), ('observation_sha256', '0' * 64), ('extra', 1)]
        values = [b'', canonical(document) + b'\n', b'x' * 16_385]
        for field, replacement in changes:
            changed = copy.deepcopy(document); changed[field] = replacement
            values.append(canonical(changed))
        changed = copy.deepcopy(document); del changed['log_sha256']; values.append(canonical(changed))
        reached = []
        def decrypt(*args):
            reached.append(True); raise AssertionError('invalid context reached decryption')
        with patch.object(public_runner, 'unseal', decrypt):
            for raw in values:
                self.rejected(owner.verify_evidence_bytes, b'', b'', b'', b'', raw,
                              driver.digest(raw), code='OWNER_CONTEXT_REJECTED')
            self.rejected(owner.verify_evidence_bytes, b'', b'', b'', b'', canonical(document),
                          '0' * 64, code='OWNER_CONTEXT_REJECTED')
        self.assertEqual(reached, [])

    def test_real_coordinator_observation_verifies_evidence_with_repr_safe_result(self):
        archive, plan, cipher, context = captured_evidence()
        with fixture_pins(archive, plan):
            result = owner.verify_evidence_bytes(archive, plan, KEY, cipher, context, driver.digest(context))
        self.assertEqual((result.observed_responses, result.fixed_subject_receipts), (8, 0))
        self.assertEqual((result.ciphertext_sha256, result.ciphertext_bytes), (driver.digest(cipher), len(cipher)))
        self.assertEqual(repr(result), 'VerifiedEvidence()')
        self.assertFalse(hasattr(result, '__dict__'))
        for name in ('payload', 'key', 'archive_raw', 'plan_raw', 'launch'):
            self.assertFalse(hasattr(result, name))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.observed_responses = 104

    def test_reencrypted_changed_launch_time_or_identity_cannot_supply_own_expectations(self):
        archive, plan, cipher, context = captured_evidence()
        original = json.loads(public_runner.unseal(cipher, KEY, pilot_host.PURPOSE))
        for kind in ('launch', 'host_start', 'host_end', 'run_id', 'attempt', 'commit'):
            payload = copy.deepcopy(original)
            if kind == 'launch': payload['launch']['container_id'] = 'f' * 64
            elif kind in ('host_start', 'host_end'): payload[kind] += 1
            else: payload['context'][kind] = {'run_id': '124', 'attempt': 2, 'commit': 'b' * 40}[kind]
            changed = public_runner.seal(canonical(payload), KEY, pilot_host.PURPOSE)
            # Change only external output identity to reach the launch/time/identity check.
            expected = json.loads(context)
            expected['observation']['output_ciphertext_sha256'] = driver.digest(changed)
            expected['observation']['output_ciphertext_bytes'] = len(changed)
            expected['observation_sha256'] = driver.digest(canonical(expected['observation']))
            raw = canonical(expected)
            with self.subTest(change=kind), fixture_pins(archive, plan):
                self.rejected(owner.verify_evidence_bytes, archive, plan, KEY, changed, raw,
                              driver.digest(raw), code='OWNER_EVIDENCE_REJECTED')

    def test_ciphertext_authentication_identity_and_fresh_original_inputs_are_required(self):
        archive, plan, cipher, context = captured_evidence()
        for changed_archive, changed_plan, key, encrypted in (
                (archive + b'x', plan, KEY, cipher), (archive, plan + b'x', KEY, cipher),
                (archive, plan, b'x' * 32, cipher), (archive, plan, bytearray(KEY), cipher),
                (archive, plan, KEY, cipher[:-1]), (archive, plan, KEY, cipher + b'x')):
            with fixture_pins(archive, plan):
                self.rejected(owner.verify_evidence_bytes, changed_archive, changed_plan, key,
                              encrypted, context, driver.digest(context), code='OWNER_EVIDENCE_REJECTED')

    def test_verify_cli_refuses_stale_context_before_key_adapter(self):
        raw = canonical(context_document(observation(), log_for(observation())))
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp); path = root / 'context.json'; path.write_bytes(raw + b' ')
            reached = []
            def forbidden(*args): reached.append(True); raise AssertionError(PUBLIC_CANARY)
            with patch.object(owner, '_load_owner_key', forbidden):
                code, output = self.cli(['verify-evidence', '--archive', str(root / 'missing.zip'),
                    '--plan', str(root / 'missing.json'), '--dpapi-key-file', str(root / PUBLIC_CANARY),
                    '--evidence', str(root / 'missing.aesgcm'), '--expected-context', str(path),
                    '--expected-context-sha256', driver.digest(raw)])
            self.assertEqual(reached, []); self.assertEqual(code, 2)
            self.assertEqual(output, 'OWNER_BUNDLE_ERROR=OWNER_CONTEXT_REJECTED\n')

    def test_verify_cli_with_public_fake_adapter_emits_only_public_verification_metadata(self):
        archive, plan, cipher, context = captured_evidence()
        with tempfile.TemporaryDirectory() as temp, fixture_pins(archive, plan):
            root = pathlib.Path(temp)
            for name, raw in (('source.zip', archive), ('plan.json', plan),
                              ('evidence.aesgcm', cipher), ('context.json', context)):
                (root / name).write_bytes(raw)
            with patch.object(owner, '_load_owner_key', return_value=KEY):
                code, output = self.cli(['verify-evidence', '--archive', str(root / 'source.zip'),
                    '--plan', str(root / 'plan.json'), '--dpapi-key-file', str(root / 'PUBLIC-FAKE-DPAPI'),
                    '--evidence', str(root / 'evidence.aesgcm'), '--expected-context', str(root / 'context.json'),
                    '--expected-context-sha256', driver.digest(context)])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output), {'ciphertext_sha256': driver.digest(cipher),
                'ciphertext_bytes': len(cipher), 'observed_responses': 8, 'fixed_subject_receipts': 0})
            self.assertEqual(len(list(root.iterdir())), 4)

    def test_linked_or_replaced_context_is_refused_before_key_adapter(self):
        raw = canonical(context_document(observation(), log_for(observation())))
        real_read = os.read
        for kind in ('symlink', 'hardlink', 'file-replaced', 'ancestor-replaced'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temp:
                root = pathlib.Path(temp); parent = root / 'input'; parent.mkdir()
                original = parent / 'original'; original.write_bytes(raw); path = parent / 'context.json'
                if kind == 'symlink': path.symlink_to(original)
                elif kind == 'hardlink': os.link(original, path)
                else: path.write_bytes(raw)
                replaced = []; key_reads = []
                def read(fd, count):
                    block = real_read(fd, count)
                    if not replaced and kind in ('file-replaced', 'ancestor-replaced'):
                        if kind == 'file-replaced': path.rename(parent / 'old'); path.write_bytes(raw)
                        else: parent.rename(root / 'old-parent'); parent.mkdir(); path.write_bytes(raw)
                        replaced.append(True)
                    return block
                def key(*args): key_reads.append(True); raise AssertionError(PUBLIC_CANARY)
                with patch.object(owner.os, 'read', read), patch.object(owner, '_load_owner_key', key):
                    code, output = self.cli(['verify-evidence', '--archive', 'unused', '--plan', 'unused',
                        '--dpapi-key-file', 'unused', '--evidence', 'unused', '--expected-context', str(path),
                        '--expected-context-sha256', driver.digest(raw)])
                self.assertEqual(code, 2); self.assertEqual(key_reads, [])
                self.assertEqual(output, 'OWNER_BUNDLE_ERROR=OWNER_CONTEXT_REJECTED\n')

    def test_seal_cli_authenticates_actual_output_and_preserves_original_bytes(self):
        archive, plan = public_inputs()
        with tempfile.TemporaryDirectory() as temp, fixture_pins(archive, plan):
            root = pathlib.Path(temp); (root / 'source.zip').write_bytes(archive); (root / 'plan.json').write_bytes(plan)
            output = root / 'sealed.aesgcm'
            args = ['seal-input', '--archive', str(root / 'source.zip'), '--plan', str(root / 'plan.json'),
                    '--dpapi-key-file', str(root / 'PUBLIC-FAKE-DPAPI'), '--output', str(output)]
            with patch.object(owner, '_load_owner_key', return_value=KEY):
                code, text = self.cli(args)
                self.assertEqual(code, 0); encrypted = output.read_bytes()
                self.assertEqual(json.loads(text), {'ciphertext_sha256': driver.digest(encrypted),
                                                   'ciphertext_bytes': len(encrypted)})
                opened = sealed_input.open_frozen_input(encrypted, KEY)
                self.assertEqual((opened.archive_raw, opened.plan_raw), (archive, plan))
                self.assertEqual(self.cli(args)[0], 2)
                self.assertEqual(output.read_bytes(), encrypted)
            self.assertEqual((root / 'source.zip').read_bytes(), archive)
            self.assertEqual((root / 'plan.json').read_bytes(), plan)
            self.assertEqual({path.name for path in root.iterdir()}, {'source.zip', 'plan.json', 'sealed.aesgcm'})

    def test_interrupted_write_or_changed_actual_ciphertext_never_reports_success(self):
        archive, plan = public_inputs(); real_fsync = os.fsync
        for failure in ('fsync', 'tamper'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temp, fixture_pins(archive, plan):
                root = pathlib.Path(temp); (root / 'source.zip').write_bytes(archive); (root / 'plan.json').write_bytes(plan)
                output = root / 'sealed.aesgcm'; tampered = []
                def fsync(fd):
                    if failure == 'fsync': raise OSError(PUBLIC_CANARY)
                    real_fsync(fd)
                    if not tampered and output.exists():
                        data = output.read_bytes(); output.write_bytes(data[:-1] + bytes([data[-1] ^ 1])); tampered.append(True)
                with patch.object(owner, '_load_owner_key', return_value=KEY), patch.object(owner.os, 'fsync', fsync):
                    code, text = self.cli(['seal-input', '--archive', str(root / 'source.zip'),
                        '--plan', str(root / 'plan.json'), '--dpapi-key-file', str(root / 'PUBLIC-FAKE-DPAPI'),
                        '--output', str(output)])
                self.assertEqual(code, 2); self.assertNotIn('ciphertext_sha256', text)
                if failure == 'tamper': self.assertEqual(tampered, [True])

    def test_seal_readback_authenticates_and_revalidates_even_matching_written_bytes(self):
        archive, plan = public_inputs()
        malformed = public_runner.seal(b'{"schema":"PUBLIC-WRONG-ENVELOPE"}', KEY, b'FROZEN-SOURCE-BUNDLE')
        for cipher in (b'PUBLIC-NOT-AUTHENTICATED', malformed):
            with tempfile.TemporaryDirectory() as temp, fixture_pins(archive, plan):
                root = pathlib.Path(temp); (root / 'source.zip').write_bytes(archive); (root / 'plan.json').write_bytes(plan)
                with patch.object(owner, '_load_owner_key', return_value=KEY), \
                     patch.object(sealed_input, 'seal_frozen_input', return_value=cipher):
                    code, output = self.cli(['seal-input', '--archive', str(root / 'source.zip'),
                        '--plan', str(root / 'plan.json'), '--dpapi-key-file', 'PUBLIC-FAKE-DPAPI',
                        '--output', str(root / 'sealed.aesgcm')])
                self.assertEqual(code, 2); self.assertNotIn('ciphertext_sha256', output)

    def test_default_key_format_is_unsupported_with_no_plaintext_cli_or_env_fallback(self):
        args = ['seal-input', '--archive', 'PUBLIC-NOT-READ.zip', '--plan', 'PUBLIC-NOT-READ.json',
                '--dpapi-key-file', PUBLIC_CANARY, '--output', 'PUBLIC-NOT-CREATED.aesgcm']
        with patch.dict(os.environ, {'AI09_BUNDLE_KEY_B64': base64.b64encode(KEY).decode()}):
            code, output = self.cli(args)
        self.assertEqual(code, 2)
        self.assertEqual(output, 'OWNER_BUNDLE_ERROR=OWNER_KEY_FORMAT_UNSUPPORTED\n')
        for option in ('--key', '--key-b64'):
            code, output = self.cli([*args, option, PUBLIC_CANARY])
            self.assertEqual(code, 2); self.assertEqual(output, 'OWNER_BUNDLE_ERROR=OWNER_BUNDLE_FAILED\n')

    def test_key_adapter_failure_is_redacted(self):
        with patch.object(owner, '_load_owner_key', side_effect=RuntimeError(PUBLIC_CANARY)):
            code, output = self.cli(['seal-input', '--archive', 'source', '--plan', 'plan',
                                    '--dpapi-key-file', PUBLIC_CANARY, '--output', 'output'])
        self.assertEqual(code, 2); self.assertEqual(output, 'OWNER_BUNDLE_ERROR=OWNER_BUNDLE_FAILED\n')


if __name__ == '__main__': unittest.main()
