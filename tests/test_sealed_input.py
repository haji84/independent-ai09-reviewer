"""Complete generated PUBLIC fixtures only; never the pinned private inputs."""
import base64
import contextlib
import copy
import dataclasses
import importlib.util
import io
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import traceback
import unittest
import urllib.request
import zipfile
from unittest.mock import patch

import data_driver as driver
import frozen_plan
import pilot_host
import public_runner
import source_archive
from test_frozen_plan import encode, fixture, sha
from test_pilot_host import FakeRuntime

codec = __import__('sealed_input') if importlib.util.find_spec('sealed_input') else None
KEY = b'PUBLIC-SEALED-INPUT-KEY-CANARY-0'
PURPOSE = b'FROZEN-SOURCE-BUNDLE'
EVIDENCE_PURPOSE = b'CONFIDENTIAL-REVIEW-EVIDENCE'
SCHEMA = 'AI09-FROZEN-INPUT-v1'
CANARY = 'PUBLIC-ERROR-CANARY-DO-NOT-DISPLAY'


def envelope(archive_raw, plan_raw):
    return {'archive_b64': base64.b64encode(archive_raw).decode('ascii'),
            'plan_b64': base64.b64encode(plan_raw).decode('ascii'), 'schema': SCHEMA}


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(',', ':'), allow_nan=False).encode('ascii')


@contextlib.contextmanager
def fixture_pins(archive_raw, plan_raw):
    # The production API never takes expected hashes or a prior verified object.
    with patch.object(source_archive, 'FROZEN_SHA', sha(archive_raw)), \
         patch.object(frozen_plan, 'FROZEN_PLAN_SHA', sha(plan_raw)):
        yield


class SealedInputTest(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(codec, 'strict in-memory sealed input codec is missing')
        self.archive, self.plan, self.files = fixture()
        self.raw_plan = encode(self.plan)

    def encrypt(self, plaintext):
        return public_runner.seal(plaintext, KEY, PURPOSE)

    def rejected(self, operation, *args):
        with self.assertRaises(driver.GateError) as caught:
            operation(*args)
        self.assertEqual(str(caught.exception), 'SEALED_INPUT_REJECTED')
        self.assertIsNone(caught.exception.__cause__)
        self.assertTrue(caught.exception.__suppress_context__)
        return caught.exception

    def test_roundtrip_preserves_raw_bytes_and_exceeds_default_json_limit(self):
        raw_plan = self.raw_plan + b'\n ' + b' ' * 90_000
        expected = canonical(envelope(self.archive, raw_plan))
        self.assertGreater(len(expected), 131_072)
        with fixture_pins(self.archive, raw_plan):
            cipher = codec.seal_frozen_input(self.archive, raw_plan, KEY)
            opened = codec.open_frozen_input(cipher, KEY)
            verified = frozen_plan.verify_plan(opened.archive_raw, opened.plan_raw)
        self.assertEqual(public_runner.unseal(cipher, KEY, PURPOSE), expected)
        self.assertEqual(opened.archive_raw, self.archive)
        self.assertEqual(opened.plan_raw, raw_plan)
        self.assertEqual(len(verified.spans), 104)
        self.assertEqual(len({span.path for span in verified.spans}), 47)
        self.assertEqual(repr(opened), 'FrozenInput()')
        self.assertEqual(tuple(field.name for field in dataclasses.fields(opened)),
                         ('archive_raw', 'plan_raw'))
        self.assertFalse(hasattr(opened, '__dict__'))
        self.assertFalse(hasattr(opened, 'key'))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            opened.plan_raw = b'REPLACEMENT'
        self.assertNotIn(self.raw_plan, cipher)
        self.assertNotIn(KEY, cipher)

    def test_wrong_key_purpose_and_ciphertext_mutations_are_rejected(self):
        plain = canonical(envelope(self.archive, self.raw_plan))
        cipher = self.encrypt(plain)
        changed = bytearray(cipher); changed[-1] ^= 1
        values = [cipher[:-1], cipher+b'APPENDED', bytes(changed), b'X'+cipher[1:],
                  public_runner.seal(plain, KEY, EVIDENCE_PURPOSE)]
        with fixture_pins(self.archive, self.raw_plan):
            for value in values:
                with self.subTest(ciphertext_bytes=len(value)):
                    self.rejected(codec.open_frozen_input, value, KEY)
            self.rejected(codec.open_frozen_input, cipher, bytes(range(32)))

    def test_exact_key_and_immutable_bytes_types_are_required(self):
        cipher = self.encrypt(canonical(envelope(self.archive, self.raw_plan)))
        class ByteSubclass(bytes):
            pass
        with fixture_pins(self.archive, self.raw_plan):
            for key in (b'', b'k'*31, b'k'*33, 'k'*32, bytearray(KEY),
                        memoryview(KEY), ByteSubclass(KEY), None):
                with self.subTest(key_type=type(key).__name__):
                    self.rejected(codec.seal_frozen_input, self.archive, self.raw_plan, key)
                    self.rejected(codec.open_frozen_input, cipher, key)
            for value in (bytearray(self.archive), memoryview(self.archive),
                          ByteSubclass(self.archive), 'PUBLIC/path.zip', None):
                self.rejected(codec.seal_frozen_input, value, self.raw_plan, KEY)
            for value in (bytearray(self.raw_plan), memoryview(self.raw_plan),
                          ByteSubclass(self.raw_plan), 'PUBLIC/plan.json', None):
                self.rejected(codec.seal_frozen_input, self.archive, value, KEY)
            for value in (bytearray(cipher), memoryview(cipher), ByteSubclass(cipher),
                          'PUBLIC/input.aesgcm', None):
                self.rejected(codec.open_frozen_input, value, KEY)

    def test_bounds_precede_expensive_operations(self):
        attempts = []
        def forbidden(*args, **kwargs):
            attempts.append(True)
            raise AssertionError('operation must not be reached')
        with patch.object(frozen_plan, 'verify_plan', side_effect=forbidden), \
             patch.object(base64, 'b64encode', side_effect=forbidden):
            for archive, plan in ((b'', self.raw_plan), (self.archive, b''),
                                  (b'x'*5_000_001, self.raw_plan),
                                  (self.archive, b'x'*2_000_001),
                                  (b'x'*1_000_000, b'y'*600_000)):
                self.rejected(codec.seal_frozen_input, archive, plan, KEY)
        self.assertEqual(attempts, [], 'oversized input reached verification or allocation')
        with patch.object(public_runner, 'unseal', side_effect=forbidden):
            for cipher in (b'', public_runner.MAGIC+b'x'*28,
                           public_runner.MAGIC+b'x'*(2_000_000+29)):
                self.rejected(codec.open_frozen_input, cipher, KEY)
        self.assertEqual(attempts, [], 'invalid framing reached authentication')

    def test_exact_envelope_overhead_is_included_in_size_preflight(self):
        empty_size = len(b'{"archive_b64":"","plan_b64":"","schema":"AI09-FROZEN-INPUT-v1"}')
        archive_encoded_size = 4*((len(self.archive)+2)//3)
        max_plan_length = ((2_000_000-empty_size-archive_encoded_size)//4)*3
        raw_plan = self.raw_plan+b' '*(max_plan_length-len(self.raw_plan))
        plain = canonical(envelope(self.archive, raw_plan))
        self.assertLessEqual(len(plain), 2_000_000)
        self.assertGreater(len(plain), 1_999_996)
        with fixture_pins(self.archive, raw_plan):
            cipher = codec.seal_frozen_input(self.archive, raw_plan, KEY)
            self.assertEqual(codec.open_frozen_input(cipher, KEY).plan_raw, raw_plan)
        attempts = []
        def forbidden(*args, **kwargs):
            attempts.append(True)
            raise AssertionError('allocation after over-cap preflight')
        with patch.object(base64, 'b64encode', side_effect=forbidden), \
             patch.object(frozen_plan, 'verify_plan', side_effect=forbidden):
            self.rejected(codec.seal_frozen_input, self.archive, raw_plan+b' ', KEY)
        self.assertEqual(attempts, [])

    def test_both_encoded_fields_are_bounded_before_any_base64_decode(self):
        # Narrow an existing input cap only in this fixture to exercise the
        # independently bounded plan field before archive decoding allocates.
        cipher = self.encrypt(canonical(envelope(self.archive, self.raw_plan)))
        attempts = []
        def forbidden(*args, **kwargs):
            attempts.append(True)
            raise AssertionError('decoding exceeded a raw input bound')
        with patch.object(source_archive, 'MAX_PLAN', len(self.raw_plan)-1), \
             patch.object(base64, 'b64decode', side_effect=forbidden):
            self.rejected(codec.open_frozen_input, cipher, KEY)
        self.assertEqual(attempts, [])

    def test_authenticated_json_contract_is_strict(self):
        good = envelope(self.archive, self.raw_plan)
        variants = [b'', b'not-json', b'\xff', b'['*25+b'0'+b']'*25,
                    canonical(good)+b'\n', b' '+canonical(good),
                    canonical(good).replace(b'"schema":', b'"\\u0073chema":'),
                    canonical(good)[:-1]+b',"schema":"'+SCHEMA.encode()+b'"}',
                    b'null', b'false', b'[]', canonical(CANARY), self.archive]
        for name in ('archive_b64', 'plan_b64', 'schema'):
            missing = dict(good); del missing[name]; variants.append(canonical(missing))
            for value in (None, False, 1, [], {}, CANARY):
                changed = dict(good); changed[name] = value; variants.append(canonical(changed))
        extra = dict(good); extra['archive_sha256'] = sha(self.archive)
        variants.append(canonical(extra))
        wrong_schema = dict(good); wrong_schema['schema'] = 'AI09-FROZEN-INPUT-v2'
        variants.append(canonical(wrong_schema))
        with fixture_pins(self.archive, self.raw_plan):
            for number, plain in enumerate(variants):
                with self.subTest(case=number):
                    self.rejected(codec.open_frozen_input, self.encrypt(plain), KEY)

    def test_noncanonical_base64_is_rejected(self):
        alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
        for remainder in (1, 2):
            raw_plan = self.raw_plan + b' '*((remainder-len(self.raw_plan)) % 3)
            good = envelope(self.archive, raw_plan)
            text = good['plan_b64']
            position = -3 if remainder == 1 else -2
            changed = list(text)
            changed[position] = alphabet[alphabet.index(changed[position]) | 1]
            bad_bits = ''.join(changed)
            self.assertNotEqual(bad_bits, text)
            self.assertEqual(base64.b64decode(bad_bits, validate=True), raw_plan)
            values = [bad_bits, text.rstrip('='), text+'=', text+'\n',
                      '\n'+text, text[:4]+' '+text[4:], '', '\u00e9', '!!!!', 'A===']
            with fixture_pins(self.archive, raw_plan):
                for number, value in enumerate(values):
                    bad = dict(good); bad['plan_b64'] = value
                    with self.subTest(remainder=remainder, case=number):
                        self.rejected(codec.open_frozen_input, self.encrypt(canonical(bad)), KEY)

    def test_self_consistent_fixtures_cannot_replace_production_pins(self):
        cipher = self.encrypt(canonical(envelope(self.archive, self.raw_plan)))
        self.rejected(codec.seal_frozen_input, self.archive, self.raw_plan, KEY)
        self.rejected(codec.open_frozen_input, cipher, KEY)

    def test_replaced_original_bytes_fail_even_with_valid_authentication(self):
        with fixture_pins(self.archive, self.raw_plan):
            for archive, raw_plan in ((self.archive+b'\x00', self.raw_plan),
                                      (self.archive, self.raw_plan+b' ')):
                self.rejected(codec.seal_frozen_input, archive, raw_plan, KEY)
                self.rejected(codec.open_frozen_input,
                              self.encrypt(canonical(envelope(archive, raw_plan))), KEY)

    def test_recomputed_final_span_defect_is_rejected(self):
        bad = copy.deepcopy(self.plan)
        last = bad['chunks'][103]
        last['end_byte'] -= 1
        content = self.files[last['path']]
        last['sha256'] = sha(content[last['start_byte']:last['end_byte']])
        last['end_line'] = content[:last['end_byte']].count(b'\n')+1
        raw_plan = encode(bad)  # Recompute the canonical self-hash as well.
        cipher = self.encrypt(canonical(envelope(self.archive, raw_plan)))
        with fixture_pins(self.archive, raw_plan):
            with self.assertRaisesRegex(driver.GateError, '^FROZEN_PLAN_COVERAGE$'):
                frozen_plan.verify_plan(self.archive, raw_plan)
            self.rejected(codec.seal_frozen_input, self.archive, raw_plan, KEY)
            self.rejected(codec.open_frozen_input, cipher, KEY)

    def test_success_does_not_cache_verification_or_accept_authority_overrides(self):
        with fixture_pins(self.archive, self.raw_plan):
            cipher = codec.seal_frozen_input(self.archive, self.raw_plan, KEY)
            opened = codec.open_frozen_input(cipher, KEY)
            with patch.object(frozen_plan, 'FROZEN_PLAN_SHA', '0'*64):
                self.rejected(codec.seal_frozen_input, self.archive, self.raw_plan, KEY)
                self.rejected(codec.open_frozen_input, cipher, KEY)
        self.rejected(codec.seal_frozen_input, opened, self.raw_plan, KEY)
        for options in ({'expected_sha': sha(self.archive)}, {'purpose': PURPOSE},
                        {'schema': SCHEMA}, {'verified': opened}, {'start': 8}):
            with self.assertRaises(TypeError):
                codec.seal_frozen_input(self.archive, self.raw_plan, KEY, **options)
            with self.assertRaises(TypeError):
                codec.open_frozen_input(cipher, KEY, **options)

    def test_errors_and_diagnostics_do_not_display_input_or_exception_canaries(self):
        cipher = self.encrypt(canonical(envelope(self.archive, self.raw_plan)))
        stdout = io.StringIO(); stderr = io.StringIO()
        with fixture_pins(self.archive, self.raw_plan), \
             contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            for name, operation, args in (
                    ('seal', codec.seal_frozen_input, (self.archive, self.raw_plan, KEY)),
                    ('unseal', codec.open_frozen_input, (cipher, KEY))):
                with patch.object(public_runner, name, side_effect=OSError(CANARY)):
                    error = self.rejected(operation, *args)
                    displayed = ''.join(traceback.format_exception(error))
                    self.assertNotIn(CANARY, displayed)
                    self.assertNotIn(KEY.decode(), displayed)
            with patch.object(frozen_plan, 'verify_plan', side_effect=RuntimeError(CANARY)):
                self.rejected(codec.seal_frozen_input, self.archive, self.raw_plan, KEY)
                self.rejected(codec.open_frozen_input, cipher, KEY)
        self.assertEqual(stdout.getvalue(), '')
        self.assertEqual(stderr.getvalue(), '')

    def test_codec_calls_have_no_file_network_process_or_environment_io(self):
        attempts = []
        def forbidden(*args, **kwargs):
            attempts.append(True)
            raise AssertionError('codec attempted external I/O')
        class ForbiddenEnvironment:
            get = __getitem__ = __setitem__ = __iter__ = __len__ = forbidden
        guards = [('builtins.open', forbidden), ('io.open', forbidden),
                  ('os.open', forbidden), ('os.read', forbidden), ('os.write', forbidden),
                  ('os.getenv', forbidden), ('os.environ', ForbiddenEnvironment()),
                  ('socket.socket', forbidden), ('socket.create_connection', forbidden),
                  ('subprocess.Popen', forbidden), ('subprocess.run', forbidden),
                  ('os.system', forbidden), ('urllib.request.urlopen', forbidden),
                  ('zipfile.ZipFile.extract', forbidden), ('zipfile.ZipFile.extractall', forbidden),
                  ('public_runner.open_bundle', forbidden)]
        with fixture_pins(self.archive, self.raw_plan), contextlib.ExitStack() as stack:
            for name, replacement in guards:
                stack.enter_context(patch(name, replacement))
            cipher = codec.seal_frozen_input(self.archive, self.raw_plan, KEY)
            opened = codec.open_frozen_input(cipher, KEY)
        self.assertEqual(attempts, [])
        self.assertEqual((opened.archive_raw, opened.plan_raw), (self.archive, self.raw_plan))
        self.assertFalse(any(value is KEY for value in vars(codec).values()))

    @unittest.skipUnless(sys.platform == 'linux', 'Linux host path; mandatory Linux CI')
    def test_decoded_fixture_reaches_existing_host_and_still_requires_fresh_pins(self):
        cipher = self.encrypt(canonical(envelope(self.archive, self.raw_plan)))
        with tempfile.TemporaryDirectory(prefix='ai09-sealed-fixture-') as temp:
            output = pathlib.Path(temp); output.chmod(0o700)
            fake = FakeRuntime()
            with fake.install(), pilot_host.prepare_runtime() as prepared:
                with fixture_pins(self.archive, self.raw_plan):
                    opened = codec.open_frozen_input(cipher, KEY)
                    result = pilot_host.run_frozen_pilot(
                        prepared, opened.archive_raw, opened.plan_raw, KEY,
                        run_id='123', attempt=1, commit='a'*40, output_directory=output)
            evidence = (output/'ai09-observed-evidence.aesgcm').read_bytes()
            payload = driver.parse_json(public_runner.unseal(evidence, KEY, EVIDENCE_PURPOSE),
                                        driver.MAX_PACKET)
            packet = driver.parse_json(base64.b64decode(payload['packet_b64']), driver.MAX_PACKET)
            self.assertEqual([item['chunk_id'] for item in packet['exchanges']],
                             ['000', '001', '002', '003', '004', '005', '006', '007'])
            self.assertEqual(payload['context']['source_sha'], sha(self.archive))
            self.assertEqual(payload['context']['plan_sha'], sha(self.raw_plan))
            self.assertEqual(payload['launch']['input_class'], 'FROZEN_DATA_ONLY')
            self.assertEqual(result.ciphertext_sha256, sha(evidence))
            self.assertEqual((result.observed_responses, result.fixed_subject_receipts), (8, 0))
            self.assertNotIn(KEY.decode(), repr(fake.commands))
            self.assertFalse(fake.present)
            rejected_output = output/'rejected'; rejected_output.mkdir(mode=0o700)
            fake = FakeRuntime()
            with fake.install(), pilot_host.prepare_runtime() as prepared:
                with self.assertRaisesRegex(driver.GateError, '^FROZEN_SOURCE_HASH_MISMATCH$'):
                    pilot_host.run_frozen_pilot(
                        prepared, opened.archive_raw, opened.plan_raw, KEY,
                        run_id='123', attempt=1, commit='a'*40, output_directory=rejected_output)
            self.assertFalse(any(command[1] == 'create' for command in fake.commands))
            self.assertEqual(list(rejected_output.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
