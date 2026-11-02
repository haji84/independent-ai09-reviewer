"""Strict in-memory original ZIP/raw-plan codec; no runtime admission or I/O.

Callers supply bytes and a key. The unchanged seal primitive obtains only its
cryptographic nonce from the OS. This module does not acquire inputs or keys,
retain the key, select a pilot, or authorize execution/export. Python does not
provide secure zeroization of transient cryptographic arguments or memory.
"""
import base64
import dataclasses

import data_driver as driver
import frozen_plan
import public_runner
import source_archive as source

__all__ = ('FrozenInput', 'seal_frozen_input', 'open_frozen_input')

_SCHEMA = 'AI09-FROZEN-INPUT-v1'
_PURPOSE = b'FROZEN-SOURCE-BUNDLE'
_KEYS = ('archive_b64', 'plan_b64', 'schema')
_EMPTY_SIZE = len(driver.encode_json({'archive_b64': '', 'plan_b64': '', 'schema': _SCHEMA}))
_FRAMING_SIZE = len(public_runner.MAGIC) + 12 + 16
_ERROR = 'SEALED_INPUT_REJECTED'


@dataclasses.dataclass(frozen=True, slots=True, repr=False)
class FrozenInput:
    """Read-only raw bytes, not a verification or execution capability."""
    archive_raw: bytes
    plan_raw: bytes

    def __repr__(self):
        return 'FrozenInput()'


def _need(condition):
    driver.require(condition, _ERROR)


def _raw(value, limit):
    _need(type(value) is bytes and 0 < len(value) <= limit)


def _encoded_size(length):
    return 4 * ((length + 2) // 3)


def _encoded_bound(text, limit):
    _need(type(text) is str and 0 < len(text) <= _encoded_size(limit)
          and len(text) % 4 == 0)
    padding = len(text) - len(text.rstrip('='))
    _need(padding <= 2 and 0 < 3 * (len(text) // 4) - padding <= limit)


def _decode(text):
    raw = base64.b64decode(text, validate=True)
    # validate=True alone accepts nonzero unused pad bits and some extra padding.
    _need(base64.b64encode(raw).decode('ascii') == text)
    return raw


def seal_frozen_input(archive_raw: bytes, plan_raw: bytes, key: bytes) -> bytes:
    """Verify both original inputs in full, then seal their unchanged bytes."""
    try:
        _need(type(key) is bytes and len(key) == 32)
        _raw(archive_raw, source.MAX_ARCHIVE)
        _raw(plan_raw, source.MAX_PLAN)
        size = _EMPTY_SIZE + _encoded_size(len(archive_raw)) + _encoded_size(len(plan_raw))
        _need(size <= driver.MAX_PACKET
              and size + _FRAMING_SIZE <= public_runner.MAX_ENCRYPTED)
        frozen_plan.verify_plan(archive_raw, plan_raw)
        plaintext = driver.encode_json({
            'archive_b64': base64.b64encode(archive_raw).decode('ascii'),
            'plan_b64': base64.b64encode(plan_raw).decode('ascii'),
            'schema': _SCHEMA})
        _need(len(plaintext) == size)
        return public_runner.seal(plaintext, key, _PURPOSE)
    except Exception:
        raise driver.GateError(_ERROR) from None


def open_frozen_input(ciphertext: bytes, key: bytes) -> FrozenInput:
    """Authenticate, decode strictly and freshly verify all 47/104 coverage."""
    try:
        _need(type(key) is bytes and len(key) == 32)
        _need(type(ciphertext) is bytes
              and _FRAMING_SIZE + 1 <= len(ciphertext)
              <= min(public_runner.MAX_ENCRYPTED, driver.MAX_PACKET + _FRAMING_SIZE))
        plaintext = public_runner.unseal(ciphertext, key, _PURPOSE)
        _raw(plaintext, driver.MAX_PACKET)
        envelope = driver.parse_json(plaintext, driver.MAX_PACKET)
        driver.exact_keys(envelope, _KEYS)
        _need(type(envelope['schema']) is str and envelope['schema'] == _SCHEMA)
        # Bound both decoded allocations before either one occurs.
        _encoded_bound(envelope['archive_b64'], source.MAX_ARCHIVE)
        _encoded_bound(envelope['plan_b64'], source.MAX_PLAN)
        archive_raw = _decode(envelope['archive_b64'])
        plan_raw = _decode(envelope['plan_b64'])
        _raw(archive_raw, source.MAX_ARCHIVE)
        _raw(plan_raw, source.MAX_PLAN)
        _need(driver.encode_json(envelope) == plaintext)
        frozen_plan.verify_plan(archive_raw, plan_raw)
        return FrozenInput(archive_raw, plan_raw)
    except Exception:
        raise driver.GateError(_ERROR) from None
