# Strict in-memory sealed input codec

Status: design reviewed and bounded implementation ready for independent
whole-change review; no private activation.
Base: existingPR2 `5c9c0fb83abfdb051b0d7cd8ae08bf1ddaafadeb`, actual tree
`a45f37e1d65347204278d6d2bfa273f7a28de7e1`. All44 base file blobs were checked.

## Intent and scope

Connect encrypted input bytes to the already-reviewed data-only frozen-input
contract, without opening any production gate. The owner requested continued
ordinary implementation; this bounded unit needs no repeated key/Environment
installation or design questionnaire. Root chose the existing Python/AES-GCM
stack and authorized only the two CI path-filter additions described below.

The original ZIP and raw plan remain immutable. The implementation must use the
existing independently pinned constant in `source_archive.FROZEN_SHA`, whose value is
`9cf979733d8d4753023b1dd239ba4a5f3be2e0a6a3216c9dda206c089a2b6aa5`.
Raw plan pin remains `frozen_plan.FROZEN_PLAN_SHA`
(`ad7c9a7b6914670c82b436ede89d543e8e09a3c0902448c9378fb6ab1aaecf44`).
The verifier must freshly check all104 spans and47 selected sources on both
encode and decode. No new version of the original subject, normalization,
recompression, re-chunking or expected-hash override is allowed.

## Approaches and choice

1. **Canonical JSON with two base64 data fields — selected by the implementation
   coordinator for review.** Reuses the existing strict JSON parser and needs no
   outer archive paths, extraction or executable members. Base64 adds about one
   third to the size; explicit preflight keeps it within existing limits.
2. **A strict two-member outer ZIP.** Saves some space and resembles the legacy
   bundle, but introduces outer ZIP metadata/path/alias parsing or another archive
   parser. The fixed-source reader cannot simply validate a different outer ZIP.
   That extra surface is unnecessary for this fixed roughly100KB input pair.

The old `public_runner.open_bundle()` extracts a multi-member private harness and
is not reused. The historical ciphertext digest in `sealed/README.md` establishes
neither the new data-envelope format nor compatibility with the installed key.
No real ciphertext is read, rewritten, produced or installed in this unit.

## Public API and data format

New `sealed_input.py` exposes exactly these ordinary byte-oriented operations:

```python
seal_frozen_input(archive_raw: bytes, plan_raw: bytes, key: bytes) -> bytes
open_frozen_input(ciphertext: bytes, key: bytes) -> FrozenInput
```

`FrozenInput` is a frozen, slotted data value with exactly `archive_raw` and
`plan_raw` immutable byte fields. Its representation is `FrozenInput()` and
contains no bytes, names, paths, key, counts or approval flags. It is not a trust
capability: callers may not substitute it for fresh verification, and the current
host continues to independently verify its raw inputs. The API accepts no path,
file object, loader callback, Batch, VerifiedPlan, schema/purpose override, run
selector or alternative pin. Bytearray/memoryview and non-bytes keys are rejected.

The authenticated plaintext has exactly three keys:

```json
{"archive_b64":"...","plan_b64":"...","schema":"AI09-FROZEN-INPUT-v1"}
```

The envelope uses `data_driver.encode_json` canonical ASCII encoding. Decode
requires strict duplicate-free/type-safe JSON, exact keys and schema, canonical
standard padded base64 with decode/re-encode equality, and canonical outer JSON
byte equality. Original archive and raw-plan bytes themselves are never changed.
There are no embedded hashes to trust; code-pinned fresh verification decides.

Use the unchanged `public_runner.seal/unseal`, MAGIC, HKDF and AES-256-GCM
mechanism, with fixed purpose `b'FROZEN-SOURCE-BUNDLE'`. The evidence purpose is
not accepted. A legacy ZIP plaintext or unknown schema is rejected even if its
AEAD authentication succeeds; this is not a legacy migration or fallback decoder.

## Bounds and operation order

- Keys are exactly32 immutable bytes. Raw archive and raw plan are nonempty bytes
  bounded by the existing5,000,000 and2,000,000 byte maxima respectively.
- The final canonical plaintext envelope is at most the existing
  `data_driver.MAX_PACKET` (2,000,000 bytes). Its size is computed before base64
  allocation as the fixed empty-envelope overhead plus
  `4*ceil(archive_length/3) + 4*ceil(plan_length/3)`.
- Ciphertext is nonempty and at most the lesser of existing
  `public_runner.MAX_ENCRYPTED` (5,000,000) and the plaintext cap plus the existing
  MAGIC/12-byte nonce/16-byte tag overhead. Require enough bytes for all framing
  and nonempty plaintext before calling authentication. No limits are increased.
- Encode validates types/lengths/key and preflights expansion, then freshly calls
  `frozen_plan.verify_plan` before creating the canonical envelope and sealing.
- Decode validates ciphertext/key type and bounds before authentication, then
  bounds plaintext before strict parsing. It checks schema/keys/encoded lengths,
  canonical base64 and decoded bounds, canonical JSON equality, then freshly
  verifies original pins and all104/47 coverage before returning `FrozenInput`.
- Recorded real input lengths73,434 and28,948 imply an envelope larger than the
  default131,072-byte parser limit. Use the explicit existing2MB limit. Not all
  maximum-size raw pairs fit the envelope; such pairs fail closed.

Every caller-visible validation, authentication or unexpected ordinary exception
is converted to a fixed `GateError('SEALED_INPUT_REJECTED')` without raw details
or displayed exception chaining. Neither operation prints/logs or reads an
environment variable. No key is retained in the result, module state or cache.
Transient arguments/derived cryptographic memory exist normally; Python cannot
promise secure zeroization or protection against inspection of the trusted host.

There is no filesystem, network, subprocess, provider, key-store or Environment
I/O. The only randomness is the existing seal primitive's OS cryptographic nonce
source. Input bytes and a key are supplied by a future independently authorized
caller; this library is not authorization to obtain or transmit them.

## Meaningful validation

Tests use generated PUBLIC archives/plans with test-only substituted fixture pins.
Production has no override. First observe new assertions fail before implementing.

- A generated47-source/104-span roundtrip preserves both exact raw byte strings,
  including plan whitespace; result mutation and content-bearing repr are refused.
- Wrong key, evidence-purpose ciphertext, bit flips, truncation, appended bytes,
  empty/type/size violations, legacy ZIP plaintext and unknown schema all reject.
- Authenticated malformed JSON, duplicate/unknown/missing keys, non-string fields,
  noncanonical outer JSON, malformed/noncanonical base64 and expansion overflow
  reject without returning any partial input. Large pairs are rejected before
  expensive encoding/parsing and allocation beyond their fixed bounds.
- Matching self-declared metadata cannot replace production pins. Archive/plan
  substitution and a defect in the final104th span reject even after re-encryption
  and test-only recomputation of internal hashes. Both public entrypoints perform
  fresh verification rather than accepting a caller-created verified object.
- PUBLIC canaries never appear in repr, fixed errors or captured stdout/stderr.
  Guard filesystem/network/process/environment operations during codec calls to
  show that decoding never extracts, imports, runs or fetches supplied material.
- One generated integration can decode input and pass its raw bytes to the
  unchanged host with the existing external Docker/download fixtures. Its real
  bounded child capture and temporary encrypted output exercise only test data;
  this adds no actual model call and never establishes private receipts.

Run the complete existing unit suite plus new tests, retain any sandbox loopback
failure honestly, obtain different-model whole-change review, freeze exact bytes,
then root publishes one commit in existingPR2. The new head uses the existing
PUBLIC8 CI once; no extra model command, parallel run or corrective retry is
introduced by this design. Actual private counts remain 0/8 and 0/104 until authorized
private execution is separately observed.

## Expected five-file change

1. New `sealed_input.py`.
2. New `tests/test_sealed_input.py`.
3. Existing public CI: add only those two paths to `pull_request.paths`.
   Jobs, commands, trigger types, permissions, time/resource/model limits and
   secret access remain byte-identical after removing those two added lines.
4. README: narrowly correct the old repository-secret bullet to the already
   installed `ai09-private-pilot` Environment-only secret policy. No operation
   creates, reads, registers, rotates or moves the existing key.
5. This short design, with the bounded implementation checklist/results appended.

No changes to `pilot_host`, PUBLIC smoke, guest, frozen-input verifier, crypto
primitives, dependencies, parked pilot, AGENTS, protection or activation settings.
The previous10-file frozen candidate and its review/failure evidence remain intact.

## External gates left for the final concrete action

Owner input recovery and owner key/Environment installation are already complete.
Do not ask for them again or for another human approver. Later work must provide
a reviewed owner-runtime encoder using the existing DPAPI key and original data,
verify actual current ciphertext/hash/size and runtime key match, check storage
headroom/retention/stop conditions, and authorize the exact final main SHA for a
bounded private run/export. Secret-free runtime prefetch and the opaque host
handle still need concrete wiring; neither that wiring nor private activation
belongs to this codec unit. No formal GitHub approval or final DESIGN_APPROVAL
is inferred from implementation, PUBLIC fixtures or technical model review.

## Implementation record (2026-10-29)

The configured independent `gpt-6.1-terra` reviewer accepted the original design
SHA256 `e6577503a01745f0807cf75122a8b0100a3672df3f99f0f3482d4a7bd99487b7`
with no design blockers. The local technical report has SHA256
`ba27bc7fef61c073ca51f3eeb47dcae581d4e744ebb75b4e986877cba65a0e83`;
the serving-model digest was not observed. The exact reviewed design bytes are
preserved separately. This review grants neither formal GitHub approval nor
private activation.

Root authorized one additional concise implementation plan at
`docs/superpowers/plans/2026-10-29-sealed-input.md`, bringing the change to six
files without changing the accepted format or operational boundary. Native
execution produced the strict codec and 15 new PUBLIC-fixture tests. The tests
failed before implementation and then passed, including canonical base64 pad
bits, exact envelope preflight, recomputed final-span coverage failure, guarded
I/O, and unchanged-host integration with actual bounded child capture and
ciphertext readback. Existing external Docker/download fixtures supply the
integration's runtime observations; no actual model ran.

The full default-sandbox run found eight existing loopback `EPERM` errors across
seven methods. The same PUBLIC unit command under the approved local-loopback
allowance passed **176/176**, with **zero skips**, in **5.554s**. The failure and
success logs are retained locally. No code changed to bypass those restrictions.
CI changed only by the two permitted path lines; README changed only by the
Environment-only correction. All other 42 baseline files remain byte-identical.

Implementation is ready for an exact-byte freeze and independent whole-change
technical review. Actual private counts are still **0/8 and 0/104**. Current
owner ciphertext/key compatibility, owner-runtime encoding, storage/transfer,
production admission and exact-main private activation remain separate gates.
