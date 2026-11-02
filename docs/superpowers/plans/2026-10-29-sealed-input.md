# Sealed Input Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Encode and open an authenticated, strictly bounded in-memory pair of unchanged original ZIP and raw plan bytes.

**Architecture:** Reuse the existing AES-GCM primitive with the fixed source purpose. Carry the two byte strings in canonical JSON/base64 and freshly run the existing fixed-hash, complete 47-source/104-span verifier in both directions. Return a read-only, content-hiding value without granting runtime authority.

**Tech Stack:** Existing Python standard library, `cryptography`, and `unittest`; no new dependency.

**Spec:** `docs/superpowers/specs/2026-10-29-sealed-input-design.md` (reviewed SHA256 `e6577503a01745f0807cf75122a8b0100a3672df3f99f0f3482d4a7bd99487b7`).

## Global Constraints

- Base head: `5c9c0fb83abfdb051b0d7cd8ae08bf1ddaafadeb`; all 44 baseline blobs verified in the isolated materialized workspace.
- Existing raw archive/plan pins and all 47-source/104-span checks remain unchanged. No caller pin, schema, purpose, selection or verified-object override.
- Schema `AI09-FROZEN-INPUT-v1`; exactly `archive_b64`, `plan_b64`, `schema`; purpose `b'FROZEN-SOURCE-BUNDLE'`.
- Exact immutable `bytes`; key length 32; archive at most 5,000,000 bytes; plan at most 2,000,000; nonempty envelope at most 2,000,000; ciphertext at least MAGIC + 12 + 16 + 1 bytes and no larger than either existing encrypted cap or envelope cap plus framing.
- No filesystem/network/process/environment access during codec calls; only the existing cryptographic nonce randomness is permitted. No key in return value, module state or cache.
- Fixed `GateError('SEALED_INPUT_REJECTED')`, with displayed exception chaining suppressed and no raw output.
- No actual source, owner key, model execution, remote change or private activation; private results remain 0/8 and 0/104.
- At most six candidate files: codec, tests, two-line public CI path addition, one README correction, reviewed design, this plan. Runtime, parked workflow and production HOLD remain unchanged.

## Review Focus

1. Nonzero unused base64 pad bits can decode successfully; `test_noncanonical_base64_is_rejected` must reject them.
2. Validly authenticated but noncanonical or wrong-shaped JSON must fail without a partial result; `test_authenticated_json_contract_is_strict` covers it.
3. A final 104th-span omission with recomputed chunk/plan hashes must fail both directions; `test_recomputed_final_span_defect_is_rejected` covers it.
4. Base64 expansion or framing errors must fail before expensive decoding/encoding; `test_bounds_precede_expensive_operations` covers the exact limits.
5. A returned input value does not authorize execution or skip host verification; `test_decoded_fixture_reaches_existing_host_and_still_requires_fresh_pins` covers real bounded capture and ciphertext readback with external PUBLIC fixtures only.

---

### Task 1: Strict in-memory codec and fixture acceptance

**Files:** Create `sealed_input.py` and `tests/test_sealed_input.py`.

**Interfaces:**
- Consumes: `frozen_plan.verify_plan(archive_raw, plan_raw)`, `data_driver.parse_json/encode_json/exact_keys`, and unchanged `public_runner.seal/unseal`.
- Produces: `seal_frozen_input(archive_raw: bytes, plan_raw: bytes, key: bytes) -> bytes`; `open_frozen_input(ciphertext: bytes, key: bytes) -> FrozenInput`; frozen/slotted `FrozenInput.archive_raw` and `.plan_raw`, repr `FrozenInput()`.

- [x] Write focused tests using complete generated 47/104 fixtures, independent literal schema/purpose expectations and test-only fixed-pin substitution. Include byte-exact whitespace-preserving roundtrip, immutable/repr-safe result, wrong key/purpose, mutation/truncation/appending, exact types/lengths, malformed JSON/base64 and final-span coverage. Guard I/O and canary diagnostics. Include one unchanged-host integration using `test_pilot_host.FakeRuntime`.
- [x] Run `python -m unittest discover -s tests -p 'test_sealed_input.py' -v` before implementation and retain the output. Expected: assertion failures identifying the absent codec, not import or setup errors.
- [x] Implement the two operations and small private validation helpers. Calculate exact empty-envelope overhead plus both padded base64 lengths before any base64 encoding; check encoded and predicted decoded lengths before decoding. Compare decoded/re-encoded base64 and canonical JSON bytes. Freshly verify all original data before sealing or returning. Wrap ordinary exceptions in the fixed error.
- [x] Run the same focused command. Expected: all new tests pass, including nonzero pad bits, authenticated malformed inputs, 104th-span recomputation, guarded I/O and fixture-only host integration. Correct implementation defects using retained reproductions; do not weaken assertions.
- [x] Record the focused result and exact changed bytes in the local ledger. No local or remote publication commit yet; root will publish one reviewed commit for the entire unit.

### Task 2: Narrow CI wiring, documentation and review package

**Files:** Modify `.github/workflows/ai09-public-boundary-ci.yml`, `README.md`, and the reviewed design; update this plan's checkboxes/results.

**Interfaces:** Consumes Task 1's two new paths and full fixture tests; produces the exact six-file review candidate and verification evidence outside candidate paths.

- [x] Add only `sealed_input.py` and `tests/test_sealed_input.py` to existing public `pull_request.paths`. Correct only the obsolete README repository-secret bullet to `ai09-private-pilot` Environment-only. Append design-review identity and observed implementation results without rewriting the reviewed design decision.
- [x] Compare baseline bytes and diff. Expected: removing the two added CI path lines recreates the original file; parked workflow and all other baseline files except README/CI are identical; no secret/private input or crypto/runtime change.
- [x] Run `python -m unittest discover -s tests -v`, saving complete output. Expected: all existing and new tests pass. If the managed sandbox reports loopback `EPERM`, keep that exact failure and rerun only this same PUBLIC unit command with the already authorized narrow loopback allowance; no network/model/service operation is added.
- [x] Freeze exact candidate files, SHA256/Git blob manifest, base and candidate tree, patch, and RED/GREEN/full-suite evidence. Expected: recomputation matches every frozen byte and prior host-candidate evidence is unchanged.
- [ ] Hand the fixed package to a genuinely different model for whole-change technical review. No self-approval, merge, publication, owner-runtime transfer or private run follows from local green tests.

## Plan self-review and execution choice

The design and five Terra implementation checks map to Task 1; CI/README boundaries and evidence map to Task 2. Task 2 consumes only the two new paths and their test result, so there is no API conflict. The five review-focus cases each have a named test. No implementation bodies are prescribed beyond the exact size formula and canonical comparison. Root explicitly chose native execution and authorized continued ordinary development; no repeated plan-approval question is needed.

## Results

- RED: 15 assertion failures before the codec existed; the final PUBLIC fixture test file was also rerun RED before implementation.
- Focused GREEN: 15/15 passed, no skips, 0.465s.
- Whole-suite default sandbox: 176 tests, eight existing loopback socket `EPERM` errors across seven methods; no assertion failures. Full failure output retained.
- Same whole-suite command with the narrowly approved local-loopback allowance: 176/176 passed, no skips, 5.554s. No real model, external network, owner key or private source was used.
- Base comparison: exactly two added CI path lines and one corrected README line; 42 other baseline files, including the parked workflow and runtime, unchanged.
- The exact-byte review candidate is frozen; genuinely different-model whole-change technical review is the next gate. No formal approval or private activation is implied.
