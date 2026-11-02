# Observed eight-item pilot connection implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Track progress in the task-local native Windows ledger.

**Goal:** Connect eight data-only requests, complete observed runtime evidence and authenticated round-trip verification without activating private execution.

**Architecture:** Retain the approved public driver/offline container/host teardown boundary. Stage only bounded batch data in a private host directory with an exact read-only file mount. Preserve the complete captured observation and launch manifest in an encrypted envelope; validate against independent host expectations after teardown and after unseal. Do not promote synthetic packets to actual evidence.

**Tech Stack:** Existing Python, pinned Ollama/qwen3, Docker policy, AES-GCM/HKDF. No new dependency or provider.

**Spec:** Issue #3 and docs/architecture/private-execution-proposal.md. The owner authorized continued completion on 2026-10-29; different-model design review found this connection fits the already approved data-only architecture. Human approver is haji84 only.

## Global constraints

- Original source SHA256 9cf979733d8d4753023b1dd239ba4a5f3be2e0a6a3216c9dda206c089a2b6aa5 and original raw plan SHA256 ad7c9a7b6914670c82b436ede89d543e8e09a3c0902448c9378fb6ab1aaecf44 remain unchanged.
- No private inputs in Git, public fixtures, logs or artifacts; never import or execute bundle code.
- Production loader and parked workflow remain unconditionally closed. No key creation/installation, secrets, activation, merge or paid operation in this implementation.
- Existing Docker profile, 450-second guest deadline, 540-second work deadline, 2MB capture and 5MB authenticated encryption limits remain unchanged.
- Reuse PR #2. Do not reset exhausted corrective-retry budgets; a failed new CI is recorded and stopped without automatic corrective retry.
- All new model demonstration inputs are PUBLIC; fixed-subject counts stay 0/8 and 0/104.

## Review focus

1. A valid encrypted envelope containing forged inventory/timestamps must still fail semantic revalidation.
2. A last-item failure cannot release a seven-item success or partial plaintext evidence.
3. Public asset directory permissions must not spread to confidential batch staging.
4. Inventory, timing and launch manifest must remain inside the encrypted evidence, not merely separately printed hashes.
5. An observed response contract is not cryptographic model attestation or formal owner approval.

### Task 1: Bounded staged batch and observed packet contract

**Files:** Create pilot_batch.py and tests/test_pilot_batch.py.

**Interfaces:** encode_batch(Batch)->bytes; decode_batch(bytes)->Batch; verify_observation(raw, expected, host_start, host_end)->ValidatedObservation. Exactly eight ordered chunks. New observation schema never grants approval or counts fixed-subject receipts.

- [x] Write and run failing PUBLIC tests for eight-item round trip, duplicate/swapped context, request/response binding, inventory tamper, ordered request times, response timestamps and final-item failure.
- [x] Implement strict bounded exact-key validation using existing driver/transport/inventory functions. Preserve all raw request/response and inventory bytes.
- [x] Run the new contract suite and existing driver tests.

### Task 2: Connect staged public data to the pinned real worker

**Files:** Modify tests/fixtures/model_guest.py, tools/public_model_smoke.py and tests/test_public_model_smoke.py.

**Interfaces:** Worker reads only /input/batch.json; public host constructs its own eight chunks and context. Worker performs sequential real HTTP calls under one deadline; complete packet is accepted only after positive teardown. Public context rejection remains mandatory.

- [x] Write and run failing tests for final-item error, no raw error disclosure, staged-input validation and missing/forged context rejection.
- [x] Use a separate 0700 host temporary parent and one 0444 read-only file mount. Preserve runtime/model/driver hash and effective Docker checks.
- [x] Keep original source/plan and production admission untouched. Public model calls become eight; fixed-subject count stays zero.
- [x] Run worker/host tests plus the full public suite.

### Task 3: Preserve and revalidate the complete evidence envelope

**Files:** Extend pilot_batch.py and its tests; modify CI path filters/step description and append current implementation status to the existing architecture document.

**Interfaces:** evidence_envelope(raw,batch,launch,host_start,host_end)->bytes; verify_evidence(payload,batch,launch,host_start,host_end)->ValidatedObservation. Seal/unseal use the existing evidence purpose and independently owned host expectations.

- [x] Write and run failing tests for missing outer metadata, launch substitution, bounded overflow and authenticated-but-semantically-invalid ciphertext.
- [x] Preserve complete captured packet plus host launch/time/context. After sealing, decrypt in memory and repeat all semantic checks before any export boundary. No artifact upload is added.
- [ ] Verify all local tests, diff hygiene and a fresh different-model whole-branch review. Publish reviewed public changes in existing PR #2, then run one latest-HEAD CI without corrective retry.
- [ ] Verify exact CI jobs/log boundaries/artifact absence, update Issue #3, and identify the remaining concrete private installation/activation gates. Do not claim original eight or 104 completion from PUBLIC observations.
