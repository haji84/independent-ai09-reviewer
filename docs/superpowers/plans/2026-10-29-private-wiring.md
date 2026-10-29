# Private Pilot Connection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Connect the strict encrypted input to the reviewed eight-observation host through bounded pipes, and verify output against separately retrieved host commitments, while private activation remains unconditionally closed.

**Architecture:** One trusted coordinator launches one sanitized child; only validated READY permits ciphertext/key delivery. The child retains its original host handle and clock. A separate owner-local pure boundary reconstructs expected launch against an authenticated retrieval commitment; the unverified real DPAPI adapter fails explicitly.

**Tech Stack:** Existing Python, cryptography, unittest, selectors, POSIX descriptors, pinned GitHub Actions; no dependency/provider addition.

**Spec:** `docs/superpowers/specs/2026-10-29-private-wiring-design.md`, reviewed original SHA256 `5ee30873931ee9599d109f0ac60adf2a94743ce234514f4bdce3543e42f97538`; Terra revision-2 review SHA256 `00f7a5b134b484f7a05bb67d853c74d7989eba86bb7dbb73a174d5e31198c548`.

## Global Constraints

- Base PR2 head `462c35f3eff19194097d2f6e9c8dba0e391dfd50`, actual tree `54df4be13bd2265ad7715ad112b0f2b9011e9b99`, 48 verified files. Previous workspace/freeze stays unchanged.
- Fixed raw source/plan pins and fresh 47-source/104-span verification remain unchanged; only first eight exchanges, fixed model/resource limits, original work540/cleanup600 clocks, capture480 and existing PUBLIC8 smoke.
- Coordinator receives the Environment key in its own environment; only the child/download processes are secret-free before READY. Trusted host/kernel/daemon/same UID and authenticated owner retrieval are explicit assumptions.
- Transport allowlist is only for PUBLIC fetch; offline Docker, CPU extraction and capture retain their exact PATH-only environments.
- READY at most512 bytes; stdout total4096; any stderr rejects with cap1024; DONE fixed canonical metadata. Input frame bounded by the actual sealed-input maximum; absolute deadlines never reset.
- Run ID is canonical decimal STRING `[1-9][0-9]{0,19}`. Attempt/epoch ns/job ID are positive exact integers excluding bool; coordinator attempt is exactly1. SHA values are lowercase hex, commit40 and hashes64.
- No real private data/key/model/DPAPI, remote writes, dispatch or activation. Owner Windows compatibility and hosted HOLD ordering remain NOT_RUN.
- Scope: section8's 17 files (host+test, assets+test, private module/dispatcher/test/one fixture, owner helper+test, two workflows+workflow test, README/architecture/design/plan). No AGENTS or policy changes.

## Review Focus

1. Real duplex pipes can deadlock or accept an early DONE; fault tests exercise partial writes, input above pipe capacity, stalled peers, duplicate/extra control frames and short deadlines.
2. Parent crash cleanup can outlive its budget or claim too much; recorded-name reaping, TERM/KILL fallback and failure outcomes stay bounded/non-ready.
3. A matching ciphertext hash does not authenticate expected context; pure helper tests use separately approved identities and actual timestamp-prefixed marker parsing, with source-echo/duplicate/substitution negatives.
4. Ancestor or file swaps can detach an acknowledged ciphertext; descriptor-chain, file identity/nlink/type/size and before/after read checks get real filesystem mutation tests.
5. HOLD inside an Environment job can prompt approval too early; the unbound admission failure and success-only downstream dependency get execution and condition-matrix tests; actual GitHub ordering is separately NOT_RUN.

---

### Task 1: Host cleanup metadata and PUBLIC transport

**Files:** `pilot_host.py`, `tests/test_pilot_host.py`, `runtime_assets.py`, `tests/test_runtime_assets.py`.
**Interfaces:** Add `prepared_cleanup_info(prepared) -> CleanupInfo(container_name, work_deadline, cleanup_deadline)` with immutable hidden repr and live non-consuming identity validation. Add actual `host_start_ns`, `host_end_ns` to `PilotResult`. Add `public_fetch_environment()` for exact inherited proxy/CA allowlist plus interpreter runtime names; use verified HTTPS context in `_download`.

- [x] Write tests that fail for absent cleanup metadata/times and stripped configured proxy/CA. Check handle expiry/consume, same name through create/remove, wall-clock values, CA precedence and no offline environment change.
- [x] Run the two focused files and retain RED. Expected: new contract assertions fail while baseline behavior remains intact.
- [x] Implement only the metadata/name allocation/result additions and PUBLIC transport correction.
- [x] Run the two focused files. Expected: all PASS; no network, models or private material.

### Task 2: One-shot coordinator and child

**Files:** new `private_pilot.py`, `tools/private_pilot.py`, `tests/test_private_pilot.py`, `tests/fixtures/private_pilot_child.py`.
**Interfaces:** `coordinate() -> bytes` returns canonical public host observation after exact success. `child_main(run_id, attempt, commit, output_directory, nonce)` consumes only the one bounded stdin frame inside the prepared context. Fixed dispatcher chooses coordinator or its internal child mode; production has no child/provider/verifier override.

- [x] Write real-pipe tests for READY-before-read/key, canonical frames/nonce/deadlines, strict admitted public context, sanitized child environment, large partial input, EOF/order/exit/flood/stall/cancellation failures, and exact-name cleanup. Add generated deterministic 47/104 encrypted input through real host capture/crypto/output using existing external PUBLIC fixtures.
- [x] Run focused tests before implementation. Expected: absent coordinator assertion failures, retained as RED.
- [x] Implement strict public admission, fixed input path and safe output creation, retained directory descriptors and bounded reads; one nonblocking selector loop drains both control pipes while writing the frame. The child handles TERM inside its host context and enforces EOF/deadlines. Parent never forwards child output, and aborts never become ready.
- [x] Run focused tests, correct observed defects with evidence. Expected: bounded success only for READY→frame/EOF→DONE→EOF/exit0 and verified actual ciphertext; all fault modes terminate within fixture budgets.

### Task 3: Owner-local pure boundary and expected context

**Files:** new `tools/owner_bundle.py`, `tests/test_owner_bundle.py`.
**Interfaces:** `build_expected_context(run_metadata, job_metadata, log_bytes, *, approved_run_id, approved_attempt, approved_commit, approved_input_sha256, approved_input_bytes, approved_job_id) -> bytes`; `verify_evidence_bytes(archive_raw, plan_raw, key, ciphertext, expected_context_raw, expected_context_sha256)` uses external launch/time commitments and existing verifier. CLI seal/verify paths require the real DPAPI adapter, which raises `OWNER_KEY_FORMAT_UNSUPPORTED` until its actual non-secret contract is reviewed.

- [x] Write tests using an observation emitted by the actual PUBLIC-fixture coordinator. Reject malformed/duplicate/timestamp-echo markers, mismatched metadata, stale context/digest, modified external identity, re-encrypted changed launch/time, and unread/unsupported key formats. Prove context refusal before key access and exclusive output/readback behavior with test-only fake key adapter.
- [x] Run RED, implement the strict pure parser/verifier and bounded owner command wrapper without a plaintext-key CLI/env alternative, then run GREEN. Expected: PUBLIC fixture succeeds, all substitutions refuse, Windows/real key remains NOT_RUN.

### Task 4: Parked workflow, operator documentation and freeze

**Files:** existing two workflows, `tests/test_public_workflow.py`, README, architecture, design and this plan.
**Interfaces:** Add only three optional empty public dispatch strings `approved_main_sha`, `input_ciphertext_sha256`, `input_ciphertext_bytes`; pass only through coordinator-step env without shell interpolation. Coordinator requires all strictly before spawn, alongside actual haji84/manual/main/attempt1/SHA context. Unbound admission always fails; protected downstream job needs success. No enable input or upload activation.

- [x] Replace obsolete tests with behavioral assertions for unchanged fail-closed admission and dependency matrix; observe RED against current topology/body.
- [x] Replace unreachable private Python body with pinned key-free setup/image pull and one coordinator secret step. Artifact export remains absent/disabled until its separate concrete approval. Add necessary public CI path filters only; no PUBLIC8 command/resource change.
- [x] Run workflow-focused GREEN, then one complete suite. Preserve any default loopback EPERM and use only the previously approved exact unit-suite allowance if needed. Expected: all tests PASS, honest skip/Windows/hosted ordering status.
- [x] Document authenticated provenance versus hash integrity, unsupported owner key format, remaining durable export/main activation gates and actual measured test results.
- [x] Freeze exact changed bytes, base/full candidate tree, patch/manifests/evidence; retain previous freeze; hand a genuinely different model the whole change. Root publishes only after review. No self-approval or remote action here.

## Self-review and execution

Tasks 2 and 3 consume Task1's metadata/transport and Task2's observation schema; Task4 uses the coordinator's fixed environment names. No duplicated host execution logic or provider interface is introduced. All five review-focus items have owning tests. Root approved native execution and the three-input public transport clarification; no repeated routine approval is needed. Exact schemas and limits come from the spec; authenticated retrieval is an operator action, not a JSON trust flag.


## Actual results and remaining gates

- Task1 host21/21PASS and PUBLIC transport15/15PASS. Missing metadata and inherited transport were observed RED; ALL_PROXY-only bypass/unsupported transport were separately reproduced before repair.
- Task2 coordinator12/12PASS with real pipes, large partial writes, original deadlines, actual signal/cleanup, filesystem identity and PUBLIC47/104 integration. Initial10 missing-module assertions and actual coordinator TERM exit-15 were observed before fixes.
- Task3 owner16/16PASS; exact15-key context, real fixture observation, external launch/time commitments, pre-key context rejection, exclusive output and readback. Initial13 absent-helper failures and an ignored indented marker were observed RED. The helper's PUBLIC asset fixture setup mismatch was corrected using independent known fixture literals, never envelope-derived pins.
- Task4 workflow8/8PASS after7 expected RED failures against the obsolete topology. Unbound unconditional HOLD, success-only protected downstream job, no enable input and literal-false exact-file export remain.
- Whole suite: default211tests/8existing loopback EPERM errors/no assertion failures; same suite under approved local-loopback allowance211/211PASS, no skips,16.270s. Full failure and success outputs are preserved.
- The17-file candidate is frozen for genuinely different-model whole-change review. No technical/model review is self-approved. New-head PUBLIC CI, actual parked-main ordering observation, real non-secret DPAPI format/Windows compatibility, exact ciphertext transfer and private activation/export remain separate gates.

Execution ruling: root authorized a narrow parallel owner-helper implementation after a slot became free; it changed only tools/owner_bundle.py and its test. Final integration and the whole suite were performed by the coordinator author. Raw decoded log input is capped at16MiB; larger logs fail closed rather than truncate. Context/observation caps stay16KiB/2048bytes.
