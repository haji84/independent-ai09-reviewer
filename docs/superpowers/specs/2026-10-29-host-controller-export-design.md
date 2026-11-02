# Host controller and verified encrypted export

Status: bounded implementation candidate; not private activation. Different-model
technical design review completed. Initial whole-change review identified the
ancestor-rename P2 below; its repair awaits re-review and exact-head CI.
Base: PR #2 `fc9db6b22bafaf66e0cb5ea706d36bf5fa607e6a`, tree
`3c82e39e96f5b6cecdb4df8fbe3c208d1aabd237`.

## Intent and established authority

Connect the already approved data-only input adapter to the existing inspected
model container and to a durable encrypted evidence file. Reuse PR #2, the
existing model/runtime pins, capture limits, deadlines, encryption format and
owner-only approval policy. Test with PUBLIC generated inputs and the existing
PUBLIC model demonstration. The parked production workflow and production
admission stay closed throughout this implementation and its public CI.

Issue #3's latest owner amendment records that the main review-policy change,
owner key and main-only protected `ai09-private-pilot` Environment are installed.
Those installations are not requested again. Actual ciphertext installation,
runtime key matching, storage conditions and private activation are separate.
No formal GitHub APPROVED event is inferred from model review or chat approval.
The owner's renewed completion instruction authorizes ordinary implementation;
this design does not expand permissions, data disclosure, provider or budget.

## Current code and approaches

`frozen_plan.prepare_pilot_batch` freshly verifies all104 original spans and
47 selected sources before selecting000..007. `tools/public_model_smoke.py`
already downloads pinned public runtime assets, creates/inspects the offline
container, captures actual observations, proves stop, validates evidence and
performs an in-memory AES-GCM roundtrip. It then discards the ciphertext.
`pilot_batch` deliberately restricts its present evidence interface to PUBLIC
launch metadata; it is not a private admission or execution controller.

Chosen implementation approach: move that existing host lifecycle into one
shared public module, retain the PUBLIC entrypoint's fixed test input, add a
separate frozen-input entrypoint deriving its own expectations, and export only
verified ciphertext. This keeps one launch/stop path under actual existing CI.
Duplicating a private Docker runner creates two controls that can diverge.
Removing the legacy workflow HOLD is rejected: its old private-code execution
is unsafe and is not the approved data-only design.

## Proposed interfaces and boundaries

### 1. Shared runtime and capture

New `pilot_host.py` owns the existing prepare/runtime lifecycle and one internal
batch execution path. Preparation selects and verifies the current pinned CPU
runtime/model before any future private entrypoint receives private data or a
key. A host-owned prepared runtime retains the original overall540s deadline
and600s cleanup horizon; preparation time is not reset for inference. The guest
keeps450s and the existing capture cap of2,000,000 bytes. Runtime/model files are
freshly verified before container creation.

`run_public_pilot` constructs the same fixed eight PUBLIC toy chunks itself.
It does not accept caller chunks, source hashes or a classification override.
`run_frozen_pilot` accepts original archive/plan bytes and host run identity,
derives its Batch through `prepare_pilot_batch`, and cannot accept an externally
constructed Batch, VerifiedPlan, selector or hash override. The library interface
grants no deployment, secret-access or private activation permission; no CLI or
workflow calls it in this unit.

The internal execution path uses the exact existing container profile, private
0700 staging parent and0444 single input file, public trusted guest/driver,
no-network/nonroot/read-only Docker, PATH-only Docker subprocess environment,
no secret/key/source ZIP/plan mount, disabled daemon logs and positive
kill/wait/inspect stop verification. No raw stdout/stderr reaches CI logs.
The encryption key is retained only by the trusted host and never forwarded to
the guest, process environment, arguments, inspection metadata or launch record.

### 2. Frozen-input evidence contract

Keep the current PUBLIC `evidence_envelope` and `verify_evidence` behavior strict
and unchanged. Add separate frozen-input functions that freshly derive expected
source/plan/chunk context from immutable raw bytes and require a distinct fixed
host launch classification. They share schema/size/timestamp/request/inventory
checks internally; public callers cannot opt into the frozen classification.
After decryption, verify against the original external inputs, run identity,
host-owned launch and actual host time window again. The complete captured
packet remains byte-identical in the envelope.

Contract-valid observations and a frozen input identity are not a cryptographic
model attestation, a finding-accuracy result, ownership approval or a formal
GitHub review. Public tests and the public smoke retain fixed-subject counts0/8
and0/104. Any eventual real count requires actual authorized runtime evidence.

### 3. Ciphertext-only durable export

The host validates the observation/envelope after positive stop and log checks,
seals it with the existing domain-separated AES-GCM purpose, unseals it in
memory and re-verifies semantics before writing. It creates one fixed-named
ciphertext file exclusively in a caller-owned0700 temporary output directory;
the file uses0600, is not an existing file/symlink/hardlink, and is never an
extracted plaintext source or receipt. Existing5,000,000-byte encrypted bounds
remain. Use bounded writes, file fsync, safe readback with stable identity,
ciphertext hash comparison, authenticated decryption and semantic verification
of the actual reopened bytes before returning success metadata.

The result exposes only safe metadata (ciphertext digest/length and validated
observation count), with raw values and paths hidden from repr/error messages.
No artifact upload, output command file or private evidence count promotion is
added. If write/fsync/readback/verification fails, do not acknowledge a ready
export or overwrite/delete an unrelated file. An encrypted incomplete file may
remain after an ambiguous failure; it must not be used as a verified export.
This does not guarantee power-loss durability or interrupt a blocked OS read.

### 4. Existing PUBLIC smoke as the actual integration test

Refactor `tools/public_model_smoke.py` to call the shared runtime/controller with
its unchanged fixed PUBLIC inputs and public test key. Export only into its new
private temporary directory, reopen/decrypt/reverify the actual file, then delete
the entire test directory normally. Keep existing metadata output and0 fixed
receipts. No artifact/cache upload or additional model call is added: the same
eight responses and mandatory context rejection exercise the new common path.

## Proposed source scope

1. Add `pilot_host.py`.
2. Add `tests/test_pilot_host.py`.
3. Extend `pilot_batch.py` with separate frozen-input evidence interfaces.
4. Extend `tests/test_pilot_batch.py`.
5. Refactor `tools/public_model_smoke.py` to the shared host path.
6. Adjust `tests/test_public_model_smoke.py` to preserve its behavioral checks.
7. Add the new module/test paths to existing public CI path filters only.
8. Update `docs/architecture/private-execution-proposal.md` with actual scope.
9. Correct stale README statements about completed input/key setup and preserve
   the remaining activation/real-receipt holds.
10. This design and a bounded implementation plan.

No `AGENTS.md`, original input, production loader, parked pilot, dependency,
model pin, resource limit, repository protection, secret or workflow authority
change is included. Any newly discovered need outside this list returns to root.

## Validation and independent review

Before implementation, obtain the different-model design review required by
AGENTS §1.3 and §3. Then meaningful RED/GREEN tests cover lifecycle ordering,
no key/canary propagation, stop/log failures before seal, fixed-input/host
context substitutions, altered launch class, complete packet preservation,
exclusive file creation, link/alias/identity rejection, size limits, write/fsync/
readback failure, corrupted/authenticated-but-invalid evidence, and retry refusal
for an existing output. Use real temporary filesystem I/O and actual bounded
subprocess capture where appropriate; use generated fixtures, never private data.

Run the affected/full public boundary suite, a fresh different-model whole-change
review, then root publishes in existing PR #2 and observes one new-head public CI.
The existing Docker/model CI tests the shared path on a real PUBLIC model. A
failed CI is retained and diagnosed; prior successful runs are not substitutes.
No private input/model invocation or extra automatic corrective retry is budgeted
by this design. The exact reviewed hashes, commands and outcomes belong in the
carrying PR record; no unobserved merge or runtime result is written in advance.

## Remaining activation work after this unit

The data-only encrypted input wrapper/loader, owner-runtime ciphertext creation
and placement, storage/quota evidence, final current-SHA owner gate and an actual
main-only private workflow must still be completed/reconciled. Owner DPAPI key
storage on Windows is not assumed accessible from this cloud executor. Existing
key installation must not be repeated or its value printed. Actual8 then104,
claim reproduction and final design approval remain unmet until observed.

## Implementation conditions from the independent design review

The orchestrator selected `gpt-6.1-terra`, different from the Astra design and
implementation author. Its technical design response accepted the bounded scope
subject to the following conditions. The model selection is observable; a serving
digest or independent provider attestation is not. No GitHub APPROVED, private
activation or final DESIGN_APPROVAL is inferred.

- Preparation is an explicit context manager receiving no input/key. The yielded
  handle has no caller-supplied configuration and is accepted by live identity,
  once, before the original deadline. Expired/closed/used/forged handles fail.
- The host independently owns launch metadata and time windows. Validation proves
  their consistency with externally supplied expectations, not runtime authenticity
  against a malicious trusted host or key holder.
- A timed-out Docker create has an uncertain outcome. Cleanup always attempts
  removal of the unique generated name and verifies its absence, even when create
  never returned successfully. Cleanup failure wins over a primary exception.
- Export walks directory components without following links; retains directory and
  parent descriptors; requires caller ownership and0700; creates the fixed0600
  file exclusively; handles partial/zero writes; checks fsync; and verifies inode,
  type, ownership, mode, size, link count and timestamps through actual reopened
  descriptor and current directory entries. A hostile same-user host is outside
  this boundary, and no power-loss atomicity is claimed.
- The packet capture cap and base64-expanded envelope cap are separate. PUBLIC
  integration remains eight PUBLIC responses and zero fixed-subject receipts.

## Bounded implementation plan and observed local checks

1. Add separate frozen evidence functions, preserving PUBLIC signatures/class.
   Derive expectations freshly from the complete original raw inputs on both
   construction and verification. New8 tests failed before implementation;
   existing9 tests passed. The37 contract/input tests then passed with no skips.
2. Extract the shared host, staged-input, capture/stop/log path. Add two-phase
   single-use preparation and fixed PUBLIC/separate frozen entrypoints. New15
   host/export tests failed because the controller did not exist, then passed.
3. Add ciphertext-only exclusive write/readback. Exercise actual filesystem I/O
   and actual bounded subprocess capture while substituting only external
   downloads/Docker with PUBLIC fixtures. Additional boundary checks cover a
   deadline expiring during write, preserved preparation time, and the complete
   generated frozen-input path with a separate test key. No real model ran locally.
4. Route the existing PUBLIC smoke through the shared controller. Two new tests
   showed the old smoke never wrote/read back a ciphertext file and ignored the
   new export-failure boundary. Both passed after the refactor, alongside its
   eight previous tests. The PUBLIC model call count and workflow steps stay fixed.
5. Add only the new module/test to the existing public workflow's path filter.
   No production workflow, dependency, model/runtime pin, resource cap, secret,
   permission or branch policy changes.
6. Run the complete unit suite, freeze exact bytes, obtain a different-model
   whole-change review, and publish in existingPR2 only after findings are handled.
   Fresh exact-head PUBLIC CI is still required. Private activation is separate.

The first additional positive-path test exposed a test fixture key-length typo
(34 instead of32), corrected in the generated fixture before its successful run;
this was not a product defect or RED→GREEN product evidence. The earlier full
suite in the default sandbox encountered socket EPERM in existing loopback tests;
that environmental failure is retained and not reported as a suite PASS.

Final local integration verification used the same complete unit command with
local loopback sockets permitted: **160/160 PASS,0 SKIP,0 failures/errors**,5.236s.
No Docker/model or private input/key was used; actual subprocess capture, local
loopback fixtures and filesystem/encryption checks ran. The initial sandbox
failure remains separate evidence. This result does not establish hosted actual
PUBLIC-model execution, private receipts or an independent code-review outcome.

### Independent whole-change review: ancestor-rename repair

The `gpt-6.1-terra` whole-change review reproduced a P2: renaming an earlier
ancestor during export left the final directory's descriptor valid under its
new path, so the original implementation could acknowledge ciphertext absent
from the caller's requested path. The trusted final directory assumption did
not close that gap. Its exact initial candidate, manifest and failure evidence
are preserved separately; the finding is not waived.

The repair retains the root descriptor plus every parent/name/child descriptor
and its device/inode/type identity. Each existing directory validation now
checks the root path and the entire chain, retaining the final directory's
ownership/mode and all existing file identity checks. A real rename at either
of two ancestor depths failed the new regression on the old code (two failed
subtests), then failed closed correctly after the repair. Descriptor sets were
identical before/after the regression (4 open both times). The complete repaired
unit suite passed **161/161,0 SKIP,0 failures/errors**,5.135s. No deadline, runtime,
private activation or authority setting changed. Rename after the last check or
after return remains outside an atomic guarantee.

Docker removal plus the subsequent absence listing is a point-in-time observation
of the trusted daemon. No live asynchronous-create fault experiment was run, and
the listing does not prove an in-flight create can never finish later. This
limitation is documented without adding an untested cleanup mechanism.
