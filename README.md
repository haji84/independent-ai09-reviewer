# Independent AI09 reviewer: public code, confidential source

**Status:** BLOCKED at P0. The pilot deliberately fails before checkout,
dependency installation, secret access, decryption or inference. Fixed-subject
model reviews: **0/8 pilot, 0/104 full**. `DESIGN_APPROVAL=HOLD`,
`MERGE_AUTHORIZED=false`, `PUBLISHER_ENABLED=false`.

This repository intentionally contains only *public-safe* review bootstrap code. Do not commit the frozen source ZIP, its plan, raw AI responses, findings, credentials, or owner-only key.

## Private by encryption, even with a Public repository
- The frozen 47-file / 104-chunk source ZIP must enter GitHub **only as AES-256-GCM ciphertext** `sealed/ai09-private-bundle.aesgcm`. The authenticated decryption gate verifies its original SHA-256: `9cf979733d8d4753023b1dd239ba4a5f3be2e0a6a3216c9dda206c089a2b6aa5`.
- The 256-bit master secret is installed *only* as `AI09_BUNDLE_KEY_B64` in the protected `ai09-private-pilot` Environment. Never put it in repository secrets, commits, issues, PR comments, logs, or artifacts.
- Runner-only decrypted sources and raw receipts live in temporary storage. Only AES-256-GCM sealed receipts may be exported as workflow artifacts. Domain-separated keys prevent source and evidence cross-use.
- Manual run on `main` only, read-only GitHub token, no writes, no publishing and no merge authority. The 8-chunk pilot is NOT an approved 104-chunk full audit.
- **Public is still public:** the workflow code, timing, logs, and encrypted bytes remain observable. Confidentiality assumes the key is private and trusted workflow code/branch are protected.

## Admission remains closed
Do not dispatch the parked workflow. The owner-managed key and main-only
`ai09-private-pilot` Environment are already installed, as recorded in the
[Issue #3 owner amendment](https://github.com/haji84/independent-ai09-reviewer/issues/3#issuecomment-6431408757).
Do not repeat that installation or disclose the key. Its retained
private execution steps are **unsafe if the first HOLD is removed**: private
tests/planning inherit the decryption key in the same step, have network/host
access, and can modify later sealing and artifact files. Redirecting stdout and
using an `.aesgcm` extension do not establish isolation or authentic encryption.

See [P0 evidence and restart gates](docs/architecture/public-boundary.md).
Reopening requires the reviewed isolation implementation, adversarial isolation
evidence, protected main/workflow, the current owner authorization and independent
technical-review gates, and verified storage/cost limits. The later owner policy
names haji84 as the sole human approver; it does not create a formal GitHub
APPROVED event. Confidential ciphertext installation and actual private activation
remain separate. Never put a key or source ZIP in this repo, Issue, PR, or chat.
The parked workflow is intentionally non-runnable.

The HOLD applies to this workflow revision; older revisions/runs require separate
inspection. If any public output leaks private material, stop execution and
evaluate key rotation and history contamination with the owner.

## Public verification
Use the supported Python version noted in `requirements-public.txt` in a fresh
virtual environment:

```sh
python -m pip install --require-hashes -r requirements-public.txt
python -m unittest discover -s tests -v
```

Tests use synthetic public subjects only; the frozen ZIP is never needed. These
tests and a public-bootstrap model review do not count as private-subject review
receipts or formal GitHub approval.

The separate Linux CI job runs `python3 -I tools/sandbox_probe.py` using Docker
and public synthetic fixtures. Missing Docker is a failure, not a skipped PASS.
The following `tools/data_driver_probe.py` exercises eight public toy chunks
against a fake loopback server, privately captures the binary response, verifies
it against independent host expectations and encrypts the exact verified bytes.
Tampered context, trailing output, overflow and an escaped child must fail.
All evidence is explicitly SYNTHETIC; actual-model counts remain zero.

The owner approved this data-only implementation and public synthetic tests.
The recovered original plan now has an independently pinned read-only verifier:
`frozen_plan.verify_plan` validates all104 spans and47 selected sources before
`prepare_pilot_batch` selects000..007. The legacy production loader still fails
with `FROZEN_PLAN_SCHEMA_UNVERIFIED`; no workflow calls the new frozen host path.
Windows capture is disabled. Linux CI must verify process/container behavior.
The production pilot HOLD stays in place. See the
[architecture and activation gaps](docs/architecture/private-execution-proposal.md).

`source_archive.py` provides bounded, data-only ZIP reading with the fixed
original hash and48 regular members (47 selected sources plus the manifest).
It preserves exact binary contents,
checks headers/ranges/DEFLATE EOF/CRC and returns immutable data without file
extraction or code execution. Its tests use public toy archives. The actual
fixed ZIP and original104-chunk mapping were separately checked in the recovered
input compatibility stage; those earlier offline checks are not model receipts.
The original inputs remain unchanged. Opaque plan-byte preservation alone does
not parse, authenticate or regenerate a plan.

The public CI attempts eight real Ollama/qwen3 calls on fixed public toy
chunks and the mandatory context-limit rejection via `tools/public_model_smoke.py`.
It verifies release/model bytes before
offline container launch and checks version, model digest, exact request and
response contract after confirmed teardown. It has independent disk/time/CPU/
memory bounds and no GPU, provider, permission or resource-limit fallback.
The latest observed outcome is recorded in Issue #3. A successful toy call
contributes **zero** frozen-subject receipts. Raw toy receipts are retained only
in host memory. The shared controller seals the complete packet and host evidence,
creates one exclusive0600 ciphertext file in a private0700 temporary directory,
then reopens, hashes, decrypts and semantically verifies those actual bytes.
The PUBLIC test removes its temporary directory normally; only host-derived
metadata/hashes are logged, with no artifact/cache upload.

`pilot_host.prepare_runtime()` receives no input or key. It yields an opaque,
single-use handle with the original540-second work deadline and600-second cleanup
horizon. `run_public_pilot` supplies fixed PUBLIC data and its PUBLIC test key.
The separate `run_frozen_pilot` library entry derives its own expectations from
the original pinned archive and raw plan; it accepts no Batch, selector or hash
override. Its distinct evidence contract cannot be substituted into the PUBLIC
contract. Neither API is a private admission gate, model attestation or approval.
The host process, Docker daemon and caller-owned private output directory remain
trusted. A failed write can leave incomplete ciphertext; it is never acknowledged
as ready and is not overwritten on retry. These checks do not promise power-loss
atomicity or interrupt a blocked kernel filesystem call.

This host/export connection is a candidate awaiting its independent whole-change
review and fresh exact-head PUBLIC CI. Actual private counts remain **0/8 and0/104**.

The runner uses local Ollama `qwen3:1.7b` with no paid hosted model APIs. Model answers are unverified until provenance, all chunks, and findings are independently reproduced. No automatic approval or merge.
