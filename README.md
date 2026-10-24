# Independent AI09 reviewer: public code, confidential source

**Status:** BLOCKED at P0. The pilot deliberately fails before checkout,
dependency installation, secret access, decryption or inference. Fixed-subject
model reviews: **0/8 pilot, 0/104 full**. `DESIGN_APPROVAL=HOLD`,
`MERGE_AUTHORIZED=false`, `PUBLISHER_ENABLED=false`.

This repository intentionally contains only *public-safe* review bootstrap code. Do not commit the frozen source ZIP, its plan, raw AI responses, findings, credentials, or owner-only key.

## Private by encryption, even with a Public repository
- The frozen 47-file / 104-chunk source ZIP must enter GitHub **only as AES-256-GCM ciphertext** `sealed/ai09-private-bundle.aesgcm`. The authenticated decryption gate verifies its original SHA-256: `9cf979733d8d4753023b1dd239ba4a5f3be2e0a6a3216c9dda206c089a2b6aa5`.
- The 256-bit master secret goes *only* into the repository Actions secret `AI09_BUNDLE_KEY_B64`. Never put it in commits, issues, PR comments, logs, or artifacts.
- Runner-only decrypted sources and raw receipts live in temporary storage. Only AES-256-GCM sealed receipts may be exported as workflow artifacts. Domain-separated keys prevent source and evidence cross-use.
- Manual run on `main` only, read-only GitHub token, no writes, no publishing and no merge authority. The 8-chunk pilot is NOT an approved 104-chunk full audit.
- **Public is still public:** the workflow code, timing, logs, and encrypted bytes remain observable. Confidentiality assumes the key is private and trusted workflow code/branch are protected.

## Admission remains closed
Do not register the bundle key or dispatch the parked workflow. Its retained
private execution steps are **unsafe if the first HOLD is removed**: private
tests/planning inherit the decryption key in the same step, have network/host
access, and can modify later sealing and artifact files. Redirecting stdout and
using an `.aesgcm` extension do not establish isolation or authentic encryption.

See [P0 evidence and restart gates](docs/architecture/public-boundary.md).
Reopening requires an owner-approved isolation design, independent review and
adversarial isolation evidence, protected main/workflow changes, a legitimate
different GitHub reviewer's approval on the latest commit, and verified cost
limits. Only after these gates may the owner separately authorize secret and
verified ciphertext installation. Never put a key or source ZIP in this repo,
Issue, PR, or chat. The current workflow is intentionally non-runnable.

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
The original frozen-plan schema and chunk rules are unavailable, so its adapter
always fails with `FROZEN_PLAN_SCHEMA_UNVERIFIED`. Windows capture is disabled;
Linux CI must verify process/container behavior. The production pilot HOLD stays
in place. See the [architecture and activation gaps](docs/architecture/private-execution-proposal.md).

`source_archive.py` provides bounded, data-only ZIP reading with the fixed
original hash and 47-file requirement. It preserves exact binary contents,
checks headers/ranges/DEFLATE EOF/CRC and returns immutable data without file
extraction or code execution. Its tests use public toy archives. The actual
fixed ZIP has not been opened or modified; original compatibility and the
104-chunk mapping remain unverified. Opaque plan-byte preservation does not
parse, authenticate or regenerate a plan.

The runner uses local Ollama `qwen3:1.7b` with no paid hosted model APIs. Model answers are unverified until provenance, all chunks, and findings are independently reproduced. No automatic approval or merge.
