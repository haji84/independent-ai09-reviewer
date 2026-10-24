# Data-only private execution — implementation approved, activation closed

Status: owner approved the data-only design and public implementation/synthetic
tests in this task on 2026-10-25 JST. NOT AUTHORIZED FOR PRIVATE DATA.
Authority: Issue #3; implementation approval is not final DESIGN_APPROVAL.
The production pilot admission failure remains unchanged. Counts remain 0/8 and
0/104. No new model/provider, credential, billing, permission or merge authority.

## Approved implementation direction

Replace execution of encrypted Python with a public, reviewed, data-only driver.
The driver reads the original frozen ZIP and authenticated chunk plan as bounded
data. It never imports, runs tests from, or executes any code from that bundle.
This retains the immutable subject, original SHA and 104-chunk plan. The exact
plan schema/compatibility must be checked inside the approved private boundary;
it is currently unavailable and must not be guessed into a claimed PASS.

Executing the existing private harness in Docker is an alternative, but it can
forge receipts or impersonate a model endpoint. It also needs a safe export path
after hostile descendants stop. The separate-model design review recommends
the smaller data-only trust surface. Keeping networked host execution is rejected.

## Proposed boundary

1. Before secret access, prefetch and verify immutable Python/Ollama/model bytes.
   Prove the model digest and independent model identity. No paid inference API.
2. A trusted host step authenticates/decrypts the bundle, checks the original
   ZIP SHA, and makes only the data needed for review available read-only.
   Untrusted bundle code never runs in a key-bearing process or a subprocess.
3. An immutable public driver and loopback Ollama run in a resource-limited,
   non-root, network-none container. No key, GitHub command-file environment,
   Docker socket, host PID namespace, writable host mount or sealer is exposed.
   Python starts isolated from private cwd, sitecustomize, PYTHONPATH and plugins.
4. The trusted driver records the actual HTTP request/response bytes, verified
   model metadata, target/chunk/input hashes and timestamps. Model output is
   untrusted JSON data; it cannot request tools, code execution or approval.
5. Candidate output channel: attach to trusted-driver stdout into a bounded
   binary host pipe, with Docker daemon logging disabled. Nothing from this pipe
   reaches Actions logs/command files directly. After container termination the
   host verifies completeness, strict response schemas and context bindings,
   then encrypts evidence before export. This channel still needs implementation,
   adversarial testing and independent review before activation.

Do not use “stop container, then copy tmpfs receipts”: tmpfs is removed at stop,
and Docker documents tmpfs copy limitations. A container flag alone does not
prove confidentiality, including kernel/daemon compromise, swap and timing.

## Authorized investigation in this PR

`tools/sandbox_probe.py` and its public fixture evaluate only synthetic canaries.
The pinned image is the official Linux amd64 Python 3.13 slim-bookworm manifest
`sha256:4cea12ab7d78a3312c85f8cab19b6971d4fe9704da25443986c0bc20a6678850`,
resolved from the Docker Registry on 2026-10-24. Pull is before execution;
container creation uses `--pull=never`.

The probe checks effective inspection policy, absence of inherited synthetic
credentials/GitHub environment, blocked external TCP, working private loopback,
root/input write/rename/unlink denial, empty effective capabilities, setuid denial,
seccomp/no-new-privileges, file-size limits, host-canary integrity, disabled daemon
logs, parent/descendant shutdown and a forced wall-time stop. Missing Docker or
unexpected controls fails the Linux job. No model, private source, secret, actual
receipt or artifact upload exists in this experiment.

The additional `tools/data_driver_probe.py` uses eight PUBLIC toy chunks and a
fake loopback HTTP server, not a model. It exercises normal capture/verification/
in-memory encryption, swapped attempt, trailing JSON, output overflow and an
escaped child/timeout. It uses the same inspected Docker policy and never
exports an artifact or raw pipe. `data_driver.py` reconstructs exact requests
from independent host expectations. `loopback_client.py` bounds HTTP headers,
bodies and the total deadline. `confidential_capture.py` discards stderr and
requires positive host-owned container-stop verification before returning bytes.
The controller seals only those verified bytes, with a public synthetic key.

This is a synthetic contract implementation, not frozen-plan compatibility or
actual inference provenance. Original archive compatibility, original-plan adaptation,
verified Ollama/model launch, inventory/receipt timestamps and production
orchestration remain activation gaps. No REAL evidence promotion exists. Windows
capture fails closed; process/container behavior requires Linux CI. Tests do not
prove all resource exhaustion or isolation against kernel/daemon compromise.

References: [network none](https://docs.docker.com/engine/network/drivers/none/),
[container controls](https://docs.docker.com/engine/containers/run/),
[tmpfs lifetime/swap](https://docs.docker.com/engine/storage/tmpfs/),
[copy limitations](https://docs.docker.com/reference/cli/docker/container/cp/),
[logging](https://docs.docker.com/engine/logging/configure/),
[Ollama generate body contract](https://docs.ollama.com/api/generate).

## Bounded implementation plan

1. Test strict bounded JSON, a data-only chunk/request contract and independent
   host receipt verification. Host expectations, not worker fields, determine
   run/attempt/commit, original source/plan hashes, chunk bytes and request options.
2. Implement Linux-only bounded binary capture. Return nothing until the
   host-owned Docker identity is confirmed stopped; timeout, excess output and
   teardown uncertainty fail closed. Windows capture is unavailable.
3. Exercise a fake loopback model inside the existing offline Docker policy,
   capture without daemon logs, verify exact bytes and encrypt those same bytes
   in memory. The evidence class is SYNTHETIC and cannot become REAL by changing
   a worker field. No private inputs or model downloads are part of this test.
4. Obtain a different-model public-code review and latest-head CI. Preserve the
   pilot HOLD. The production plan adapter unconditionally raises
   FROZEN_PLAN_SCHEMA_UNVERIFIED until the original schema and chunk rules are
   supplied and validated; synthetic fixtures are not compatibility evidence.

## Approval still required for activation

Private activation, legitimate separate GitHub
approval, successful latest-head CI, account storage/budget checks and separately
authorized key/ciphertext installation remain distinct gates. Public standard
runner minutes are free under current GitHub documentation; artifact/storage
usage and account limits still require verification before private evidence runs.

## Original-plan location investigation (2026-10-25 JST)

The owner requested autonomous investigation before asking for a location.
Read-only inspection covered all three remote branches, all 31 then-reachable
commits including historical/deleted paths, both existing PRs and their comments,
Issue #3 and comments, and exact filename/ZIP/SHA searches across accessible
owner repositories/issues/PRs. The linked AI-/1831 issue's 95 comments identify
PR #2 as a separate confidential 104-chunk effort, not the older Node reviewer.
No original plan, schema, reviewer.py or checkpoint_runner.py was found in that
target Git history. Searches found the plan reference only in Issue #3/current
bootstrap records. GitHub code search covers indexed default branches; the
target's other branches were additionally inspected through Git directly.

The concrete historical reference is `evidence/frozen-review-plan.json` in
[the original pilot workflow](https://github.com/haji84/independent-ai09-reviewer/blob/28c9d071c87f1eb4cdbc1c2f46ab96239b4e0196/.github/workflows/ai09-public-safe-pilot.yml).
It invokes a private `reviewer.py plan` and compares its output, but defines no
keys, chunk ordering, byte/newline rules or expected original-plan hash. The
encrypted payload is not in Git. This is evidence of an unresolved location,
not proof that a specification does not exist outside the inspected sources.

Additional implementation, within the approved data-only architecture:

- Add `source_archive.py` and `tests/test_source_archive.py`: hardcoded original
  ZIP hash, bounded central-directory preflight without ZipFile allocation,
  bounded STORED/DEFLATED reads, exact path/byte preservation, no extraction,
  imports, execution or newline/encoding normalization. Validate 47 regular
  files without guessing the 104-chunk mapping. Explicit directories are data.
- Preserve opaque original-plan bytes/hash under a size bound without claiming
  schema validity. Keep `load_frozen_plan` blocked. Tests use public toy ZIPs
  and patch the hash only in test code; no production hash-override argument.
- Run adversarial tests, separate-model review, latest-head CI and Issue #3
  write-back. No private inputs, keys, real-model runs or activation in this step.

`source_archive.py` now implements this read-only data stage using a checked ZIP
subset parser, without allocating ZipFile objects. It also validates local
headers/data descriptors, non-overlapping contiguous compressed ranges, complete
raw-DEFLATE EOF/size/CRC, and rejects unused/trailing compressed bytes. All
source file bytes remain undecoded and immutable; ZIP filenames are decoded as
required by the ZIP format but never normalized. Opaque plan hashing is neither
authentication nor schema validation. No workflow activation is connected to
this reader, and original fixed-ZIP compatibility remains untested.

Supported structure intentionally excludes ZIP64/multidisk, encryption, special
files, other compression, concatenated/self-extracting ZIPs, unexplained gaps,
and ambiguous EOCD signatures in comments. If the original uses an unsupported
structure, stop and review the parser; do not rewrite the original archive.
Public toy tests cover both streaming data descriptors and seekable ZIPs,
binary/newline preservation and adversarial structures. Independent advisory
review found no concrete defect; latest CI evidence belongs in Issue #3.

## Bounded public-model runtime experiment

The next independent stage uses only a fixed PUBLIC toy chunk and actual local
qwen3:1.7b, never the frozen ZIP/plan or bundle key. Standard public Ubuntu
runner compute is free under GitHub's current billing documentation; no cache,
artifact, larger runner, billing setting or private activation is involved.
Account storage/budget approval for future private evidence remains unresolved.

Implementation plan: `runtime_assets.py` plus tests pins the complete official
Ollama 0.34.0 tar SHA before parsing; bounds streamed tar metadata/skipped data,
selects at most256MiB of CPU files, rejects unsupported tar records and resolves
safe aliases to regular bytes without host symlinks. It verifies the raw pinned
qwen manifest and every config/layer size+SHA in Ollama's read-only model layout.
No extracted binary, installer or ldd is run on the host. Unsupported dependencies
or a limit failure stop; there is no GPU/all-library or resource-relaxation retry.

`tools/public_model_smoke.py` will admit disk/time budgets before downloads, use
one overall deadline and one attempt, and inspect a distinct bounded model
profile (4GiB RAM/swap, two CPUs,128 PIDs,64MiB scratch) with the same no-network,
non-root, read-only, no-capability, no-socket/no-host-write/no-daemon-log controls.
A public fixture calls the real loopback service once with finite generation/
context/thread limits and records raw request/response, version/tags and timing.
The host verifies its own context/digests and confirms container teardown before
accepting the packet. Only fixed metadata is logged; raw receipts are discarded,
so later independent raw-receipt replay is unavailable for this experiment.
SYNTHETIC input classification and fixed-subject counts0/8,0/104 never change.
This is observed inference under trusted runner/container assumptions, not a
cryptographic model-execution attestation or formal GitHub approval.
Regular local filesystem operations are assumed to complete: deadline checks
surround bounded reads/writes/hashing, but cannot interrupt a blocked kernel
filesystem call. Network downloads use a separately timed child process.
