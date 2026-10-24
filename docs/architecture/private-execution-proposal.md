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
actual inference provenance. Original archive parsing, original-plan adaptation,
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
