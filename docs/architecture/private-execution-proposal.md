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

The first public-model run, Actions40125417922 at a8d95b9, passed all76 Linux
boundary tests and both existing synthetic probes, but failed during the model
response phase. It does not establish successful inference. Different-model
review reproduced two compatibility defects: omitted shared CPU libraries
`libllama-server-impl.so`/`libllama-common.so`, and rejection of the pinned API's
optional `prompt_eval_cached_count`. The original loader error was discarded,
so attribution of that CI failure to the missing libraries remains an inference.
Static ELF parsing of the SHA-verified official tar independently confirms
llama-server's DT_NEEDED entries include libllama-server-impl.so and
libllama-common.so.0. No extracted binary was executed on the host.

The final bounded corrective attempt adds only those CPU library families and
requires their presence, permits only an exact integer cached count in the
interval0..prompt_eval_count, and separates transport/schema failure codes
without exposing response or exception text. Regression tests fail before the
fix and pass afterward; unknown fields and all resource/security limits remain
enforced. If the next CI fails, stop automatic retries and record BLOCKED in
Issue #3. Successful public toy inference would still leave private receipts0/104.

# Public context rejection implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans
> for this bounded native implementation; independent model design/code reviews
> remain required by Issue #3. This is public implementation planning, never a
> replacement or edit of the original frozen-review-plan.json.

**Goal:** Reject oversized model inputs visibly instead of accepting a silently
truncated review, while preserving the original chunks and all activation gates.

**Architecture:** Bind explicit no-truncate/no-shift flags into the reconstructed
request. Observe one normal public toy response and one pinned context-limit
rejection under the existing inspected runtime, then independently verify the
raw rejection evidence on the host after container teardown.

**Tech Stack:** Existing Python stdlib/unittest, pinned Ollama0.34.0/qwen3:1.7b,
GitHub's existing public Linux CI; no additional dependency/provider/credential.

**Spec:** Issue #3 and the approved data-only design above. The owner's renewed
completion instruction authorizes ordinary public implementation and testing;
it does not authorize private activation, new permissions, billing or approval.

## Global constraints

- Preserve the fixed source SHA and original plan; do not rechunk or normalize.
- Keep FROZEN_PLAN_SCHEMA_UNVERIFIED and unconditional pilot HOLD unchanged.
- Keep 4096 context,2048 generation,2 threads and existing Docker/time limits.
- Public synthetic input only; no raw request/response reaches Actions logs.
- Evidence remains SYNTHETIC; fixed-subject counts remain0/8 and0/104.
- The previous CI correction sequence succeeded. This is a new planned missing
  control, not a retry of that failure; no additional automatic CI correction
  attempts are budgeted. A failed new CI is recorded BLOCKED without retry.

## Review focus

- A worker changing or omitting either flag must fail host request binding.
- An unrelated400,500,malformed/oversized/slow response must never count as a
  context-limit rejection; accept only the pinned error contract.
- Negative evidence must bind the exact host-known public input/options/context,
  rather than trust a worker-provided pass boolean or self-chosen input hash.
- Capture/deadline/log suppression/container teardown and inventory verification
  must cover both positive and negative requests with no new writable mount.
- A rejected request is not a completed review; no real/fixed receipt promotion,
  tokenizer attestation, original-plan compatibility or104 completeness claim.

## Bounded tasks

- [x] Add failing data-driver tests for explicit truncate=false/shift=false,
  exact reconstruction and rejection of flag tampering. Implement the flags
  without changing chunk bytes, context size or generation budget.
- [x] Add failing transport/probe tests for the pinned context-limit error,
  including unrelated status/body, missing/duplicate fields, bad types, limits
  and deadlines. Implement the smallest bounded400-only diagnostic path while
  leaving ordinary inference restricted to200.
- [x] Extend the existing public model guest/host to record and independently
  validate one deterministic oversized public input rejection after teardown;
  normal toy inference must still succeed. Add canary-suppression tests.
- [x] Run local tests/compile/diff checks, obtain different-model code review,
  publish within PR #2, and verify the new HEAD's CI once. Record exact outcome
  and remaining gates in Issue #3. Never relax a limit to obtain PASS.

The separate gpt-6-astra design review accepted this public-only implementation
with a strict pinned error contract: HTTP400, outer error string containing
JSON with an error object, exactly code/type/message/n_prompt_tokens/n_ctx,
code400, type exceed_context_size_error, context4096, bounded integer prompt
count at least4096, and the pinned message with matching counters. Generic400,
unknown nesting, extra OOM text and changed input/flags cannot establish PASS.
No original-plan/tokenizer/production attestation follows from this probe.

Local RED→GREEN evidence: missing flags were accepted before the fix; absent
rejection/host validators and a guest that emitted success without negative
evidence failed their new assertions. After implementation,90 tests ran with
85 PASS/5 Linux-only SKIP; compile and diff checks pass. Linux rejection behavior
was subsequently observed in CI40184971674 atd1c30a3: Linux90/90 PASS,
normal public toy inference1PASS and strict context rejection1PASS,HTTP400,
16103 prompt tokens versus4096 context; total42.36s. Artifacts0 and checked
raw/canary markers absent. No automatic corrective retry was used. This does
not establish every future input's tokenization or original-plan compatibility.

# Synthetic104 completeness implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans.
> This consumes host-owned normalized expectations; it never invents, parses,
> regenerates or replaces the original frozen plan.

**Goal:** Reject missing, duplicated or mismatched receipts across13 batches of8
using public synthetic data, preserving every exact raw packet for re-verification.

**Architecture:** `receipt_collection.py` verifies13 immutable host Batch values
and13 byte packets with the existing verifier, then constructs a deterministic
SYNTHETIC index plus base64 of the unchanged raw packets. A separate reader
re-verifies packets against externally supplied expectations and rebuilds the
complete canonical payload. Existing in-memory seal/unseal must preserve it.

**Tech Stack:** Existing Python stdlib/unittest and existing public_runner AES-GCM
functions. No additional dependency, file output, workflow step or model call.

**Spec:** Issue #3's13x8 completeness requirement and approved data-only design.
The different-model design review accepts this synthetic-only component.

## Collection constraints and review focus

- Exactly13 Batch objects with8 chunks each; flattened IDs exactly000..103 in
  order, common commit/source/plan, and host-selected run/attempt per batch.
- Repeated run/attempt across disjoint batches is valid. This is within-collection
  completeness, not a persistent cross-run replay/approval ledger.
- Preserve raw request/response bytes through their original packets. Do not
  trust metadata/index/counters found only in the candidate payload.
- Cap final canonical JSON at the existing2MB parser limit. Preflight raw packet
  types/lengths and base64 expansion plus a bounded index before parsing/encoding.
  Larger collections remain unsupported; do not raise capture/parser/seal limits.
- Immutable output classification: SYNTHETIC,synthetic_receipts104,fixed_subject_receipts0.
  No original47-file coverage, real inference, accuracy or approval claim.
- No partial success if any batch fails, including the last batch. Authenticated
  ciphertext with semantically invalid plaintext must still fail verification.
- Private adapter, fixed ZIP/plan, pilot HOLD, keys/permissions/billing unchanged.

## Bounded collection tasks

- [x] Test complete13x8 construction, raw preservation and immutable classification
  RED→GREEN; implement `assemble_synthetic_collection(expected_batches, packets)`.
- [x] Test missing/extra/reordered/duplicate packets, host mismatch and oversize
  rejection before parsing; verify no partial result. Implement strict preflight.
- [x] Test canonical payload/index/packet/type/attempt tampering RED→GREEN;
  implement `verify_synthetic_collection(payload, expected_batches)` using fresh
  verification and independent index reconstruction.
- [x] In public tests seal the exact immutable payload, unseal and reverify with
  external expectations. Reject authenticated but semantically invalid payloads.
- [ ] Run local checks, independent code review, one latest-HEAD CI in PR #2,
  and write actual results/gates to Issue #3. No automatic CI correction retry.

Ruling: use a2MB final encoded JSON cap, rather than4MB raw packets or a new
binary format. Base64 expansion and index must fit existing limits. This is the
smallest verifiable implementation; actual receipt-size compatibility remains
unproven until the original plan and approved private pilot become available.

The initial9 collection assertions failed because no verifier existed. The
implemented collection and reader now pass the full99-test local suite with
94 PASS/5 Linux-only SKIP. Tests include authenticated but semantically invalid
plaintext, and aggregate base64 expansion rejected before any packet parsing.
This introduces no file-based exporter or production runtime wiring.

# Recovered frozen-input compatibility (2026-10-27)

Owner-provided staging inputs now identify the fixed original ZIP and original
plan. Read-only audits by the implementer and gpt-6-astra independently checked
all104 chunk/source hashes and contiguous coverage of47 selected source files.
The ZIP has48 regular members: the47 selected sources plus one declared manifest.
The former47-member admission rule rejected the authentic unchanged archive.

Raw plan SHA256 isad7c9a7b6914670c82b436ede89d543e8e09a3c0902448c9378fb6ab1aaecf44;
the verified embedded canonical hash is24c5ba68496d129a47b005831e9b523ccb21a5b395f8f1693d7fe78e47a34e94.
Canonical consistency is distinct from raw-byte identity and signed provenance.
No original input bytes, paths or private implementation are copied into tests.

The approved additional repair is specified in
`docs/superpowers/plans/2026-10-27-frozen-input-compatibility.md`.
The source reader now admits the fixed48-member archive, without hash/count
overrides. `frozen_plan.verify_plan` independently pins exact raw plan bytes,
checks the recovered schema/canonical hash and source selection, then verifies
every original byte offset, source/chunk hash, UTF-8 slice and full coverage.

Original plan end_line is an LF-count boundary, not the final covered line.
`FrozenSpan` retains that unchanged boundary and byte offsets, alongside
covered_end_line. Normalized Chunk values contain the exact input bytes and
actual covered interval. Requests/findings therefore cannot cite an unreceived
following line. Chunk/span/plan representations hide private content and paths.

This is an offline input adapter only. The production loader and parked pilot's
unconditional HOLD remain unchanged. There is no private-model invocation,
encryption-key access, credential/permission/billing change or new artifact.
Fixed-subject model receipts remain0/8 and0/104; formal GitHub approval is still
required. Latest-HEAD CI for this additional repair remains pending.
