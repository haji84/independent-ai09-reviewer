# Data-only private pilot connection — design proposal

Status: **PUBLIC-FIXTURE IMPLEMENTATION CANDIDATE; PRIVATE ACTIVATION HOLD**.
The original design received independent revision-2 technical review. The exact
implementation still requires independent whole-change review and new-head CI.
Author: implementation-side Astra agent. A genuinely different-model review of
these exact bytes is required before implementation. This document does not
authorize secret access, ciphertext publication, main integration, or execution.

Revision2 addresses both blocking findings in the independent Terra review of
`824a6cfc4afd3324aa39dfdda5b7c6ffe3cfb21f52e907e9917f4c86229c7f6b`.
That exact proposal, author receipt and blocking review are preserved under
`history/824a6cfc/`. The repairs define separately retrieved host-context
commitments for owner verification and an unbound HOLD job before the protected
Environment job. This revision still requires independent re-review.

## 1. Source basis and outcome

Final read-only GitHub retrieval during this design confirmed PR2 head
`462c35f3eff19194097d2f6e9c8dba0e391dfd50`, main
`482061676e769d9404d0d742a17fa1eeb6a63992`, PR unmerged and main protected.
Its actual tree is `54df4be13bd2265ad7715ad112b0f2b9011e9b99`, parent
`5c9c0fb83abfdb051b0d7cd8ae08bf1ddaafadeb`. Host/assets/parked workflow remain
the reviewed controller baseline. The now-published `sealed_input.py` was read
and its Git blob independently matched against the actual new tree:
`3019ca492a7715c729e5d6d44658751f94d85f11` (file SHA256
`f1d68b522ea474d0c29fefbd63450407204dae8c984afd8091851a265c638e99`).
This design consumes its real `seal_frozen_input(archive_raw, plan_raw, key)` and
`open_frozen_input(ciphertext, key)` APIs and `FrozenInput.archive_raw/plan_raw`;
it does not assume a new or different codec interface.

Primary policy evidence is [Issue3](https://github.com/haji84/independent-ai09-reviewer/issues/3)
and the latest appended [owner gate record](https://github.com/haji84/independent-ai09-reviewer/issues/3#issuecomment-6431408757).
The owner already installed the `ai09-private-pilot` Environment and its
Environment-only `AI09_BUNDLE_KEY_B64`, with main-only branches, haji84 review and
admin bypass disabled. Do not request that installation or another human again.
Actual runtime key equality, current data-only ciphertext, storage conditions and
private activation were explicitly not established by installation.

Relevant observed implementation:

| Source | Existing contract |
| --- | --- |
| `pilot_host.py:119–183` | One process-local, single-use handle; pinned public preparation; original 540-second work / 600-second cleanup clocks |
| `pilot_host.py:223–262` | Network-none model container; bounded capture; stopped/log checks and removal before export |
| `pilot_host.py:319–438` | Exclusive encrypted write, fsync, descriptor/ancestor checks, authenticated actual readback and semantic revalidation; frozen entry re-verifies all original inputs |
| `runtime_assets.py` | Fixed Ollama archive, manifest and five model blobs; bounded key-free download children; verified CPU extraction; no extracted host-code execution. Current `ProxyHandler({})` and two-variable child environment need the narrow transport correction below before managed-environment use. |
| `confidential_capture.py` | Actual bounded binary child capture with stop verification; CLI/process-group termination alone is not Docker containment |
| `.github/workflows/ai09-public-safe-pilot.yml` | First-step unconditional HOLD, then obsolete private-Python extraction/host execution; no Environment binding |

The parked workflow blob is `e52cd667e02d561149d34f973edc7f34f646a065`.
It must never be made active by merely deleting its HOLD. The next unit should
replace its unreachable legacy execution body with this reviewed data-only path,
while retaining a first-step unconditional HOLD until the separate final gate.

**Outcome:** a PUBLIC-fixture-tested connection from the existing Environment
secret and strict encrypted original input to the existing eight-observation host
and verified encrypted output. It should leave only real owner-environment input,
storage and activation verification to the final gate. It must not create another
model provider, private Python execution path, persistent daemon or review bypass.

## 2. Alternatives and selected approach

**A. Separate Actions prefetch and adoption.** Persist only pinned public raw
assets, rehash the full 1,433,537,033-byte archive and all five blobs, restage CPU
files, then mint a new handle. This is workable but needs a new cross-step
inventory, path/adoption contract and combined-clock authority. Merely putting a
secret in the adoption step environment does not solve secret handoff.

**B. A long-lived prepared host with a Unix socket.** Retains the handle but adds
cross-step process lifetime, socket ownership, framing, replay and orphan cleanup.
The current repository does not implement those surfaces.

**C. One trusted coordinator and one sanitized child within the same step —
selected for independent review.** The child performs the existing
`prepare_runtime()` and retains its handle in that context. Only after a bounded,
validated READY message does the coordinator read the key and send one bounded
key/ciphertext frame. No public-asset cache, adoption parser, timestamp handoff
between Actions steps or cross-step daemon is needed. All expensive preparation,
input wait, inference and export stay inside the child's existing clock.

This selection supersedes the earlier read-only preference for A because the
one-step pipe option was not part of the A-versus-socket comparison. It is a design
proposal, not an assertion that its implementation has already passed review.

### Exact confidentiality claim

The **coordinator is a trusted key-bearing process**: GitHub injects the step
secret into its environment at process creation. The design does not claim the
secret is absent from the whole runner before READY. The coordinator does no
network access, downloading, model startup or model inference. Its only Docker
operations are bounded cleanup of its recorded child-owned container.

The execution child and its public download subprocesses receive an explicit
environment allowlist, not a copy-and-delete environment. Besides interpreter
runtime names, preserve only explicitly supported inherited transport names when
present: `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY` and their lowercase
forms, `SSL_CERT_FILE`, `SSL_CERT_DIR`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`.
Do not print their values, manufacture credentials, alter routes, unset an
inherited proxy to obtain access, or disable certificate verification. Approved
transport configuration may include a proxy placeholder or credential; it is
allowed only for the trusted PUBLIC prefetch path, never model/container env.
The child receives no key,
original ZIP/plan, GitHub command-file paths, GitHub token or Actions credentials
before READY. The coordinator reads only the named public GitHub context fields
before READY and does not fetch or decode the secret value until afterward.

The existing downloader explicitly constructs `ProxyHandler({})` and strips
proxy/CA names in `download()`. The connection unit must narrowly replace that
direct-network behavior with inherited proxy handling and verified configured
CA trust, and extend its download-child allowlist accordingly. Preserve fixed
destination/redirect checks and hard timeouts. Use OpenSSL's `SSL_CERT_FILE` /
`SSL_CERT_DIR` default verified context; if only a requests/curl bundle is
configured, explicitly supply that bundle to the verified urllib TLS context
(requests before curl), rather than silently ignoring the configured trust.
Do not propagate those transport variables to `_docker`, `stage_cpu`, capture,
or the offline model. Their existing exact environment policies remain unchanged.
Managed-runtime policy/status were unavailable in this executor; that is not a
network-readiness or destination-authorization claim. No network CLI was run.

The reviewed host, its code, interpreter, kernel, Docker daemon and same-user
runner are trusted, as in the current host contract. This does not defend against
malicious same-UID code reading the coordinator's environment through `/proc`, a
compromised kernel/daemon or Python memory inspection. No stronger claim is made.

## 3. Small changes to the existing host

Keep the `prepare_runtime()` public signature, asset checks, downloads, CPU
staging, clocks and single-use identity validation. Do not introduce an asset
adoption API for this approach.

Allocate the unique `ai09-model-<32 lowercase hex>` container name inside the
prepared state before yielding its handle. `_observe` uses that same name instead
of allocating another one after it receives private input. Add:

```python
prepared_cleanup_info(prepared) -> CleanupInfo
```

`CleanupInfo` is immutable and contains only `container_name`, `work_deadline` and
`cleanup_deadline`; its repr contains no values. It checks the same live handle
identity and expiry without consuming it. It cannot execute work or recreate a
handle. The name remains host-generated; callers cannot supply a container name,
Batch, asset hashes, selector, deadline reset or alternative input pins.

This small public metadata surface lets the coordinator know exactly what to
remove if the child dies after creation. The child cannot create a model container
before READY because the current preparation only inspects the image and prepares
public files. The coordinator records the name before sending any secret frame.
Existing PUBLIC smoke uses the same host and must retain its behavior.

Add the actual `_observe` `host_start` and `host_end` values to the immutable,
repr-safe `PilotResult` as `host_start_ns` / `host_end_ns`. The existing
`launch_sha256` already derives from the host-owned launch object independently
of the encrypted envelope. These three values are available to the trusted
coordinator only after the existing validation/export path succeeds. No time or
launch expectation is recovered from the encrypted evidence to populate this
result. They provide the external commitment described in section7; they are not
hardware or cryptographic execution attestation. Existing PUBLIC output need not
print the added fields and its fixed-subject count remains0.
These are the existing `time.time_ns()` Unix-epoch observations, not the separate
monotonic deadlines carried by READY. Do not substitute or convert between them.

## 4. One-shot process protocol and execution order

New `private_pilot.py` holds the trusted coordinator, child loop and framing
helpers. `tools/private_pilot.py` is a small fixed dispatcher; production code does
not accept an alternative child executable, loader, provider or verifier callback.
PUBLIC tests may patch external boundaries inside their own fixture process.

1. **Admission remains outside private execution.** A separate job with no
   Environment binding unconditionally fails before checkout. The downstream
   Environment job requires that job's success and is therefore skipped while
   parked; it must not queue an Environment approval request. The proposed future enabled form
   requires manual dispatch on main, the existing protected Environment, haji84,
   the explicitly approved checked-out main SHA and exactly attempt1. No automatic
   corrective retry or inherited retry-budget reset is introduced.
2. Before any secret-bearing step, use the existing pinned checkout/setup and
   hashed Python dependency installation, plus a key-free pull of
   `policy.IMAGE`. Current `prepare_runtime()` inspects that image; it does not
   pull it. No later action downloads executable dependencies after secret access.
3. The coordinator validates public context and creates a fresh owned 0700 output
   directory `ai09-private-pilot-<run_id>-<attempt>` under trusted `RUNNER_TEMP`.
   Run ID and attempt are strictly numeric public GitHub fields, not model data.
   Existing directories are refused, never reused or overwritten. It records its monotonic
   start, starts one Python `-I -B` child with `close_fds=True`, a new process group
   and a literal allowlist (`PATH`, the interpreter library path if required and
   the explicitly supported inherited PUBLIC transport configuration above).
   Public run ID, attempt, commit, output directory and a fresh 128-bit nonce are
   the only initial context. No key, ciphertext content or original path is in
   argv or environment. Root imports resolve only from the reviewed public tree.
4. The child enters `prepare_runtime()`. It obtains cleanup metadata only after
   every existing check succeeds. It sends exactly one canonical JSON READY line,
   at most512 bytes, then waits for input inside the same prepared context.
5. READY has exactly `v=1`, `kind="READY"`, the parent's nonce, the host-generated
   container name, and integer monotonic work/cleanup deadline nanoseconds. The
   coordinator rejects duplicate READY, extra keys, bad types, extra lines, wrong
   nonce/name, malformed deadline values, early final output, EOF,
   or an overlong/noncanonical frame. This is trusted-process control metadata,
   not an independent execution attestation.
   Effective deadlines are always the minimum of the child's valid values and
   the coordinator's own absolute ceilings. A normal later child start is not an
   error; it simply cannot extend the coordinator's budget.
6. After valid READY is stored, the coordinator reads only the fixed repository
   path `sealed/ai09-private-bundle.aesgcm` through bounded no-follow descriptor
   reads. This keeps the existing placement contract but accepts only the new
   strict data envelope; historical ciphertext compatibility is not assumed.
   It verifies the
   owner-approved ciphertext SHA256 and length before reading the key. File and
   ancestor identity must be stable; no filename or external URL comes from model
   output. Existing source/plan pins are never replaced by this ciphertext hash.
7. Only then read `AI09_BUNDLE_KEY_B64`. Require canonical standard base64 of
   exactly32 bytes. Reject invalid padding/pad bits by re-encoding comparison.
   Never copy the general process environment or include the value in an error.
8. Send exactly one binary frame through child stdin: fixed versioned magic,
   nonce, 32 key bytes, fixed-width ciphertext length and ciphertext bytes. Its
   maximum is the codec's actual bound:
   `min(public_runner.MAX_ENCRYPTED, data_driver.MAX_PACKET + len(public_runner.MAGIC) + 12 + 16)`.
   Do not import a nonexistent public `MAX_CIPHERTEXT` constant. Close stdin.
   No secret file, named pipe, socket, shell interpolation or command-file value
   is used. Child validates lengths before allocation and requires EOF after the
   frame; truncation, trailing data, a second frame or expiry rejects the run.
9. The child calls `sealed_input.open_frozen_input`, then the unchanged
   `run_frozen_pilot` with those original raw bytes, its key and the live prepared
   handle. Both loader and host freshly verify all47 sources/104 spans. Only
   chunks000–007 enter the existing container. No untrusted bundle code is
   extracted, imported or executed. The existing fixed-model/limits/stop/export
   conditions remain mandatory.
10. After actual readback and semantic revalidation succeed and the prepared
    context exits cleanly, the child sends one bounded canonical DONE line and
    exits0. DONE carries only nonce, ciphertext SHA/bytes, `observed_responses=8`,
    host-owned `launch_sha256`, `host_start_ns` and `host_end_ns`;
    it contains no paths, plaintext packet, finding, source snippet or key. Host
    `fixed_subject_receipts=0` remains unchanged; the wrapper cannot grant owner
    approval or promote the PUBLIC fixture into private receipts.
11. The coordinator requires exact READY→DONE→EOF, child exit0, no extra output,
    the correct nonce and the fixed result schema. It reopens only the exact
    ciphertext output, verifies size/hash/identity against DONE, then emits only
    the canonical allowlisted host-observation metadata specified in section7
    and fixed success metadata. This observation is committed to the GitHub job
    log before any eventual artifact upload. Any ambiguous child completion or local-read failure
    fails closed. Secret/key/data objects are not kept globally; no secure Python
    zeroization promise is made.

The coordinator must never forward child stdout/stderr verbatim. Both are pipes
drained concurrently: stdout has a4096-byte total cap across control frames;
stderr is counted and discarded under a1024-byte cap, with any nonempty stderr
making the run non-ready. Exceeding either cap terminates the child; no raw bytes
are included in public errors. All public failures use a fixed allowlisted code
or `PRIVATE_PILOT_FAILED`, with no exception chaining, argv, path or traceback.

## 5. Deadlines, duplex I/O and cleanup

The current host's540/600 clocks include its public downloads, input waiting,
capture, output verification and normal cleanup. They are never refreshed at
READY, after decoding or at export. The input reader uses the prepared state's
remaining work time, not a new timeout. Existing capture remains at most480 seconds
and additionally bounded by the remaining work time; the guest retains its own
existing bound. No resource or model-call limit is increased.

The coordinator has its own absolute work ceiling at `parent_start+540` and
cleanup ceiling at `parent_start+600`; a child-reported later deadline cannot
extend either. Child startup therefore consumes the parent's budget. The small
startup offset may make the parent abort earlier than the child's clock, which
is acceptable. Deadline metadata only tightens the limit; it is not authority to
reset it. Compare monotonic values on the same Linux runner.

Use nonblocking descriptors with selectors for both control reads and secret
writes. Drain output while writing the bounded ciphertext, handle partial writes,
and enforce absolute remaining time on every iteration. A blocked pipe, EOF,
extra byte, output flood or cancelled run must not wait indefinitely. Never call
`communicate()` with an unbounded buffered response or depend on pipe capacity.

On any failure the coordinator first marks the result unusable and stops sending
input. It requests child termination once; the child installs a minimal
termination handler that raises a fixed interruption inside the host context so
the existing `finally` blocks can stop/remove the container. The coordinator also
has a reaper for the already-recorded exact random name: credential-free bounded
`docker rm --force` and `docker ps --all --quiet --filter name=^/<name>$` only.
No broad container listing/removal or name supplied by private data is accepted.
The reaper and child wait use the parent's remaining cleanup budget. A hard-kill
fallback and process wait are bounded; no success metadata follows any aborted,
ambiguous or unverified cleanup path, even if ciphertext bytes remain on disk.

Normal success still requires the existing positive stopped state, suppressed
Docker logs, verified removal and encrypted readback. Parent emergency cleanup
observes only point-in-time daemon absence. It does not prove an asynchronous
create can never complete later, nor prove all grandchildren died after a fatal
interpreter exit. Such paths stay `CLEANUP_UNVERIFIED`, never export-ready. Host
power loss, SIGKILL of the coordinator or uninterruptible filesystem calls cannot
be made safe by a Python `finally`; do not claim otherwise. A workflow cleanup
step may repeat only the same recorded run-owned cleanup, without secrets, as a
best-effort defense. It cannot turn a failed result into PASS.

## 6. Safe parked workflow and final export choice

After independent design and code review, replace the old unreachable body with
the new data-only sequence. Keep `workflow_dispatch`, main guard,
`contents: read`, pinned actions, no persisted credentials, concurrency without
cancel-in-progress and unconditional HOLD. The HOLD belongs to an **unbound
admission job**, not to the Environment-bound job. GitHub evaluates an
Environment's protection before sending its job to a runner, so a first-step HOLD
inside that same job could still request an unnecessary owner review. GitHub's
documented `needs` pattern places a deployment after successful prerequisite work
and then Environment protection. Sources:
[deployment environments](https://docs.github.com/en/actions/concepts/workflows-and-actions/deployment-environments)
and [using environments to manually trigger jobs](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow#using-environments-to-manually-trigger-workflow-jobs).

Required parked job topology:

```yaml
jobs:
  admission:
    if: github.ref == 'refs/heads/main' && github.event_name == 'workflow_dispatch'
    runs-on: ubuntu-24.04
    timeout-minutes: 1
    permissions: {}
    steps:
      - name: Private activation remains closed
        shell: bash
        run: |
          echo 'PRIVATE_ACTIVATION_NOT_AUTHORIZED; DESIGN_APPROVAL=HOLD'
          exit 1
  isolated-pilot:
    needs: [admission]
    if: ${{ needs.admission.result == 'success' && github.ref == 'refs/heads/main' && github.event_name == 'workflow_dispatch' }}
    environment: ai09-private-pilot
    # existing bounded runner/permissions and reviewed data-only steps follow
```

The admission job has no Environment, checkout/action, secret reference or
continue-on-error. A failed, cancelled or skipped admission cannot make the
downstream condition true. Do not add `always()` to that dependency, an input
enable flag or a reusable-workflow alternative bypass. Only the downstream job
binds the already-existing `ai09-private-pilot` Environment; do not change that
Environment or branch rules. The future activation change replaces the
unconditional admission failure only after the distinct final authorization.

The secret appears exactly once, at the coordinator step, never at job/global,
prefetch, cleanup or artifact steps. Remove private extraction/tests/reviewer
execution and old `always()` sealing/upload logic rather than retaining a second
reachable runtime.

The public boundary suite should execute the unbound HOLD script with canary secret
values and prove nonzero exit, no files, no secret reads, no child/model launch and
no upload after failure. It also verifies the two job scopes and exact
success-only dependency, including failure/skipped/cancelled prerequisites and
non-main/non-manual contexts. Do not weaken the behavior of this guard test to fit
the new workflow; changing the old error text to the accurate activation-HOLD
reason is not permission to remove the guard.
Update other old text-based tests to assert the new behavior, not obsolete private
Python command strings. Add only necessary CI path filters for new files; keep the
existing PUBLIC eight-call smoke, model and resource limits unchanged.

After this still-parked version is legitimately on main, one actual no-secret
manual dispatch must show admission failure, `isolated-pilot` skipped and no
pending Environment deployment/review. Observe jobs and pending deployments
through GitHub's read-only API/UI; do not approve anything to make this test pass.
An unexpected pending review is a failed ordering check, not a request to haji84.
This hosted ordering observation is NOT_RUN in this design, and static tests alone
must not be reported as its completion.

The reviewed parked replacement may describe an eventual **encrypted-only**
artifact step, but its default remains disabled. Execution must not discard the
only real private evidence in an ephemeral runner: before final activation the
owner must choose and approve a durable export destination and capacity. The
smallest proposed option is one exact verified ciphertext file, at most the
existing5MB cap, retention1 day, no raw logs/manifests and no retry/upload of
partial output. This retention choice is a proposal, not current authorization.
Actual storage headroom and owner consent must be recorded before using it.

An eventual artifact step requires explicit approved export selection, successful
coordinator outcome and exact output readback metadata. Use a fixed single file,
not a glob or `always()` on failure. Only allowlisted booleans/hash/byte counts may
enter GitHub step outputs. Until those conditions and the final main SHA are
approved, the unconditional first HOLD remains and private inference is0/8.

## 7. Owner encoder and independently expected evidence context

Provide a local owner helper that uses the same reviewed `sealed_input` codec,
the existing original ZIP/raw plan and existing DPAPI-protected key. It must run
in the owner's existing Windows context, perform no network operations or Git
changes, preserve original bytes, use exclusive output creation, and authenticate
the actual newly read-back ciphertext before reporting only SHA256/size.

Proposed interface:

```text
owner_bundle.py seal-input --archive <original ZIP> --plan <raw plan>
  --dpapi-key-file <existing protected key file> --output <new ciphertext file>
owner_bundle.py verify-evidence --archive <original ZIP> --plan <raw plan>
  --dpapi-key-file <same protected key file> --evidence <downloaded ciphertext>
  --expected-context <separately retrieved context JSON>
  --expected-context-sha256 <digest from the trusted retrieval channel>
```

Key bytes are never CLI arguments, environment additions, stdout, temporary key
files or telemetry. DPAPI unprotect uses the existing CurrentUser protection;
output ACL assumptions must be checked in that owner context rather than equating
POSIX mode0600 with a Windows ACL. Do not generate, rotate, register or copy keys.

### 7.1 Commit host observations outside the encrypted envelope

Only after section4's clean child exit and coordinator output readback, the
coordinator writes exactly one `AI09_HOST_OBSERVATION=` line followed by canonical
ASCII JSON, at most2048 bytes. Its exact keys are:

```text
schema = AI09-HOST-OBSERVATION-v1
repository = haji84/independent-ai09-reviewer
run_id, attempt, commit
input_class = FROZEN_DATA_ONLY
input_ciphertext_sha256, input_ciphertext_bytes
output_ciphertext_sha256, output_ciphertext_bytes
launch_sha256, host_start_ns, host_end_ns
observed_responses = 8
```

Run/attempt/commit and approved input identity come from the trusted coordinator's
already validated GitHub/admission context. Output fields come from its actual
readback. Launch commitment and host times come directly from the new host-result
fields above, never from a parsed envelope or guest claim. Types, ranges and hashes
are checked before printing. No raw launch dictionary, source/chunk paths,
prompts, responses, findings, key or token is emitted. Full launch remains inside
the encrypted evidence. This is additional bounded metadata in the existing job
log, not a new Actions artifact or permission to upload any private material.

### 7.2 Obtain the expected context through a separate trusted read

After the approved run completes, the existing authenticated haji84 GitHub
connection (or the owner's authenticated GitHub reader) retrieves the **specific
run, attempt and exact job's logs**. This reader is separate from the key-bearing
owner verifier and does not receive the DPAPI key or decrypted evidence. It must:

1. Use the owner-approved run ID/attempt and final main SHA, not identifiers taken
   from the encrypted envelope. Fetch run and attempt-specific job metadata;
   establish the exact repository, manual event, main branch, approved SHA,
   successful `isolated-pilot` job and successful run. Retain the actual job ID
   and workflow path. Do not use the latest attempt or first matching job loosely.
2. Fetch that exact job's actual log and find exactly one canonical observation
   line. Reject missing, duplicate, malformed or conflicting observations. Match
   run/attempt/commit and input ciphertext identity to the independently approved
   values and GitHub metadata. Do not create an observation from the encrypted
   evidence, a summary, a model response or an old successful run.
3. Build a canonical `AI09-EXPECTED-HOST-CONTEXT-v1` JSON of at most16KiB with
   exactly these keys: `schema`, `repository`, `workflow_path`, `run_id`, `attempt`,
   `head_sha`, `run_event`, `head_branch`, `run_conclusion`, `job_id`, `job_name`,
   `job_conclusion`, `log_sha256`, `observation_sha256`, `observation`.
   The observation has exactly the section7.1 schema; redundant identities must
   match. Repository/workflow/job name, manual event/main branch and successful
   conclusions are fixed to the reviewed workflow; numeric/hash fields use the
   existing strict positive-integer/hash rules. `log_sha256` hashes the actual
   retrieved decoded UTF-8 log bytes, and `observation_sha256` hashes the canonical
   observation bytes. It includes no log text or private contents. Deliver
   that file and its SHA256 through the existing trusted owner handoff, before
   the local key-bearing verifier is run.

The retrieval source is part of the trust boundary. A hash only detects changes;
it does not authenticate who supplied the file. `--expected-context-sha256` must
come from that independent authenticated retrieval/handoff, not be calculated
from an arbitrary context file immediately before invoking the verifier. The
documentation must make this distinction explicit. The proposed connection uses
the existing GitHub read tools, not a new token, provider or artifact service.
Canonical parsing/context construction can be a pure, tested helper; authentic
retrieval is an operator/connected-reader step, not a boolean trusted because it
appears inside a JSON document.

### 7.3 Verify against those expectations; do not fall back to self-consistency

`verify-evidence` first validates the separately supplied context file's exact
bytes/hash/schema and all fixed repository/workflow/classification constraints.
Missing/unverified expected context fails before key access; no implicit fallback
is offered. It then authenticates the actual downloaded ciphertext using the
existing owner key and checks its actual hash/size against the external context.

Take expected `run_id`, `attempt`, `commit`, `host_start` and `host_end` **directly
from the externally retrieved observation**. The exact full launch is recovered
from the authenticated envelope only as the value of an external commitment:
canonicalize it and require SHA256 equality with the independently retrieved
`launch_sha256` before using it as `expected_launch`. If equality fails, stop.
This is commitment-checked reconstruction, not taking an embedded value as its
own expectation. A file with a forged launch and a freshly valid AEAD tag cannot
pass while the independent host commitment is unchanged.

Call the actual existing interface with every expectation supplied:

```python
pilot_batch.verify_frozen_evidence(
    plaintext, archive_raw, plan_raw,
    run_id=external_run_id, attempt=external_attempt, commit=external_commit,
    launch=commitment_checked_launch,
    host_start=external_host_start, host_end=external_host_end,
)
```

It freshly checks original pins, all47/104 coverage, the first8 exchanges, fixed
model identity, ordering and exact external launch/time context. A changed
envelope cannot rewrite these expectations. Successful verification means
**authenticated evidence consistent with the separately retrieved reviewed-host
observation and approved GitHub run**. It is not hardware attestation, a signature
from the model, finding correctness or authority to approve a merge. A malicious
trusted host, a compromised GitHub reader, or someone controlling both the key and
the supposed trusted observation can still fabricate consistent records; those
are outside this trust model and must not be hidden by a stronger label. Actual
owner approval and any final receipt-count admission remain separate gates.
Private finding contents stay local.

**Real format limitation:** the retrieved owner record confirms DPAPI storage but
does not give the protected file's exact filename or wrapper format. No matching
non-secret installer implementation was present in the inspected workspace.
Root's later bounded lookup also found no verified current installer format;
the Oct24 `SETUP_OWNER_JA.md` has stale repository-secret/plaintext-key guidance
and must not be used as a format or permission source. This does not prove that
the valid owner installer is absent everywhere.
Do not guess that format or call every DPAPI blob compatible. Review the existing
installer's non-secret format contract before implementing its adapter; implement
and test the pure codec/helper boundary independently. Actual owner-key/Windows
roundtrip is external evidence, not a Linux/mock PASS. The owner should supply no
plaintext key to this conversation.

## 8. Proposed files and meaningful validation

Implementation can be one reviewed connection unit after the sealed codec:

| Files | Responsibility |
| --- | --- |
| `pilot_host.py`, `tests/test_pilot_host.py` | Allocate the existing unique name before READY; validated immutable cleanup metadata and actual host time result fields; preserve current lifecycle and PUBLIC smoke |
| `runtime_assets.py`, `tests/test_runtime_assets.py` | Preserve explicit inherited proxy/CA transport for PUBLIC downloads without disclosing values, retaining URL pins/TLS verification and the exact offline subprocess policy |
| `private_pilot.py`, `tools/private_pilot.py`, `tests/test_private_pilot.py`, one PUBLIC child fixture | Bounded one-shot coordinator/child protocol, strict admission metadata, late secret access, exact output acknowledgement and failure cleanup |
| `tools/owner_bundle.py`, `tests/test_owner_bundle.py` | Owner-local encoder/verifier, bounded externally supplied expected context and commitment reconstruction; reviewed DPAPI adapter once its real non-secret format is established |
| Existing two workflows and `tests/test_public_workflow.py` | Safe parked replacement, current guard retained, precise new path filters, no activation or extra model command |
| Existing README/architecture plus this design/short plan | Actual operator sequence, unchanged limits and genuinely unresolved owner gates |

Before implementation, the reviewer should resolve whether a smaller file split
can keep the coordinator and child testable without duplicating host logic. Do not
copy `pilot_host` or add generic orchestration/provider frameworks.

Required actual PUBLIC-fixture tests:

- Observe no secret lookup, original read or key/cipher frame before valid READY;
  inspect the real child environment/argv and downloader/Docker arguments for
  canaries. Trusted parent env presence is explicitly allowed and separately
  tested; no false whole-runner absence assertion.
- Check actual download-child environment and opener construction with generated
  proxy/CA values: approved transport survives, unrelated/key/command-file canaries
  do not; inherited settings are not rewritten or bypassed, TLS stays verified,
  and none of the transport variables reach model/container/capture environments.
- Real pipes with partial writes, ciphertext larger than pipe capacity, child
  silent exit, stalled reader/writer, overlong control output, malformed JSON,
  duplicate/early READY, wrong nonce, extra DONE, wrong exit status and trailing
  secret-frame bytes. Every case terminates inside a shortened fixture deadline.
- Full generated47-source/104-span encrypted input, real bounded capture and
  encrypted filesystem output with external Docker/download fixtures; select only
  the first8, preserve complete packet, re-open/verify actual output. This is no
  actual model call and counts as0 fixed-subject receipts.
- Expiry during preparation, secret wait, decode, capture and fsync; no clock
  reset. Parent failure after recording READY, child crash after create, ambiguous
  create, cleanup failure and hard-kill fallback remain non-ready with no upload.
- Input/output symlink, hardlink, ancestor replacement, changed bytes, missing
  file, wrong ciphertext hash/size/key/purpose, all original pin/coverage failures.
- Corrupt DONE metadata, local readback changed after child success and an
  encrypted partial file left by failure never become artifact-ready.
- Capture the observation line from a real PUBLIC-fixture child/parent run and
  construct its separate context with generated GitHub metadata; use that fixed
  expected context in the owner-verifier test. Re-encrypt a changed launch or
  host time, substitute a run/attempt/commit, alter the output hash or substitute
  a stale context: each must reject. Changing the context file without changing
  its trusted digest must reject before key access. Missing/duplicate log markers,
  mismatched job/run metadata, attempts and input identity reject during context
  construction. Tests explicitly distinguish mocked retrieval from real GitHub
  provenance; they do not claim the test fixture proves remote execution.
- Parked unbound HOLD job cannot be bypassed by enable flags/canary env/PR context;
  all downstream secret/execute/upload conditions stay false after admission
  failure/skipping/cancellation, and the gate itself has no Environment binding.
  Public CI contains no secret expression or private invocation. Later actual
  parked main dispatch must independently show no pending Environment review.
- Owner helper fake-DPAPI and, when available, actual Windows generated-PUBLIC
  DPAPI roundtrips, wrong user/format, output collision, I/O interruption and
  raw-key/canary logging checks. Actual existing owner-key compatibility remains
  NOT_RUN until observed in that environment.

Run the relevant meaningful tests and the whole suite once, preserve failure
evidence, obtain whole-change different-model review, freeze exact bytes and
publish through existingPR2. The existing PUBLIC eight-model smoke runs once on
the new head; no additional private probe or model retry is implied.

## 9. Concrete final gates after ordinary implementation

1. Reconcile the real non-secret DPAPI storage format and run the reviewed owner
   helper on the existing original ZIP/plan and installed key. Record current
   ciphertext hash/size and successful local authenticated roundtrip; never ask
   for the key or reinstallation. Publication/transfer of that exact ciphertext
   requires approval for its concrete destination.
2. Present the exact reviewed final main SHA, first8 fixed-source scope,
   model/resources/deadlines, one encrypted output size/retention and actual
   storage headroom. Obtain only the remaining main/private execution/export
   authorization; do not relabel technical review as GitHub APPROVED.
3. Only then enable the reviewed parked path, execute once through the existing
   Environment review, independently retrieve the exact run/job context through
   the existing authenticated reader, retrieve the encrypted evidence into the
   owner boundary and verify the actual key/source/run/model association against
   that separately committed context. Count only observed
   valid responses. The104-stage and design approval require their own subsequent
   evidence; eight PUBLIC or private observations do not grant104 completion.

No implementation, model execution, secret read, private input access, artifact
upload or remote mutation was performed to author this proposal.

## Implementation clarification approved by root (2026-10-29)

The source of approved public identity values is exactly three optional, empty
`workflow_dispatch` string inputs: `approved_main_sha`,
`input_ciphertext_sha256`, `input_ciphertext_bytes`. They are passed only through
named coordinator-step environment entries, never shell interpolation. There is
no enable input. The coordinator requires all three before spawning/preparing or
reading input/key, validates lowercase 40/64-hex SHA values and a canonical
positive decimal byte count within the actual codec bound, and binds them to
actual haji84/manual/main/attempt1/GITHUB_SHA context. Empty values cannot execute
if admission is later enabled. They are authenticated owner-supplied claims bound
to Actions context, not cryptographic signatures. Keeping them optional while
parked allows the later no-secret admission-ordering observation without invented
approval values. The unbound unconditional HOLD and existing Environment remain.


## Additional approved implementation clarifications

Root approved making the proposed encrypted-only export concrete but unreachable:
the existing pinned upload-artifact action has literal `false && success() &&
steps.coordinator.outcome == 'success'`, the exact run-owned output filename,
retention1day and missing-file error. No enable input, actual upload or approval
of ciphertext distribution follows.

The PUBLIC transport correction handles inherited HTTP(S) ALL_PROXY as fallback
for absent per-scheme handlers without editing environment values, preserves
NO_PROXY and rejects unsupported schemes rather than using direct HTTPS silently.
Actual remote transport readiness remains untested in this unit. Owner expected
context has the15 keys enumerated in section7.2; raw decoded logs have a16MiB cap.
An extra observation preceded by indentation is rejected, while workflow source
echo substrings are not treated as authoritative observations.


## Observed local implementation validation

The complete PUBLIC fixture unit suite ran211 tests. Its default-sandbox run
reported eight existing loopback socket EPERM errors across seven methods, with
no assertion failures; that output is preserved. The identical unit suite under
the previously approved local-loopback allowance passed211/211, zero skips, in
16.270seconds. No external download, actual Docker/model, owner key/private input,
remote mutation, hosted dispatch or upload ran in this implementation unit.

Meaningful retained failures include missing host metadata, removed proxy/CA
configuration, ALL_PROXY-only HTTPS bypass, unsupported proxy acceptance, missing
coordinator/owner helpers, actual coordinator SIGTERM without cleanup, an ignored
indented duplicate observation and old parked-workflow topology. The resulting
PUBLIC tests cover bounded actual pipes/cancellation, complete47/104 inputs, actual
child capture/crypto/filesystem readback, strict authenticated context/commitments,
and disabled admission/export. These are fixture results, not private receipts.

The real owner key adapter remains OWNER_KEY_FORMAT_UNSUPPORTED until the actual
non-secret installer filename/wrapper contract is reviewed. Windows/installed-key
roundtrip and actual hosted HOLD/Environment ordering are NOT_RUN. Independent
whole-change review, publication/new-head PUBLIC CI and the final owner gates
remain outside this local completion record.
