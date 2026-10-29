# P0 public boundary: evidence, containment and restart gate

Authority: [Issue #3](https://github.com/haji84/independent-ai09-reviewer/issues/3).
Baseline: `98ee3c5b8ca6b1ee7332e5df7528a7f7910c1ede`, 2026-10-24.
This is public bootstrap evidence; no confidential review content is included.

## Scope and minimum implementation plan

Keep the existing PR #2, Public visibility, immutable target SHA, and AES-GCM
format. First reproduce boundary failures using synthetic data, then contain
unsafe execution before any secret access, repair bounded archive/evidence
handling, run public tests and latest-HEAD CI, and obtain a separate model's
public-code review. Do not build or authorize a new private execution architecture
as part of this containment. No merge, secret installation or model run is enabled.

The alternatives were keeping networked execution with redirected logs (fails
confidentiality), silently replacing the runtime (requires a design gate), and
an unconditional admission failure. The last is the reversible P0 containment
required by the Issue's fail-closed rule, rather than proof of a finished sandbox.

## Verified defects and fixes

| Boundary | Baseline behavior | Containment / regression |
| --- | --- | --- |
| Private execution | Decrypt-step environment, including master key, inherited by private Python; host/network access | First inline shell step fails unconditionally before checkout; no variable bypass. Behavioral test executes that block with synthetic env. |
| Failure cleanup | `always()` sealing/upload ran after an admission failure | Sealing additionally requires successful `open_bundle`; upload requires successful `seal_evidence`. With admission failed both are skipped. |
| ZIP paths | `a` plus `a/child`, including case aliases, leaves partial plaintext on write failure | Validate all names and parent collisions before creating destination; synthetic hash override exists only in tests. Reject normalized NUL/control names. |
| ZIP expansion | Forged 1-byte declaration for a 2 MB compressed stream caused about 7.65 MB peak allocation | Fixed 64 KiB reads and observed output limits; accept only STORED/DEFLATED. Separate review reproduced unbounded BZIP2/LZMA behavior, now rejected before output. Regression measures DEFLATE peak allocation below 4 MB. This does not certify integrity of all malformed compressed streams. |
| Evidence size | A seal could exceed the 5 MB unseal limit, producing an unusable artifact | Bound observed file/total size, ASCII chunk IDs 000–103, and complete encrypted envelope before creating output; maximum envelope roundtrip tested. |
| Supply chain | Mutable Actions refs and unconstrained transitive Python dependencies | Exact Actions commits and wheel hashes for all Python dependencies. |

No actual leak was observed or inferred. Encryption/decryption compatibility
tests do not verify real model provenance, response schema, or finding accuracy.
The fixed target was not opened or modified.

## Independent design review

A separate `gpt-6-astra` agent reviewed only the public baseline code and
reproduced the forged-ZIP allocation in memory. Its identified limits include
same-host sealer/artifact tampering and GitHub command-file output channels.
The dispatch-selected model name is not an independently attested model digest.
This is advisory public-bootstrap design review, not formal GitHub APPROVED,
not the qwen3 pilot, and not a receipt for any of the 104 fixed-subject chunks.
`DESIGN_APPROVAL=HOLD` remains mandatory.

The final independent public-code review identified the BZIP2/LZMA allocation
gap in the first fix. Both rejection tests failed before the compression
allowlist and passed after it; the full suite now has 24 passing tests using a
fresh Windows Python 3.12 virtual environment with the exact hashed dependency
set. `python -m pip check` and `git diff --check` also pass. Linux CI remains a
separate required verification; current run evidence is recorded in Issue #3.

## Supply-chain observations

Read-only checks on 2026-10-24 confirmed the Ollama v0.34.0 Linux amd64 release
asset's API digest is
`sha256:cf95886728959aa09910bb34de5cca1cc5a8f68003b5597197d3f2c2d57c0804`,
matching the parked workflow. The 1,433,537,033-byte binary was not downloaded
or executed. Source: [official release](https://github.com/ollama/ollama/releases/tag/v0.34.0).
The model registry manifest endpoint was reachable; model layers were not
downloaded, and a trusted model digest remains unverified. A mutable model tag
is insufficient evidence of independent inference.

Python hashes came from official PyPI release metadata for
[cryptography 46.0.4](https://pypi.org/pypi/cryptography/46.0.4/json),
[cffi 2.0.0](https://pypi.org/pypi/cffi/2.0.0/json), and
[pycparser 2.23](https://pypi.org/pypi/pycparser/2.23/json).
The limited wheel set intentionally fails closed on unsupported platforms.
Hashes pin bytes; they do not certify that a dependency is free of defects.

## Remaining restart conditions (not satisfied)

1. Owner-authorized effective main protection, real separate reviewer approval,
   latest-HEAD required CI, and controls over workflow modifications/bypass.
2. Owner-approved design isolating private code from the key, outbound network,
   sudo/host control, GitHub command files, the trusted sealer and public artifact
   storage. Prove attempted exfiltration, metadata output, background children,
   symlink/race and output tampering fail in the actual Linux execution boundary.
   Authenticate data crossing that boundary. A container or network flag alone
   is not evidence that the complete boundary works.
3. Read actual billing/free quota and enforce bounded spend/time before any
   GitHub-hosted model run. This session cannot read account billing through
   the available connector; no paid resource activation is authorized.
4. Separately approved ciphertext/key installation, recomputed ciphertext SHA,
   original ZIP SHA, model binary/layer identities and authenticated raw evidence.
5. Eight real pilot receipts, then separately validated 104 receipts across 13
   batches, finding reproduction and cross-file review. Current counts: 0/8, 0/104.

The connector lacks branch-protection administration, secret administration,
binary upload and workflow dispatch. Those operations have not been performed.
Compass resolves to a different project; its state is not modified. Issue #3
is the task handoff record, not another repository's PROJECT_STATE.md.

## Rollback

Keep admission closed. Reverting archive/evidence hardening can be reviewed on
the same PR, but restoring the baseline runnable workflow restores the known
unsafe path and is not an acceptable runtime rollback. No database, fixed
subject, credentials, repository settings or main commit changed in P0.
