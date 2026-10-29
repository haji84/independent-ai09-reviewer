# Frozen input compatibility implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: use superpowers:executing-plans.
> The owner approved one additional repair stage and one latest-HEAD CI run.

**Goal:** Read the unchanged original ZIP and verify its unchanged 104-span plan
as data, preserving both original line boundaries and actual covered lines.

**Architecture:** `source_archive.py` reads all 48 archive members. A new
`frozen_plan.verify_plan(archive_raw, plan_raw)` verifies independently pinned raw
bytes, the recovered canonical hash, schema, 47-source selection, byte ranges,
hashes and coverage. It returns immutable spans plus existing normalized Chunk
values. The original boundary and covered last line remain distinct.

**Tech stack:** Existing Python stdlib, unittest, existing reviewed ZIP/JSON code.

**Spec:** Issue #3; `docs/architecture/private-execution-proposal.md`; owner-approved
data-only design; independent read-only audit of owner-provided staging inputs.

## Design and global constraints

- Fixed ZIP SHA256 remains
  `9cf979733d8d4753023b1dd239ba4a5f3be2e0a6a3216c9dda206c089a2b6aa5`.
- Raw plan SHA256 is independently pinned to recovered bytes:
  `ad7c9a7b6914670c82b436ede89d543e8e09a3c0902448c9378fb6ab1aaecf44`.
  Embedded canonical hash is
  `24c5ba68496d129a47b005831e9b523ccb21a5b395f8f1693d7fe78e47a34e94`.
  A matching self-hash establishes consistency, not signed provenance.
- Canonical hashing excludes `plan_sha256`, uses sorted compact JSON,
  ensure_ascii=False, allow_nan=False, UTF-8, then SHA256. Raw bytes are retained
  by the owner and are never rewritten, regenerated, extracted or committed.
- Distinguish 48 archive files from 47 selected source files and exactly one
  declared manifest. No caller-selected source/plan hash or count override.
- Exact root keys: archive_sha256,chunk_count,chunks,expected_status,
  github_approval,maker_model,manifest_path,max_chunk_bytes,merge_authorized,
  plan_sha256,review_target,root_prefix,schema,source_file_count.
- Schema1,104 chunks,47 sources,2300-byte maximum. Authority flags remain
  expected_status=REVIEW_NOT_INVOKED,github_approval=False,merge_authorized=False.
  Maker/target are bounded descriptive strings, never execution authority.
- Exact chunk keys: index,path,start_byte,end_byte,start_line,end_line,sha256,
  source_sha256. Indices are exact integers0..103 in order. Per-file ranges are
  contiguous from0 to EOF. Every source/chunk hash and UTF-8 slice must match.
- Original start/end line boundaries equal LF count in the prefix before the
  start/end byte respectively, plus1. Covered last line is LF count before the
  final included byte, plus1. Preserve both; findings cannot cite the next line.
- `FrozenSpan` stores original offsets/line boundaries and `covered_end_line`.
  `VerifiedPlan` stores raw/canonical/source hashes and tuple spans/chunks.
  All views are immutable and hide private content/paths in repr. Existing Chunk
  repr is hardened because normalized chunks can now carry private input data.
- Production `data_driver.load_frozen_plan` and parked pilot HOLD stay unchanged.
  The new verifier is an offline input adapter, not inference or authorization.
- No secret, credential, dependency, permission, billing or resource changes.
  No private artifacts or fixture copies in Git/CI. No private-code execution.
- Reuse PR #2. Exactly one authorized CI execution; no corrective CI retry.

Approach: extend the approved public data-only path. Executing the downloaded
private harness would expand the untrusted code boundary; it is not used.
Normalizing the original bytes or rechunking would break the fixed input and is
not used. Internal covered-line metadata is derived without editing the plan.

## Review focus

- A self-consistent replacement plan must fail the independent raw-hash pin.
- A declared manifest cannot hide a second excluded or uncovered archive file.
- Original one-past line boundaries must not authorize findings on uncovered data.
- Canonical UTF-8 hashing must differ correctly from escaped JSON encodings.
- Private source/path canaries must not appear in object representations/errors.

## Task 1: Correct container identity without relaxing source boundaries

Files: source_archive.py, tests/test_source_archive.py, data_driver.py.
Consumes: existing read_frozen_archive(bytes), Chunk(id,path,start_line,bytes).
Produces: all48 validated archive members; Chunk repr without private fields.

- [x] Public48-member fixture succeeds;47 and49 fail. Observe RED first.
- [x] Keep all existing malformed ZIP/CRC/size/path/data-descriptor tests, updating
  fixture sizes and central-offset iteration consistently from47 to48.
- [x] Change only the verified archive-member count to48; limits/hash pin remain.
- [x] Test Chunk repr canaries through the new input-adapter tests; hide fields.

## Task 2: Verify the pinned plan and preserve original spans

Files: frozen_plan.py, tests/test_frozen_plan.py.
Consumes: exact archive/plan bytes and existing trusted parsers.
Produces: verify_plan(bytes,bytes)->VerifiedPlan; immutable FrozenSpan values.

- [x] PUBLIC fixture with47 sources, one manifest,104 spans and Unicode metadata.
  Observe missing verifier RED; public test-only monkeypatches pin fixture hashes.
- [x] Assert raw/source/canonical hashes, full byte preservation and immutable
  spans/chunks; original boundary2 vs covered line1 on a newline-ended slice.
- [x] Reject unpinned replacement before parsing, unknown/missing keys, boolean
  integer aliases, authority flags, invalid hashes/paths/prefixes, wrong source
  selection, gaps/overlaps/omissions, wrong line bounds, non-UTF8 cuts, bad counts
  and oversized inputs. Deep tests update only fixture pins, not production APIs.
- [x] Implement strict validation; preserve normalized Chunk's covered interval.
  Verify original spans separately. Reject unsupported line-break semantics.
- [x] Assert build_request/validate_response cannot use an uncovered next line.
  Existing production entry still refuses before I/O/inference.

## Task 3: Verify, independently review, publish and run one CI

Files: existing public CI path filters; architecture status; this plan.

- [x] Add only module/test path filters. No new jobs, artifacts or model calls.
- [x] Full local suites under existing3.12 and supplemental3.13; diff/compile
  checks. Locally verify recovered inputs in memory, printing metadata only.
- [x] Fresh different-model code review; reproduce any substantive finding
  before one bounded local correction pass. No private input to the reviewer.
- [ ] Publish only reviewed public changes atomically in PR #2; check latest
  HEAD CI exactly once and inspect logs/artifact boundary.
- [ ] Record exact hashes, tests, review, actual input compatibility and remaining
  gates in Issue #3. Fixed-subject model counts remain0/8 and0/104; HOLD.
