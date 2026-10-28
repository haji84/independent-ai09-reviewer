# Secret workflow security review — preliminary, NOT independent model review

Reviewed proposed workflow at HEAD eaeea072 and follow-up changes. Findings require reproduction and separate reviewer confirmation.

## Blocking findings
1. **HIGH: evidence destroyed** — `.github/workflows/manual-gemini-review.yml` deletes `private-review-evidence` on every run. The encrypted receipt is not retained. Cannot meet auditable evidence gate.
2. **HIGH: no real free-tier enforcement** — `REVIEW_ALLOW_PAID=false` and typed confirmation only check local environment variables; Google billing tier is not queried. No automated guarantee of zero charges.
3. **HIGH: workflow is not independently approved** — default-branch-only trigger reduces untrusted PR exposure but does not prove workflow source, dependency actions, or repository maintainers cannot exfiltrate secrets. Require a separate security review before enabling secret-bearing runs.
4. **MEDIUM: key lifecycle missing** — REVIEW_EVIDENCE_KEY has no documented creation, rotation, backup, recovery or private storage procedure. Without recovery, encrypted evidence may be irretrievable.
5. **MEDIUM: workflow cannot yet be used** — manual dispatch workflow is only on Draft branch; dispatch from trusted main is not available until separately approved merge.
6. **MEDIUM: exact code SHA scope** — subject SHA is pinned to 3b1752a3, whereas PR #9 later gained docs-only commits. The reviewed file SHA may remain valid, but current-HEAD approval requires coverage reconciliation.

## Proposed resolution
- Keep PR #4 Draft. Do not expose Gemini or evidence secrets to PR code.
- Choose private encrypted storage with integrity digest, retention and retrieval test; avoid public artifact/logs.
- Separate trusted reviewed workflow bootstrap from model invocation code.
- Prove free-tier entitlement and budget constraints outside the model script.
- Record model version, exact source SHA, execution ID, and independent identity. Treat model output as advisory until findings reproduced.
- Re-review after fixes, then run one public-file inference using approved trusted default-branch workflow.

This document is a static security analysis by the implementation-side assistant. It is NOT an independent model execution, and no formal approval is claimed.
