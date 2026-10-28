# PERSONAL AI HQ one-file independent review probe

**Status: NOT RUN. NO INDEPENDENT REVIEW VERDICT.** This is a read-only local prototype on a feature branch.

1. On an owner-controlled PC, install/start Ollama and a model **different from the implementation model**. Verify licensing, model identity and resources.
2. Clone PERSONAL-AI-HQ separately and checkout exact SHA `3b1752a3be149c4d6402286b5d8abb807ddb05ca` in detached HEAD. Confirm all source is public and free of private material.
3. Run `REVIEW_MODEL=<installed-model> node scripts/review-one-file.mjs /path/to/PERSONAL-AI-HQ` from this repository. For Windows PowerShell set `$env:REVIEW_MODEL='...'` before running node.
4. The script refuses mismatched SHA, requires completed nonempty model response, and writes local evidence to `private-review-evidence/pr9-one-file-review.json` (0600 on supporting systems). Never upload raw output to public GitHub.
5. Verify actual model/provider/runtime independence and independently reproduce every claimed finding. Encrypt evidence before backup or sharing. Only sanitized finding summaries may go into a public PR.
6. This one-file probe is **not** full 7-file coverage or an approval. Later expand to complete diff, coverage manifest, independent review and exact current HEAD.

Security: no GitHub write token required. Only loopback Ollama allowed. Do not send private code or secrets. Local evidence is unencrypted until protected by the owner; store it only on a trusted device.
