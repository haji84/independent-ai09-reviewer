# Independent AI09 reviewer: public code, confidential source

**Status:** Setup PR. No real AI review has run. Formal approval remains HOLD.

This repository intentionally contains only *public-safe* review bootstrap code. Do not commit the frozen source ZIP, its plan, raw AI responses, findings, credentials, or owner-only key.

## Private by encryption, even with a Public repository
- The frozen 47-file / 104-chunk source ZIP must enter GitHub **only as AES-256-GCM ciphertext** `sealed/ai09-private-bundle.aesgcm`. The authenticated decryption gate verifies its original SHA-256: `9cf979733d8d4753023b1dd239ba4a5f3be2e0a6a3216c9dda206c089a2b6aa5`.
- The 256-bit master secret goes *only* into the repository Actions secret `AI09_BUNDLE_KEY_B64`. Never put it in commits, issues, PR comments, logs, or artifacts.
- Runner-only decrypted sources and raw receipts live in temporary storage. Only AES-256-GCM sealed receipts may be exported as workflow artifacts. Domain-separated keys prevent source and evidence cross-use.
- Manual run on `main` only, read-only GitHub token, no writes, no publishing and no merge authority. The 8-chunk pilot is NOT an approved 104-chunk full audit.
- **Public is still public:** the workflow code, timing, logs, and encrypted bytes remain observable. Confidentiality assumes the key is private and trusted workflow code/branch are protected.

## Owner-only setup after merging this bootstrap PR
1. Protect `main` and limit who can edit `.github/workflows/`.
2. In **Settings > Secrets and variables > Actions**, create `AI09_BUNDLE_KEY_B64` using the one-line value from the private `OWNER_ONLY_AI09_BUNDLE_KEY.txt` supplied separately.
3. Upload the **encrypted** file `ai09-private-bundle.aesgcm` to `sealed/ai09-private-bundle.aesgcm` on `main`. Never upload any ZIP from the handoff.
4. Check your Actions billing and limits. In Actions manually run **Independent AI09 public-safe 8-chunk pilot** on `main`.
5. Only artifact `ai09-pilot-encrypted-only` is allowed. If public logs leak any source or findings, disable the workflow and rotate the secret.

The runner uses local Ollama `qwen3:1.7b` with no paid hosted model APIs. Model answers are unverified until provenance, all chunks, and findings are independently reproduced. No automatic approval or merge.
