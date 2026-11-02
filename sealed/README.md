# Encrypted AI09 payloads ONLY

This folder may contain one owner-supplied **AES-256-GCM ciphertext** file:
`ai09-private-bundle.aesgcm`.

Do **not** upload any `.zip`, plaintext source, review plan, JSON receipt,
key file, model output, secret, private documentation, or decrypted artifact.

Expected encrypted payload SHA-256 (not a plaintext source):
`0d2eec032aab52efa73e71e0b4a96518d951b7d4d3d29edebceac27a7909ece2`

The source inside is validated against frozen SHA-256
`9cf979733d8d4753023b1dd239ba4a5f3be2e0a6a3216c9dda206c089a2b6aa5`
only after **runner-local decryption** using the private Actions secret.

**No automatic execution on upload.** Only an explicitly dispatched workflow
on trusted `main` can request that secret.
