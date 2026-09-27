---
"@germ-network/twomlspq-swift": patch
---

Receive-path error classification fix. A message frame's staple epoch is now classified before any further decode: a readable commit ahead of the receive group surfaces `epochDesync` before the app section is decoded. And a blob that never header-opened — an out-of-window frame and garbage, indistinguishable by construction — resolves wholly to `decryptionFailed`, matching the deployed engine, instead of leaking a wire-codec error (`truncatedSection`/`unsupportedFrameTag`) from a mis-read ciphertext byte.
