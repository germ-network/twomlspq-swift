---
"@germ-network/twomlspq-swift": minor
---

Every own-leaf Update offer — routine or catch-up — now mints a fresh signature key and signs under it, instead of repeating the leaf's current key. `DecryptResult.newSender` and `ownCredentialCanonicalized` fire only when a leaf's credential id actually changes; a same-id key-only move is accepted and surfaces neither flag.
