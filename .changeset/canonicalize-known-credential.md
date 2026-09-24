---
"@germ-network/twomlspq-swift": patch
---

Applying a commit that moves a leaf to a credential already known to that party's sequence — a same-id signing-key refresh on a leaf whose canonical head has since moved on, or a fast-forward to an already-canonical, non-head id — no longer fails with `.credentialRollback`. Canonicalization now only ever runs for a credential genuinely new to the sequence; a leaf landing on a known id canonicalizes nothing, and `DecryptResult.newSender`/`ownCredentialCanonicalized` are documented accordingly.
