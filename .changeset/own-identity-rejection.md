---
"@germ-network/twomlspq-swift": patch
---

`initiate` and `receive` now reject a peer naming this device's own identity, with `.remoteIdentityMismatch`, before any state changes. `prepareToEncrypt(rotating:)` now rejects a rotation target naming an id the peer already uses, with `.invalidSuccession`.

`AuthCore.adjudicate` now checks each `.credentialReplaced` commit effect against the specific party whose leaf actually moved, rather than accepting it if either party's sequence would. `adjudicate` gains a `myLeaf` parameter; `validateSuccession` gains a `party` parameter.
