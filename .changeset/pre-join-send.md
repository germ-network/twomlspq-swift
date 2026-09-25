---
"@germ-network/twomlspq-swift": minor
---

A pre-join initiator can now send app messages before joining the acceptor's group: `prepareToEncrypt`/`encrypt` succeed instead of throwing, returning an HPKE §A.1 envelope for the invitation channel rather than a header-sealed frame for the rendezvous channel. `EncryptResult` gains `isEstablishmentEnvelope` to tell the two apart, and `canSend` is now true for a pre-join initiator that can send this way.
