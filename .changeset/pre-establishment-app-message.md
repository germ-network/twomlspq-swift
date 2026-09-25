---
"@germ-network/twomlspq-swift": minor
---

Acceptors can now open a pre-join initiator's app message: `processIncoming`/`processIncomingApproved` gain a new `IncomingResult.preEstablishment(PreEstablishmentMessage)` case for a `0x09` §A.1 staple, which decrypts in the receive group with no accompanying offer. This is source-breaking for any exhaustive switch over `IncomingResult`.
