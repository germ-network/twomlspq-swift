---
"@germ-network/twomlspq-swift": minor
---

`initiate` now registers the §A.3 round itself, around the pre-committed KP′. A new public `pqBootstrapEnvelope()` returns that parked KP′ sealed as its own §A.1 envelope — a fresh ephemeral on every call, going `nil` once the Group_B join hands off and `pqPendingOutbound()` carries it instead. Calling `pqBootstrapJoin` before that join now throws `.sessionNotReady` (retriable) rather than `.notEstablished`. Restore now accepts a pre-join initiator archive that carries the registered round, and allows only no round or that same round for such an archive.
