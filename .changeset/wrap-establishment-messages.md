---
"@germ-network/twomlspq-swift": minor
---

The §A.1 establishment vector's Welcome halves (Group_A's classical/pq pair, Group_B's classical half) and its return key package now travel as RFC 9420 `MLSMessage`s on the wire, matching every deployed peer. Receive accepts the wrapped form only; a bare struct is refused with a new `TwoMLSError.malformedEstablishmentMessage`.

A pre-fix native archive re-stapling a bare welcome, or holding a pre-fix acceptor's bare `APQWelcome_B`, no longer establishes against a post-fix peer — dev/test state only, since this engine is not yet deployed.
