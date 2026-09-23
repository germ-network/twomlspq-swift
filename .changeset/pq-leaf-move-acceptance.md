---
"@germ-network/twomlspq-swift": minor
---

A PQ re-key now accepts a peer's PQ leaf moving to an already-canonical credential, or changing only its signature key. `SideBandResult` gains `rotatedCredential`. `QueuedProposal` gains `isCatchUp`. A PQ leaf may not move to a non-canonical id: `pqRekeyApply` now throws `.invalidSuccession` for that case, not `.invalidRekeyEffects`.
