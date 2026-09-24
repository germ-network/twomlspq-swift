---
"@germ-network/twomlspq-swift": minor
---

`prepareToEncrypt` now proposes at most one Update offer per (recv epoch, target) pair, repeating the identical proposal bytes on every frame of that epoch instead of minting or staging a new one each call. A routine offer and an outstanding rotation candidate's offer coexist as two independent targets; a plain frame after a rotation offer keeps re-sending the routine offer, not the candidate's. `stagedUpdates` and the underlying archive stay bounded by the number of distinct targets used in the epoch rather than the number of `prepareToEncrypt` calls.
