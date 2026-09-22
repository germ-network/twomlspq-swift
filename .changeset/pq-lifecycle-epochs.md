---
"@germ-network/twomlspq-swift": minor
---

Expose a `GroupEpochs` pair (`pqEpoch`/`classicalEpoch`) via `TwoMLSSession.epochs` — the send group's epoch pair, mirroring the reference implementation's `epochs()` — purely additive, no behavior change. Add a from-cold, full-lifecycle test that drives establishment through the bootstrap, ratchet, re-key, fold, and rotation steps the way a host would, asserting the PQ epochs advance at each step.
