---
"@germ-network/twomlspq-swift": minor
---

`pqRekeyBegin`'s Upd′ now carries our current canonical recv-PQ id whenever that leaf lags, staging a freshly minted key under `recvPQ.pending[that id]` until the peer's Commit′ applies it. A held migration-supplied catch-up key for the same target is replaced, never consumed. A non-lagging leaf still proposes key-only, as before.
