---
"@germ-network/twomlspq-swift": minor
---

`encrypt` now self-drives the §A.5 credential catch-up (instead of a plain A.4 ratchet) whenever a recv-PQ leaf lags its owner's current canonical id. Our own catch-up opens only once the peer has already folded the target — otherwise the turn keeps ratcheting A.4 rather than opening a round it cannot complete. A session with no recv-PQ key falls through to A.4 the same way. The `encrypt` that stages a catch-up now returns a `.checkpoint` update instead of `.core`.
