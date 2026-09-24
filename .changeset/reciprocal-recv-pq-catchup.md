---
"@germ-network/twomlspq-swift": minor
---

`encrypt` now also self-drives the reciprocal §A.5 catch-up when the peer's recv-PQ leaf lags — deferred until the peer's own A.5 has already landed (observed as its leaf in our send-PQ presenting its current canonical id), so the turn opens a plain A.4 instead until then. A rotated pair now converges both PQ leaves over two self-driven rounds, plus at most one deferred A.4.
