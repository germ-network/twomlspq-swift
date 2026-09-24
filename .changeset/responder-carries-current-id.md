---
"@germ-network/twomlspq-swift": minor
---

`pqRekeyRespond`'s committer `Commit′` now moves our own send-PQ path leaf onto our current canonical credential id whenever it lags, with a freshly minted key going straight to `current` — no `pending` catch-up key is retained afterward, since our own commit applies immediately. When the leaf doesn't lag, the move stays key-only, as before.
