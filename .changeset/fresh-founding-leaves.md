---
"@germ-network/twomlspq-swift": minor
---

Every group a party founds — `initiate`'s two Group_A halves, `receive`'s Group_B classical half, and `pqBootstrapRespond`'s Group_B.pq half at §A.3 — now founds on a freshly minted leaf, never a reused KeyPackage leaf. A born-dedicated acceptor's rule-4 catch-up key is likewise minted independently of its founding leaf. `pqBootstrapRespond` now founds under the acceptor's then-canonical credential id rather than its founding one.

A pre-A.3 acceptor's send-PQ no longer carries a reservation: `LeafKeys`/`MigratedLeafKeys` restore and mint now require the canonical present-but-empty shape (`current: nil, pending: []`) for it, and the migration mint drops a supplied non-nil reservation there rather than requiring or rejecting one. A migrator should stop emitting that reservation once this ships.

Archives from this version are one-way: a pre-A.3 acceptor's archive written under this shape fails an earlier build's restore, and an earlier build's archive in that state fails this build's restore.
