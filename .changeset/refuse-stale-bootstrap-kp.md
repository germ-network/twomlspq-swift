---
"@germ-network/twomlspq-swift": minor
---

`pqBootstrapRespond` now re-serves the parked Welcome′ only while its own §A.3 round is still open. Once that round has closed, a stale bootstrap KP now answers `.duplicateSideBand` with no state change, rather than re-founding or re-serving anything; an initiator handed her own reflected KP′ is refused the same way. The re-serve itself no longer reads as a group-level move — it now returns a Core-kind update.
