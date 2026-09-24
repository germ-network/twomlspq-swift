---
"@germ-network/twomlspq-swift": minor
---

Drops the unread principal-scoped key copies: the born-dedicated recv-leaf custody record and a rotation candidate's own signing/signature key are no longer stored on `TwoMLSSession` or archived — every signing site already read the per-group stored key sets exclusively (`LeafKeys`), never these copies. `RotationCandidate` keeps only its credential id and staged epoch; the migration inputs (`MigratedRotationCandidate`, `MigratedRecvLeafPrincipal`) are unchanged.

Archives from this version are one-way: a new archive no longer carries a rotation candidate's own key material or the recv-leaf custody record, so an earlier build's decoder — which expects those fields — cannot restore one. An earlier archive that still carries them decodes fine under this version (the retired keys are simply ignored).
