---
"@germ-network/twomlspq-swift": patch
---

A credential that a live PQ leaf still presents now stays admissible past classical history-window eviction until that leaf catches up (book `group-rules.md` rule 4), maintained automatically at every state update rather than left to per-site pinning. Restore now validates the archived pin state against what the rebuilt PQ trees actually present, rejecting a stale or otherwise inconsistent pin with `.archiveInvalid`; a migrated session's minted pins are derived the same way, from the restored PQ trees, rather than carried over from the deployed engine's own (narrower) pinning.

Compatibility: an archive from an unreleased build that holds a presented id evicted from history with no corresponding pin now fails restore with `.archiveInvalid`. Released v0.2.1 archives already fail to decode on this branch for an unrelated reason, so this affects only unreleased-main archives.
