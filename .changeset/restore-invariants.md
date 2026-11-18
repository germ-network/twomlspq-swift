---
"@germ-network/twomlspq-swift": patch
---

Restore and migration refuse archives that break invariants a live session enforces (group shape, credential history, owed establishment envelope, window epochs). Migration drops pending peer approvals: an approved but unfolded peer rotation must be re-requested by the peer. Restore re-derives the current window entries.
