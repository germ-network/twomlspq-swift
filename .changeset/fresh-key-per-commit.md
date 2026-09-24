---
"@germ-network/twomlspq-swift": minor
---

Every send-classical committing round — a fold, a bind discharge, or a catch-up — now mints a fresh signature key and applies it immediately; the group never holds a pending catch-up key. Restore rejects a non-empty send-classical `pending`, and the migration mint drops any supplied entries there rather than carrying them through. Archives are one-way: an earlier build mid-rotation, with a send-classical `pending` entry, no longer restores under this build.
