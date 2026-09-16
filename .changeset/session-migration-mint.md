---
"@germ-network/twomlspq-swift": patch
---

Add `SessionMigration.mintArchive` — a public session-level parts→`SecretArchive` minter (the session analog of `InvitationMigration.mintArchive`). Builds a native `SessionArchive` from a legacy Rust session's raw parts, restoring each group half through `Group.restore`/`makeSnapshot`, with mint-time cross-checks shared with the invitation minter.
