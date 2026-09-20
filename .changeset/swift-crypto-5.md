---
"@germ-network/twomlspq-swift": minor
---

Widen the `swift-crypto` dependency to `from: "5.0.0"` and move
`swift-secret-bytes` to its 0.5.0 (swift-crypto 5) release, as part of the
org-wide swift-crypto 5 migration.

**Breaking — platform floor rises to macOS 15 / iOS 18**, matching swift-mls
(which now floors there via swift-secret-bytes 0.5.0).

Two dependencies are revision-pinned pending their own releases: swift-mls
(germ-network/swift-mls#103, the swift-crypto 5 move) and GermConvenience
(released line ≤0.9.0 still caps swift-crypto at `..<5.0.0`; main has the move).

No source changes were required, and secret custody is already complete — the
session/identity secrets ride `SecretBytes` and the persisted archives ride
`SecretArchive`.
