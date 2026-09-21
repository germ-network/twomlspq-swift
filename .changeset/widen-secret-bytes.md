---
"@germ-network/twomlspq-swift": patch
---

Widen the `swift-secret-bytes` pin from `.upToNextMinor(from: "0.5.0")` to
`from: "0.5.0"`.

`.upToNextMinor` on a 0.x version fences the range at `0.5.x`, so this package
capped the whole graph below swift-secret-bytes 0.6.0 — the release that carries
the shared `SecretBytes`↔`String` text bridge. `from:` keeps the 0.5.0 floor and
admits 0.6.0 when it cuts. No source changes.
