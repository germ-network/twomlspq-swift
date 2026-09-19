---
"@germ-network/twomlspq-swift": patch
---

Opt `APQGroup.establishClassicalOnly` out of optimization (`@_optimize(none)`). Same Android release-build SIL verifier crash swift-mls 0.1.2 fixed in `CombinerGroup.createAndAdd` — the read-`group`-then-`takeOutput()` handoff on `Transition` trips a Swift 6.4.0 optimizer bug cross-compiling for Android; this package's own orchestration path hit the same pattern.
