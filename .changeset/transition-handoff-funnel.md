---
"@germ-network/twomlspq-swift": patch
---

Funnel every Transition read-group-then-takeOutput() handoff through one @_optimize(none) @inline(never) helper, dodging the Swift 6.4.0 Android release-mode SIL verifier crash at every call site.
