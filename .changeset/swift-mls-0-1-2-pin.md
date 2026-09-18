---
"@germ-network/twomlspq-swift": patch
---

Bump the swift-mls exact pin from 0.1.1 to 0.1.2. 0.1.2 fixes an Android release-build compiler crash (`@_optimize(none)` on `MLSCombiner.createAndAdd`); this package's exact-pin discipline means consumers can't take that fix until this bump ships.
