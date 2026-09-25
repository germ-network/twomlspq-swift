---
"@germ-network/twomlspq-swift": minor
---

`Principal.generate` gains `advertisesCorrectProfile: Bool`, default off, so a host can opt in to advertising the correct session profile on every KeyPackage that principal mints. Off by default, behavior and wire bytes are byte-identical to a build with no profile mechanism at all. Opted in, the classical key package leaf, its published blob, the return key package, and the host-signed `keyPackageData` each grow by 2 bytes.
