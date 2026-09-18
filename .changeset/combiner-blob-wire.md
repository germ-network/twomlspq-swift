---
"@germ-network/twomlspq-swift": patch
---

Add the deployed Germ opaque combiner-blob wire codec to `TwoMLSPQSession`: `CombinerKeyPackage(publishedBlob:)` and `publishedBlob()` — byte-compatible with the Rust engine's `encode_combiner_key_package` / `decode_combiner_key_package` (`[version byte][opaque classical][opaque pq]`, RFC 9420 §2.1.2 varint vectors of full `MLSMessage` KeyPackages; v3 = the AppBinding capability cut). The Germ version-byte prefix is a Germ addition on top of draft-02 §7 (whose TLS framing stays in swift-mls, spec-only); this gives the Rust-free host (the reduced Android build) read AND write access to the same published key-package wire.
