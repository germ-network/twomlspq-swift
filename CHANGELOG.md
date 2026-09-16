# @germ-network/twomlspq-swift

## 0.1.0

### Minor Changes

- [#42](https://github.com/germ-network/twomlspq-swift/pull/42) [`7ad2560`](https://github.com/germ-network/twomlspq-swift/commit/7ad256039ef684c00bafbcbe543a22844d52c048) Thanks [@germ-mark](https://github.com/germ-mark)! - First pre-release.

  twomlspq-swift is a Swift-native **Two-MLS-PQ** (post-quantum MLS) implementation built on
  [swift-mls](https://github.com/germ-network/swift-mls). This release includes the
  **`0xFDEA` ML-KEM-768 cipher-suite provider** — a conformer to swift-mls's
  `MLS.CipherSuiteProvider` for the private-range suite
  `MLS_128_ML_KEM_768_AES128GCM_SHA256_Ed25519` — supplying the ML-KEM-768 KEM and RFC 9180
  base-mode HPKE over it, and reusing swift-mls suite-1's symmetric stack (HKDF-SHA256 /
  AES-128-GCM / SHA-256 / Ed25519) unchanged.
