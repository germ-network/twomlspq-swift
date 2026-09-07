# twomlspq-swift

Swift-native **Two-MLS-PQ** (post-quantum MLS) built on
[swift-mls](https://github.com/germ-network/swift-mls).

The first piece is the **`0xFDEA` ML-KEM-768 cipher-suite provider** — a
conformer to swift-mls's `MLS.CipherSuiteProvider` for the private-range suite
`MLS_128_ML_KEM_768_AES128GCM_SHA256_Ed25519`. It supplies the ML-KEM-768 KEM
and RFC 9180 base-mode HPKE over it, and reuses swift-mls suite-1's symmetric
stack (HKDF-SHA256 / AES-128-GCM / SHA-256 / Ed25519) unchanged.

The APQ combiner, the post-quantum ratchet, and the session layer will land
here next, as the Rust implementation is retired.

## Requirements

The provider uses Apple CryptoKit's ML-KEM-768, so its types are
`@available(iOS 26, macOS 26)`. The package's link floor is iOS 17 / macOS 14
(swift-mls's floor); the OS-26 requirement applies only when calling the
provider.

## Cipher suite

| Role | Value | Suite |
|------|-------|-------|
| Post-quantum | `0xFDEA` | `MLS_128_ML_KEM_768_AES128GCM_SHA256_Ed25519` (FIPS 203, private range) |

Public keys (1184 B) and ciphertexts (1088 B) are the standard FIPS 203 wire
format. The private key is CryptoKit's 96-byte `integrityCheckedRepresentation`
(seed-bearing), which is **not** interchangeable with other providers' secret
formats.

## License

Dual-licensed under [Apache 2.0](LICENSE-APACHE) and [MIT](LICENSE-MIT).
