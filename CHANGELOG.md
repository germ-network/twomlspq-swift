# @germ-network/twomlspq-swift

## 0.2.1

### Patch Changes

- [#62](https://github.com/germ-network/twomlspq-swift/pull/62) [`31676fa`](https://github.com/germ-network/twomlspq-swift/commit/31676fa9d0ff9c96e2243217a800c6400501ab76) Thanks [@germ-mark](https://github.com/germ-mark)! - Widen the `swift-secret-bytes` pin from `.upToNextMinor(from: "0.5.0")` to
  `from: "0.5.0"`.

  `.upToNextMinor` on a 0.x version fences the range at `0.5.x`, so this package
  capped the whole graph below swift-secret-bytes 0.6.0 — the release that carries
  the shared `SecretBytes`↔`String` text bridge. `from:` keeps the 0.5.0 floor and
  admits 0.6.0 when it cuts. No source changes.

## 0.2.0

### Minor Changes

- [#60](https://github.com/germ-network/twomlspq-swift/pull/60) [`34c0a3a`](https://github.com/germ-network/twomlspq-swift/commit/34c0a3a42595430fca8707c4b97e49c523144b5a) Thanks [@germ-mark](https://github.com/germ-mark)! - Widen the `swift-crypto` dependency to `from: "5.0.0"` and move
  `swift-secret-bytes` to its 0.5.0 (swift-crypto 5) release, as part of the
  org-wide swift-crypto 5 migration.

  **Breaking — platform floor rises to macOS 15 / iOS 18**, matching swift-mls
  (which now floors there via swift-secret-bytes 0.5.0).

  Two dependencies are revision-pinned pending their own releases: swift-mls
  (germ-network/swift-mls#103, the swift-crypto 5 move). GermConvenience is its
  released 0.10.0 (the swift-crypto-5 release).

  No source changes were required, and secret custody is already complete — the
  session/identity secrets ride `SecretBytes` and the persisted archives ride
  `SecretArchive`.

## 0.1.7

### Patch Changes

- [#58](https://github.com/germ-network/twomlspq-swift/pull/58) [`3402d17`](https://github.com/germ-network/twomlspq-swift/commit/3402d17f3c431da23ae50702da7c5768e4f1c217) Thanks [@germ-mark](https://github.com/germ-mark)! - Funnel every Transition read-group-then-takeOutput() handoff through one @\_optimize(none) @inline(never) helper, dodging the Swift 6.4.0 Android release-mode SIL verifier crash at every call site.

## 0.1.6

### Patch Changes

- [#56](https://github.com/germ-network/twomlspq-swift/pull/56) [`5554b65`](https://github.com/germ-network/twomlspq-swift/commit/5554b65549f8c7cbae76505d3767aac53b1dfbd9) Thanks [@germ-mark](https://github.com/germ-mark)! - Opt `APQGroup.establishClassicalOnly` out of optimization (`@_optimize(none)`). Same Android release-build SIL verifier crash swift-mls 0.1.2 fixed in `CombinerGroup.createAndAdd` — the read-`group`-then-`takeOutput()` handoff on `Transition` trips a Swift 6.4.0 optimizer bug cross-compiling for Android; this package's own orchestration path hit the same pattern.

## 0.1.5

### Patch Changes

- [#54](https://github.com/germ-network/twomlspq-swift/pull/54) [`a96b817`](https://github.com/germ-network/twomlspq-swift/commit/a96b817c46fb55ba4e837d05af5c9ea560dc914b) Thanks [@germ-mark](https://github.com/germ-mark)! - Bump the swift-mls exact pin from 0.1.1 to 0.1.2. 0.1.2 fixes an Android release-build compiler crash (`@_optimize(none)` on `MLSCombiner.createAndAdd`); this package's exact-pin discipline means consumers can't take that fix until this bump ships.

## 0.1.4

### Patch Changes

- [#52](https://github.com/germ-network/twomlspq-swift/pull/52) [`a72435f`](https://github.com/germ-network/twomlspq-swift/commit/a72435f7a044dcd407e99f91a481e18c93b5d28f) Thanks [@germ-mark](https://github.com/germ-mark)! - Widen the GermConvenience requirement from `.upToNextMinor(from: "0.8.0")` to `from: "0.8.0"`. Consumers pin this package exactly, so the minor ceiling capped their whole graph below GermConvenience 0.9.0 — that is what made 0.9.0 unreachable for CoreAppLogic (GER-2495). This package imports only the base `GermConvenience` product, which 0.9.0 leaves untouched (its change is in `GermConvenienceHTTP`).

## 0.1.3

### Patch Changes

- [#49](https://github.com/germ-network/twomlspq-swift/pull/49) [`32427db`](https://github.com/germ-network/twomlspq-swift/commit/32427db45f3950a3abd8e68a98ad42eefa1c6443) Thanks [@germ-mark](https://github.com/germ-mark)! - Add the deployed Germ opaque combiner-blob wire codec to `TwoMLSPQSession`: `CombinerKeyPackage(publishedBlob:)` and `publishedBlob()` — byte-compatible with the Rust engine's `encode_combiner_key_package` / `decode_combiner_key_package` (`[version byte][opaque classical][opaque pq]`, RFC 9420 §2.1.2 varint vectors of full `MLSMessage` KeyPackages; v3 = the AppBinding capability cut). The Germ version-byte prefix is a Germ addition on top of draft-02 §7 (whose TLS framing stays in swift-mls, spec-only); this gives the Rust-free host (the reduced Android build) read AND write access to the same published key-package wire.

## 0.1.2

### Patch Changes

- [#47](https://github.com/germ-network/twomlspq-swift/pull/47) [`0b0a619`](https://github.com/germ-network/twomlspq-swift/commit/0b0a6190ba80fb5fd093c0cfa223d235a264c456) Thanks [@germ-mark](https://github.com/germ-mark)! - Add `EstablishResult.returnKeyPackage`, carrying the established session's own classical KeyPackage so an initiator/replier can put it into the welcome's keyMaterial (the value the Rust `PQClient.reply` returns as `myKeyPackage`).

## 0.1.1

### Patch Changes

- [#46](https://github.com/germ-network/twomlspq-swift/pull/46) [`198723c`](https://github.com/germ-network/twomlspq-swift/commit/198723c24c9da33b7a8b95fdccb9d7dc0701204f) Thanks [@germ-mark](https://github.com/germ-mark)! - Add `MLKEM768CipherSuiteProvider.hpkeSecretKeySize` (96, the CryptoKit `integrityCheckedRepresentation` length) so snapshot restore can length-check ML-KEM-768 HPKE secret keys against `Nsk` (spec/snapshot.md §3.1).

- [#44](https://github.com/germ-network/twomlspq-swift/pull/44) [`672ad80`](https://github.com/germ-network/twomlspq-swift/commit/672ad80b94a703b3cbad246fb33da4e65be27dcd) Thanks [@germ-mark](https://github.com/germ-mark)! - Add `SessionMigration.mintArchive` — a public session-level parts→`SecretArchive` minter (the session analog of `InvitationMigration.mintArchive`). Builds a native `SessionArchive` from a legacy Rust session's raw parts, restoring each group half through `Group.restore`/`makeSnapshot`, with mint-time cross-checks shared with the invitation minter.

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
