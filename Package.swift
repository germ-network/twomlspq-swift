// swift-tools-version: 6.1
import PackageDescription

let package = Package(
	name: "twomlspq-swift",
	// Import/link floor matches swift-mls. The ML-KEM-768 provider additionally
	// requires OS 26 (CryptoKit ML-KEM) at RUNTIME — that floor sits on the
	// `@available(iOS 26, macOS 26)` types, not on importing or linking this package.
	// Import/link floor matches swift-mls, which now floors at macOS 15 /
	// iOS 18 (it rides swift-secret-bytes 0.5.0, whose own floor is iOS 18 /
	// macOS 15). The ML-KEM-768 provider additionally requires OS 26
	// (CryptoKit ML-KEM) at RUNTIME — that floor sits on the
	// `@available(iOS 26, macOS 26)` types, not on importing or linking this package.
	platforms: [
		.macOS(.v15),
		.iOS(.v18),
	],
	products: [
		.library(name: "TwoMLSPQCrypto", targets: ["TwoMLSPQCrypto"]),
		.library(name: "TwoMLSPQSession", targets: ["TwoMLSPQSession"]),
	],
	dependencies: [
		// `MLSCrypto` is the CipherSuiteProvider seam this package's ML-KEM-768
		// provider conforms to; `AppBinding` (0xF0A2) rides into Group_A's
		// classical half via `CombinerGroup.establish(classicalExtraExtensions:)`.
		// 0.1.6: the migration-only SPI also takes an outstanding Update's
		// leaf HPKE secret.
		.package(
			url: "https://github.com/germ-network/swift-mls.git",
			from: "0.1.6"
		),
		// The zeroizing storage behind `MLS.HpkeSecretKey.data`. 0.7.1 decodes keyed
		// containers in linear time, which snapshot restore relies on.
		.package(
			url: "https://github.com/germ-network/swift-secret-bytes.git",
			from: "0.7.1"
		),
		// The shared `tryUnwrap` (safe unwrap) and other Germ conveniences. 0.8.0
		// splits the HTTP helpers into GermConvenienceHTTP, so the base product
		// this package imports no longer links swift-http-types.
		//
		// Temporary revision pin to GermConvenience main, whose released line
		// (≤0.9.0) still caps swift-crypto at `..<5.0.0`; main has the
		// org-wide swift-crypto 5 move. Replace with the released version once
		// the next GermConvenience cuts.
		.package(
			url: "https://github.com/germ-network/GermConvenience.git",
			// 0.10.0 is its swift-crypto-5 release — the revision pin drops.
			from: "0.10.0"
		),
		// Already resolved transitively via swift-mls (now `from: "5.0.0"`);
		// wiring it directly here brings the `Crypto` product into these targets
		// for the off-Apple ML-KEM path.
		.package(url: "https://github.com/apple/swift-crypto.git", from: "5.0.0"),
	],
	targets: [
		.target(
			name: "TwoMLSPQCrypto",
			dependencies: [
				// `MLSCodec` defines the `MLS` namespace; `MLSCrypto` the seam + suite-1.
				.product(name: "MLSCodec", package: "swift-mls"),
				.product(name: "MLSCrypto", package: "swift-mls"),
				.product(name: "SecretBytes", package: "swift-secret-bytes"),
				.product(name: "Crypto", package: "swift-crypto"),
			]
		),
		.testTarget(
			name: "TwoMLSPQCryptoTests",
			dependencies: [
				"TwoMLSPQCrypto",
				.product(name: "MLSCodec", package: "swift-mls"),
				.product(name: "MLSCrypto", package: "swift-mls"),
				.product(name: "SecretBytes", package: "swift-secret-bytes"),
				.product(name: "Crypto", package: "swift-crypto"),
			]
		),
		.target(
			name: "TwoMLSPQSession",
			dependencies: [
				"TwoMLSPQCrypto",
				.product(name: "GermConvenience", package: "GermConvenience"),
				.product(name: "MLSCombiner", package: "swift-mls"),
				.product(name: "MLSProfileRFC9420", package: "swift-mls"),
				.product(name: "MLSExtensions", package: "swift-mls"),
				.product(name: "MLSCodec", package: "swift-mls"),
				.product(name: "MLSCrypto", package: "swift-mls"),
				.product(name: "MLSTreeMath", package: "swift-mls"),
				.product(name: "SecretBytes", package: "swift-secret-bytes"),
			]
		),
		.testTarget(
			name: "TwoMLSPQSessionTests",
			dependencies: [
				"TwoMLSPQSession",
				"TwoMLSPQCrypto",
				.product(name: "MLSCombiner", package: "swift-mls"),
				.product(name: "MLSProfileRFC9420", package: "swift-mls"),
				.product(name: "MLSExtensions", package: "swift-mls"),
				.product(name: "MLSCodec", package: "swift-mls"),
				.product(name: "MLSCrypto", package: "swift-mls"),
				.product(name: "MLSTreeMath", package: "swift-mls"),
				.product(name: "SecretBytes", package: "swift-secret-bytes"),
			]
		),
	],
	swiftLanguageModes: [.v6]
)
