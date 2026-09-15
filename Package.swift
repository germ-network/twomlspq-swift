// swift-tools-version: 6.1
import PackageDescription

let package = Package(
	name: "twomlspq-swift",
	// Import/link floor matches swift-mls. The ML-KEM-768 provider additionally
	// requires OS 26 (CryptoKit ML-KEM) at RUNTIME — that floor sits on the
	// `@available(iOS 26, macOS 26)` types, not on importing or linking this package.
	platforms: [
		.macOS(.v14),
		.iOS(.v17),
	],
	products: [
		.library(name: "TwoMLSPQCrypto", targets: ["TwoMLSPQCrypto"]),
		.library(name: "TwoMLSPQSession", targets: ["TwoMLSPQSession"]),
	],
	dependencies: [
		// swift-mls has no tags; pin by commit. `MLSCrypto` is the CipherSuiteProvider seam.
		// 3c1dc21 = main HEAD, adding the public non-consuming RFC 9420 §8.5
		// `Group.exportSecret(_:label:context:length:)` (swift-mls #94) — the repeatable
		// per-epoch exporter this package's header-key and rendezvous derivations draw on.
		// Additive over 5ed90f6 (the `.customProposal`-aware combiner attestation:
		// `verifyFullCommit`, `verifyApqPskBound`, the §6.1/§6.2 checks this layer
		// de-conflates onto).
		.package(
			url: "https://github.com/germ-network/swift-mls.git",
			revision: "3c1dc212d82dce85ee7d8d896f0188bbba65d0a9"
		),
		// The zeroizing storage behind `MLS.HpkeSecretKey.data`; range matches swift-mls.
		.package(
			url: "https://github.com/germ-network/swift-secret-bytes.git",
			.upToNextMinor(from: "0.4.0")
		),
		// The shared `tryUnwrap` (safe unwrap) and other Germ conveniences. 0.8.0
		// splits the HTTP helpers into GermConvenienceHTTP, so the base product
		// this package imports no longer links swift-http-types.
		.package(
			url: "https://github.com/germ-network/GermConvenience.git",
			.upToNextMinor(from: "0.8.0")
		),
	],
	targets: [
		.target(
			name: "TwoMLSPQCrypto",
			dependencies: [
				// `MLSCodec` defines the `MLS` namespace; `MLSCrypto` the seam + suite-1.
				.product(name: "MLSCodec", package: "swift-mls"),
				.product(name: "MLSCrypto", package: "swift-mls"),
				.product(name: "SecretBytes", package: "swift-secret-bytes"),
			]
		),
		.testTarget(
			name: "TwoMLSPQCryptoTests",
			dependencies: [
				"TwoMLSPQCrypto",
				.product(name: "MLSCodec", package: "swift-mls"),
				.product(name: "MLSCrypto", package: "swift-mls"),
				.product(name: "SecretBytes", package: "swift-secret-bytes"),
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
