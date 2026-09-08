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
		// c594f2b = main HEAD at the time of this pin, picking up the Data→SecretBytes
		// zeroization of the epoch seed, TreeKEM path-secret chain, and signing key.
		.package(
			url: "https://github.com/germ-network/swift-mls.git",
			revision: "c594f2b827d0808ae0edaa55d3dcf43547252c7a"
		),
		// The zeroizing storage behind `MLS.HpkeSecretKey.data`; range matches swift-mls.
		.package(
			url: "https://github.com/germ-network/swift-secret-bytes.git",
			.upToNextMinor(from: "0.4.0")
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
