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
		// Pinned to swift-mls's first tagged release. `MLSCrypto` is the
		// CipherSuiteProvider seam this package's ML-KEM-768 provider conforms to;
		// `AppBinding` (0xF0A2) rides into Group_A's classical half via
		// `CombinerGroup.establish(classicalExtraExtensions:)`. Exact pin: both
		// packages are pre-1.0 and released together, with no compatibility
		// contract established yet.
		.package(
			url: "https://github.com/germ-network/swift-mls.git",
			exact: "0.1.1"
		),
		// The zeroizing storage behind `MLS.HpkeSecretKey.data`; range matches swift-mls.
		.package(
			url: "https://github.com/germ-network/swift-secret-bytes.git",
			.upToNextMinor(from: "0.4.0")
		),
		// The shared `tryUnwrap` (safe unwrap) and other Germ conveniences. 0.8.0
		// splits the HTTP helpers into GermConvenienceHTTP, so the base product
		// this package imports no longer links swift-http-types.
		//
		// A range rather than `.upToNextMinor`: consumers pin this package
		// exactly, so a minor ceiling here caps the whole graph's GermConvenience
		// (0.9.0 was unreachable for CoreAppLogic because of it — GER-2495). This
		// package imports only the base product, which 0.9.0 leaves untouched.
		.package(url: "https://github.com/germ-network/GermConvenience.git", from: "0.8.0"),
		// Already resolved transitively via swift-mls (pinned `from: "4.0.0"`,
		// matching swift-mls's own rule); wiring it directly here brings the
		// `Crypto` product into these targets for the off-Apple ML-KEM path.
		.package(url: "https://github.com/apple/swift-crypto.git", from: "4.0.0"),
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
