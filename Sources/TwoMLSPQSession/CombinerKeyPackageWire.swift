import Foundation
import MLSCodec
import MLSCombiner
import MLSProfileRFC9420

/// The deployed Germ opaque combiner-blob framing — what the Rust engine's
/// `encode_combiner_key_package` mints and `decode_combiner_key_package` reads
/// (TwoMLSPQ rust/two-mls-pq/src/key_packages.rs): `[version byte]
/// [opaque classical][opaque pq]`, each `opaque<V>` an RFC 9420 §2.1.2 varint
/// vector (mls_rs_codec's `byte_vec`) holding a full §6 `MLSMessage` KeyPackage.
///
/// The version byte and the prefix are a GERM addition — draft-02 §7's TLS
/// framing for the pair itself is the spec-defined part and lives in swift-mls
/// (`MLS.Combiner.APQKeyPackage`); this reads the Germ wire wrapper around it.
/// The Rust engine stays the minting authority on Apple; these exist so the
/// Rust-free host (the reduced Android build) can publish and consume the same
/// wire. Full cryptographic validation stays with the consuming backend — this
/// is the framing, not a trust decision.
extension CombinerKeyPackage {
	/// The deployed framing's version byte. v3 = the AppBinding capability cut;
	/// older framings are rejected, matching the Rust parser's prerelease
	/// hard-cut policy.
	public static let publishedWireVersion: UInt8 = 3

	/// nil when `bytes` is not a well-formed blob of the deployed version:
	/// wrong version byte, a truncated vector, trailing bytes, or a half that
	/// doesn't decode as a key-package `MLSMessage`.
	public init?(publishedBlob: Data) {
		var reader = MLS.Reader(publishedBlob)
		guard
			(try? reader.readUInt8()) == Self.publishedWireVersion,
			let classicalBytes = try? reader.readOpaque(),
			let pqBytes = try? reader.readOpaque(),
			reader.isEmpty,
			let classical = Self.message(Data(classicalBytes)),
			let pq = Self.message(Data(pqBytes))
		else { return nil }
		self.init(classical: classical, pq: pq)
	}

	/// The deployed framing, byte-compatible with the Rust engine's
	/// `encode_combiner_key_package`.
	public func publishedBlob() throws -> Data {
		var writer = MLS.Writer()
		writer.writeUInt8(Self.publishedWireVersion)
		// Each half is wrapped in its §6 MLSMessage envelope first — the Rust
		// reader's `MlsMessage::from_bytes` expectation.
		try writer.writeOpaque(try MLS.RFC9420.Message.keyPackage(classical).mlsEncoded())
		try writer.writeOpaque(try MLS.RFC9420.Message.keyPackage(pq).mlsEncoded())
		return writer.data
	}

	private static func message(_ bytes: Data) -> MLS.RFC9420.KeyPackage? {
		var reader = MLS.Reader(bytes)
		do {
			let message = try MLS.RFC9420.Message(from: &reader)
			try reader.finish()
			guard case .keyPackage(let keyPackage) = message else { return nil }
			return keyPackage
		} catch {
			return nil
		}
	}
}
