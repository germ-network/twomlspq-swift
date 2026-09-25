import Foundation
import MLSCodec
import MLSProfileRFC9420

/// Every Welcome and KeyPackage this module puts on the wire travels as its
/// RFC 9420 §6 `MLSMessage`, never the bare struct — including each half of
/// the `0x01` APQ welcome and the §A.1 return key package. Decode accepts
/// the wrapped form only; a bare struct, or any other codec failure at these
/// sites, folds to `.malformedEstablishmentMessage`.
enum EstablishmentMessages {
	static func encodeWelcome(_ welcome: MLS.RFC9420.Welcome) throws -> Data {
		try MLS.RFC9420.Message.welcome(welcome).mlsEncoded()
	}

	static func decodeWelcome(_ bytes: Data) throws -> MLS.RFC9420.Welcome {
		let message: MLS.RFC9420.Message
		do {
			message = try MLS.RFC9420.Message(mlsEncoded: bytes)
		} catch is MLS.CodecError {
			throw TwoMLSError.malformedEstablishmentMessage
		} catch is MLS.RFC9420.WireError {
			throw TwoMLSError.malformedEstablishmentMessage
		}
		guard case .welcome(let welcome) = message else {
			throw TwoMLSError.malformedEstablishmentMessage
		}
		return welcome
	}

	static func encodeKeyPackage(_ keyPackage: MLS.RFC9420.KeyPackage) throws -> Data {
		try MLS.RFC9420.Message.keyPackage(keyPackage).mlsEncoded()
	}

	static func decodeKeyPackage(_ bytes: Data) throws -> MLS.RFC9420.KeyPackage {
		let message: MLS.RFC9420.Message
		do {
			message = try MLS.RFC9420.Message(mlsEncoded: bytes)
		} catch is MLS.CodecError {
			throw TwoMLSError.malformedEstablishmentMessage
		} catch is MLS.RFC9420.WireError {
			throw TwoMLSError.malformedEstablishmentMessage
		}
		guard case .keyPackage(let keyPackage) = message else {
			throw TwoMLSError.malformedEstablishmentMessage
		}
		return keyPackage
	}
}
