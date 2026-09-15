import Foundation
import MLSCodec
import MLSCrypto
import MLSProfileRFC9420

// MARK: - §A.1 HPKE establishment envelope (slice 9, PR3b)
//
// The envelope blob carries NO outer tag — `[u32-LE kem_output_len]
// [kem_output][ciphertext]` — because the invitation channel already routes
// it to the HPKE opener (book wire-format.md, "The §A.1 envelope"). The HPKE
// PLAINTEXT leads with an authenticated inner tag that selects the frame
// kind: `establishmentVectorTag` (0x07) for the four-section establishment
// reply, or `Frames.pqBootstrapKPTag` (0x13, unchanged) for the parallel A.3
// bootstrap-KP frame, carried verbatim. This slice populates only the BARE
// either/or shape (`welcome` + `returnKeyPackage`, no `appPayload`) —
// protocol-flows.md's self-sufficient signed-`appPayload` shape needs an
// app-layer identity envelope the port doesn't have.

/// The inner plaintext tag and framing constants. Declared here, not in
/// `Frames.swift`'s session-frame registry, because this tags the HPKE
/// PLAINTEXT — never a session frame of its own (wire-format.md's "three
/// declaration sites"). Gated on `TwoMLSSuite` (itself gated: it names the
/// `0xFDEA` provider), not on any OS-specific crypto of its own.
@available(iOS 26, macOS 26, *)
enum EstablishmentEnvelope {
	static let establishmentVectorTag: UInt8 = 0x07

	/// The book pins only "[framing version]" (wire-format.md ~135); the
	/// concrete value `1` is peer/interop-derived (the deployed reference's
	/// own framing-version constant), not book-mandated.
	static let framingVersion: UInt8 = 1

	// MARK: - AAD (downgrade-binds the declared suite pair; never transmitted)

	/// `[classical u16 BE][pq u16 BE]` — no suite-pair encoder existed in
	/// the port before this slice.
	static func suitePairBytes() -> Data {
		var data = Data()
		for id in [TwoMLSSuite.classical.id, TwoMLSSuite.pq.id] {
			data.append(UInt8(id >> 8))
			data.append(UInt8(truncatingIfNeeded: id))
		}
		return data
	}

	/// `[framingVersion][classical u16 BE][pq u16 BE]`, 5 bytes — derived
	/// locally on both sides, never transmitted (wire-format.md, "The seal
	/// binds the declared suite via untransmitted AAD"). A peer whose declared
	/// version or suite pair differs fails the HPKE AEAD tag, downgrade-
	/// binding the whole pair at zero wire bytes. Distinct from the archive
	/// format's own version byte.
	static func envelopeFramingAAD() -> Data {
		Data([framingVersion]) + suitePairBytes()
	}

	// MARK: - Outer framing (no tag)

	static func frameHpkeBlob(enc: Data, ciphertext: Data) -> Data {
		var buffer = Data()
		Frames.pushSection(enc, into: &buffer)
		buffer.append(ciphertext)
		return buffer
	}

	static func unframeHpkeBlob(_ blob: Data) throws -> (enc: Data, ciphertext: Data) {
		let (enc, ciphertext) = try Frames.readPrefixedThenRemainder(blob)
		return (enc: enc, ciphertext: ciphertext)
	}

	// MARK: - Inner plaintext (tag + 4 optional sections)

	/// `[establishmentVectorTag][u32 appPayload][u32 welcome]
	/// [u32 returnKeyPackage][u32 stapledMessage]` — empty section = absent.
	static func encodePlaintext(
		appPayload: Data?, welcome: Data?, returnKeyPackage: Data?, stapledMessage: Data?
	) -> Data {
		var buffer = Data([establishmentVectorTag])
		for section in [appPayload, welcome, returnKeyPackage, stapledMessage] {
			Frames.pushSection(section ?? Data(), into: &buffer)
		}
		return buffer
	}

	/// Dispatches on the plaintext's leading authenticated tag. Rejects
	/// truncation, trailing bytes (both via `Frames.readSections`), and an
	/// establishment vector carrying neither `appPayload` nor `welcome`
	/// (protocol-flows.md, "one envelope, two shapes (either/or)" — exactly
	/// one of the two shapes is on the wire, so at least one must be
	/// present).
	static func decodePlaintext(_ plaintext: Data) throws -> OpenedInitial {
		guard let tag = plaintext.first else { throw TwoMLSError.truncatedSection }
		let body = Data(plaintext[plaintext.index(after: plaintext.startIndex)...])
		switch tag {
		case establishmentVectorTag:
			let sections = try Frames.readSections(body, count: 4)
			let optional = sections.map { $0.isEmpty ? nil : $0 }
			guard optional[0] != nil || optional[1] != nil else {
				throw TwoMLSError.neitherAppPayloadNorWelcomePresent
			}
			return .establishment(
				InitialFrame(
					appPayload: optional[0], welcome: optional[1],
					returnKeyPackage: optional[2], stapledMessage: optional[3]))
		case Frames.pqBootstrapKPTag:
			return .bootstrapKP(plaintext)
		default:
			throw TwoMLSError.unsupportedEstablishmentTag(tag)
		}
	}

	// MARK: - Seal (send side)

	/// Seals `plaintext`'s composed sections to `theirKP`'s **PQ half** init
	/// key under `0xFDEA` (protocol-flows.md §A.1: "sealed to the PQ EK in
	/// Bob's KP'"). `info` is the recipient's ClientId, read off that same
	/// half's credential —
	/// a published combiner key package's two halves always share one
	/// ClientId (`TwoMLSSession.initiate`'s own AS-binding check). A fresh
	/// HPKE ephemeral every call; the caller decides how often to re-seal
	/// (`TwoMLSSession.pendingOutbound()`'s re-send unlinkability).
	static func seal(
		to theirKP: CombinerKeyPackage,
		appPayload: Data?, welcome: Data?, returnKeyPackage: Data?, stapledMessage: Data?,
		pqProvider: any MLS.CipherSuiteProvider
	) throws -> Data {
		let plaintext = encodePlaintext(
			appPayload: appPayload, welcome: welcome,
			returnKeyPackage: returnKeyPackage, stapledMessage: stapledMessage)
		let info = try basicIdentifier(theirKP.pq.leafNode.credential)
		let (enc, ciphertext) = try pqProvider.hpkeSeal(
			publicKey: theirKP.pq.initKey, info: info, aad: envelopeFramingAAD(),
			plaintext: plaintext)
		return frameHpkeBlob(enc: enc, ciphertext: ciphertext)
	}
}

/// The result of `Invitation.openInitial`/`EstablishmentEnvelope.decodePlaintext`
/// — which §A.1 frame kind the HPKE-opened plaintext's leading tag selected
/// (wire-format.md, "The §A.1 envelope").
public enum OpenedInitial: Sendable, Equatable {
	case establishment(InitialFrame)
	/// The verbatim `[0x13][KP′ bytes]` parallel bootstrap-KP frame — the
	/// same side-band shape A.3 uses in steady state, decoded here for
	/// completeness. A host holds it until establishment completes, then
	/// feeds it to `pqBootstrapRespond`; the SEND path for this parallel
	/// envelope is out of scope for this slice.
	case bootstrapKP(Data)
}

/// The establishment reply's four optional sections (empty on the wire =
/// absent). This slice populates only `welcome`/`returnKeyPackage` (the bare
/// shape, `TwoMLSSession.pendingOutbound()`); `appPayload`/`stapledMessage`
/// decode for completeness but are never populated here.
public struct InitialFrame: Sendable, Equatable {
	public var appPayload: Data?
	public var welcome: Data?
	public var returnKeyPackage: Data?
	public var stapledMessage: Data?
}

// MARK: - TwoMLSSession.pendingOutbound()

@available(iOS 26, macOS 26, *)
extension TwoMLSSession {
	/// Re-composes and re-seals the bare §A.1 establishment vector — this
	/// session's own `currentStaple` (still the plaintext `APQWelcome_A`
	/// pre-Group_B-join, header-encryption.md 404-409) plus the initiator's
	/// classical return key package — under a FRESH HPKE ephemeral every
	/// call (wire-format.md: re-send unlinkability — same plaintext,
	/// distinct outer bytes each send). `initialTheirKP` going `nil` means
	/// there is nothing left to (re-)send: the initiator has already joined
	/// Group_B (`joinGroupBIfNeeded` clears it), or this is a responder
	/// session, which never retains one.
	public func pendingOutbound() throws -> Data {
		guard let theirKP = initialTheirKP else {
			throw TwoMLSError.noPendingEstablishmentEnvelope
		}
		return try EstablishmentEnvelope.seal(
			to: theirKP, appPayload: nil, welcome: currentStaple,
			returnKeyPackage: try identity.keyPackage.classical.mlsEncoded(),
			stapledMessage: nil, pqProvider: pqProvider)
	}
}
