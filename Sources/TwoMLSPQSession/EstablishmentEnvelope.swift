import Foundation
import MLSCodec
import MLSCrypto
import MLSProfileRFC9420

// MARK: - §A.1 HPKE establishment envelope
//
// The envelope blob carries NO outer tag — `[u32-LE kem_output_len]
// [kem_output][ciphertext]` — because the invitation channel already routes
// it to the HPKE opener (book wire-format.md, "The §A.1 envelope"). The HPKE
// PLAINTEXT leads with an authenticated inner tag that selects the frame
// kind: `establishmentVectorTag` (0x07) for the four-section establishment
// reply, or `Frames.pqBootstrapKPTag` (0x13, unchanged) for the parallel A.3
// bootstrap-KP frame, carried verbatim — both sealed the same way
// (`EstablishmentEnvelope.seal(to:plaintext:pqProvider:)`), so the
// invitation-channel opener handles either without distinguishing them.
// `composeInitialEnvelope` seals either/or: the BARE shape (`welcome` +
// `returnKeyPackage`, no `appPayload`) by default, or — once the host has
// called `setInitialAppPayload` (or a migrated pre-join initiator carried
// one) — the self-sufficient signed-`appPayload` shape
// (protocol-flows.md:399-405). The engine never interprets the payload
// itself; the host is responsible for making it establishment-self-sufficient.

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
	/// the port before this envelope.
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
		return try seal(to: theirKP, plaintext: plaintext, pqProvider: pqProvider)
	}

	/// The raw-blob seal both §A.1 frame kinds share: `plaintext` already
	/// leads with its own inner tag (`establishmentVectorTag` or
	/// `Frames.pqBootstrapKPTag`).
	static func seal(
		to theirKP: CombinerKeyPackage, plaintext: Data,
		pqProvider: any MLS.CipherSuiteProvider
	) throws -> Data {
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
	/// same side-band shape A.3 uses in steady state, shipped by the
	/// initiator's `pqBootstrapEnvelope()`. A host holds it until
	/// establishment completes, then feeds it to `pqBootstrapRespond`.
	case bootstrapKP(Data)
}

/// The establishment reply's four optional sections (empty on the wire =
/// absent), either/or per protocol-flows.md:399-405: `appPayload` alone
/// (once `TwoMLSSession.setInitialAppPayload` was called, or a migrated
/// pre-join initiator carried one), or `welcome`/`returnKeyPackage` alone
/// (the bare shape). `welcome` and `returnKeyPackage` are each an RFC 9420
/// `MLSMessage`.
public struct InitialFrame: Sendable, Equatable {
	public var appPayload: Data?
	public var welcome: Data?
	public var returnKeyPackage: Data?
	/// A pre-join initiator's `0x09` app staple (book §A.1), present on any
	/// pre-join `encrypt` re-seal — session-lifecycle.md's host flow:
	/// - **First envelope:** `openInitial` -> `receive` -> feed this to the
	///   new session's `processIncoming`.
	/// - **Re-delivery** (a later re-seal of the same establishment
	///   vector): `openInitial` -> route by `forwardGroupID(spawnToken:
	///   H(appPayload ?? welcome))` -> `forwarded(spawnToken:)` -> feed this
	///   to `processIncoming`.
	/// - **Fail-open:** a lost staple is not re-sent after the initiator
	///   joins — every later send instead carries the header-sealed `0x03`
	///   path.
	public var stapledMessage: Data?
}

// MARK: - TwoMLSSession.pendingOutbound()

@available(iOS 26, macOS 26, *)
extension TwoMLSSession {
	/// Attach (or replace) the host's establishment-self-sufficient app
	/// payload — protocol-flows.md's "one envelope, two shapes (either/or)":
	/// once set, every later `composeInitialEnvelope` call (`pendingOutbound()`
	/// and, from the pre-join send path, `encrypt`) seals the payload-only
	/// shape instead of the bare `welcome`/`returnKeyPackage` sections. The
	/// engine cannot verify the payload actually carries the welcome pair,
	/// the classical return key package and `H(KP′)` — that is the host's
	/// own responsibility (protocol-flows.md:363).
	///
	/// Guards, in order: `payload` non-empty (else `.emptySection`); then
	/// `initiated`, `recvGroup == nil`, `initialTheirKP != nil` and
	/// `currentStaple.first == Frames.apqWelcomeTag` (else
	/// `.sessionNotReady`, Rust parity — `set_initial_field`).
	///
	/// Doc rule: persist the returned update before transmitting anything
	/// built from it — a session captured before this call restores as a
	/// bare-shape replier (Rust mod.rs:2048-2051, same rule).
	public mutating func setInitialAppPayload(_ payload: Data) throws -> StateUpdate {
		guard !payload.isEmpty else { throw TwoMLSError.emptySection }
		guard initiated, recvGroup == nil, initialTheirKP != nil,
			currentStaple.first == Frames.apqWelcomeTag
		else {
			throw TwoMLSError.sessionNotReady
		}
		initialAppPayload = payload
		advanceStateSeq()
		// The frame-content durability gate: a later pre-join send built
		// around this payload gates on THIS update's durability, same as a
		// fresh staple (`markStapleInstalled`'s own doc).
		markStapleInstalled()
		return try stateUpdate(kind: .core)
	}

	/// The shared §A.1 composer: `pendingOutbound()` and (from the pre-join
	/// send path) `encrypt` both build their envelope here. Either/or per
	/// protocol-flows.md:399-405 — a payload set by `setInitialAppPayload`
	/// (or carried by migration) seals ONLY `appPayload`/`stapled`; else
	/// today's bare `welcome`/`returnKeyPackage` sections, plus `stapled`.
	/// A fresh HPKE ephemeral every call (wire-format.md: re-send
	/// unlinkability — same plaintext, distinct outer bytes each send).
	///
	/// Guards: `initialTheirKP` (else `.noPendingEstablishmentEnvelope`,
	/// `pendingOutbound()`'s existing error) and
	/// `currentStaple.first == Frames.apqWelcomeTag` (else `.sessionNotReady`
	/// — unreachable pre-join in practice, defense only).
	func composeInitialEnvelope(stapled: Data?) throws -> Data {
		guard let theirKP = initialTheirKP else {
			throw TwoMLSError.noPendingEstablishmentEnvelope
		}
		guard currentStaple.first == Frames.apqWelcomeTag else {
			throw TwoMLSError.sessionNotReady
		}
		if let payload = initialAppPayload {
			return try EstablishmentEnvelope.seal(
				to: theirKP, appPayload: payload, welcome: nil,
				returnKeyPackage: nil,
				stapledMessage: stapled, pqProvider: pqProvider)
		}
		return try EstablishmentEnvelope.seal(
			to: theirKP, appPayload: nil, welcome: currentStaple,
			returnKeyPackage: try EstablishmentMessages.encodeKeyPackage(
				identity.keyPackage.classical),
			stapledMessage: stapled, pqProvider: pqProvider)
	}

	/// Re-composes and re-seals the §A.1 establishment vector — either the
	/// payload shape (once `setInitialAppPayload` has been called, or a
	/// migrated pre-join initiator carried one) or the bare shape: this
	/// session's own `currentStaple` (still the plaintext `APQWelcome_A`
	/// pre-Group_B-join, header-encryption.md 404-409) plus the initiator's
	/// classical return key package. `initialTheirKP` going `nil` means
	/// there is nothing left to (re-)send: the initiator has already joined
	/// Group_B (`joinGroupBIfNeeded` clears it), or this is a responder
	/// session, which never retains one.
	public func pendingOutbound() throws -> Data {
		try composeInitialEnvelope(stapled: nil)
	}

	/// The §A.3 parallel pre-delivery: the round `initiate` registered,
	/// sealed as its own §A.1 raw blob to the peer's KP′ — the reply's outer
	/// shape, so an acceptor's invitation-channel opener handles either.
	/// Ship it alongside `pendingOutbound()`. A pure read: a fresh HPKE
	/// ephemeral every call, no state change. `nil` once there is nothing
	/// left to pre-deliver — past the Group_B join (`pqPendingOutbound()`
	/// then carries the same frame on the steady-state side-band instead), a
	/// responder, or a round that was never registered (a pre-change
	/// archive).
	public func pqBootstrapEnvelope() -> Data? {
		guard let theirKP = initialTheirKP, case .bootstrapInitiated = pqInflight,
			let pending = pendingSideBand, pending.first == Frames.pqBootstrapKPTag
		else { return nil }
		return try? EstablishmentEnvelope.seal(
			to: theirKP, plaintext: pending, pqProvider: pqProvider)
	}
}
