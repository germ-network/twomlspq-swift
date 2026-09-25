import Foundation
import MLSCodec
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes

// MARK: - Header encryption (slice 9, PR2)
//
// Every blob that leaves the library past establishment is one opaque
// `SealedFrame = [12B nonce][classicalProvider.aeadSeal ct+tag]` — the AEAD
// covering `[u32-LE frame_len][frame][zero padding]` under empty AAD (book
// header-encryption.md, "Sealed frame"/"Frame length prefix & padding").
// The header AEAD is always the classical provider, for BOTH key families:
// only which group half DERIVES the key differs (book, "Key schedule").
// Direction: seal under MY recv group's key at its current epoch; receive =
// trial-open over MY send group's windows (book, "Send rule"/"Receive
// rule").

@available(iOS 26, macOS 26, *)
extension TwoMLSSession {
	/// New, distinct labels (book header-encryption.md, "Key schedule") —
	/// insurance against any group-id coincidence with the rendezvous
	/// exporter (`RendezvousConstants`), the PSK exporters, or each other.
	enum HeaderKeyConstants {
		static let classicalLabel = "germ.network.twomlspq.headerKey.v1"
		static let pqLabel = "germ.network.twomlspq.headerKey.pq.v1"
	}

	/// The header AEAD's own key size (32, ChaCha20-Poly1305) — the length
	/// BOTH key families derive at, regardless of which group half derives
	/// them. NOT `pqProvider.aeadKeySize` (16, AES-128): the PQ group's own
	/// AEAD is a different, weaker primitive than the header layer's fixed
	/// choice (book, "Sealed frame" — "not inherited from the group whose
	/// exporter produced the key").
	var headerKeyLength: Int { classicalProvider.aeadKeySize }

	/// `HeaderKey(G, e)` — the classical family: an exporter of `classical`
	/// at its CURRENT epoch. Raw, un-pre-hashed group id as context
	/// (`exportSecret` hashes it internally, RFC 9420 §8.5).
	func headerKey(_ classical: MLS.RFC9420.Group) throws -> Data {
		let secret = try classical.exportSecret(
			classicalProvider, label: HeaderKeyConstants.classicalLabel,
			context: classical.context.groupID, length: headerKeyLength)
		return secret.withUnsafeBytes { Data($0) }
	}

	/// `HeaderKeyPQ(G, e)` — the PQ family: an exporter of `pq` at its
	/// current `pq_epoch`, using the PQ group's own provider (its epoch
	/// secrets are PQ-suite-derived) but the HEADER AEAD's key length —
	/// both families are 32-byte ChaCha keys.
	func headerKeyPQ(_ pq: MLS.RFC9420.Group) throws -> Data {
		let secret = try pq.exportSecret(
			pqProvider, label: HeaderKeyConstants.pqLabel,
			context: pq.context.groupID, length: headerKeyLength)
		return secret.withUnsafeBytes { Data($0) }
	}

	// MARK: - Seal

	/// The shared seal primitive (book, "Sealed frame"): `[u32-LE
	/// frame.count][frame][zero padding]`, zero-padded out to `padTo` bytes
	/// (`max(0, padTo - frame.count)` zero bytes — a no-op when `padTo <=
	/// frame.count`), AEAD-sealed under a fresh `aeadNonceSize` (12) random
	/// nonce with empty AAD (book header-encryption.md, "Frame length
	/// prefix & padding"). `aeadSeal` returns `ct‖tag`, so the wire blob is
	/// `nonce ‖ ct ‖ tag`.
	func sealWith(_ key: Data, frame: Data, padTo: Int) throws -> Data {
		var plaintext = Data()
		Frames.pushSection(frame, into: &plaintext)
		plaintext.append(Data(repeating: 0, count: max(0, padTo - frame.count)))
		let nonce = classicalProvider.randomBytes(classicalProvider.aeadNonceSize)
		let sealed = try classicalProvider.aeadSeal(
			key: key, nonce: nonce, aad: nil, plaintext: plaintext)
		return nonce + sealed
	}

	/// Message-path frames (`0x01` standalone welcomes and `0x03` message
	/// frames — `encrypt`'s output, welcome-or-commit staple included): seal
	/// under `HeaderKey(recvGroup.classical, current epoch)` (book, "Send
	/// rule"), never padded (book, "Frame length prefix & padding" —
	/// message frames and return welcomes carry the prefix but are never
	/// padded). Throws `.notEstablished` with no recv group — the
	/// initiator's pre-establishment welcome travels unsealed on the
	/// invitation channel instead (never routed through here; PR3 will
	/// HPKE-envelope it).
	func seal(_ frame: Data) throws -> Data {
		guard let recv = recvGroup else { throw TwoMLSError.notEstablished }
		return try sealWith(try headerKey(recv.classical), frame: frame, padTo: frame.count)
	}

	/// The host's frame-sizing intent (book header-encryption.md, "Frame
	/// length prefix & padding"): `nil` (the default) leaves side-band
	/// frames at their natural size; `Some(n)` grows each one up to `min(n,
	/// last_message_frame_len)` so it seals to the same length as its
	/// co-stapled message, for size-unlinkability. Live only — see
	/// `padTarget`'s own comment — a host must call this again after
	/// restoring a session.
	public mutating func setPadTarget(_ target: Int?) {
		padTarget = target
	}

	/// `sideBandPadTo` (book header-encryption.md, "Frame length prefix &
	/// padding"): absent an intent, the frame's own natural length (no
	/// growth); with `padTarget` set, grow — never shrink — up to `min(target,
	/// lastMessageFrameLen)`, the co-stapled message's own unsealed frame
	/// length capped at the host's budget.
	func sideBandPadTo(frameLen: Int) -> Int {
		guard let target = padTarget else { return frameLen }
		return max(frameLen, min(target, lastMessageFrameLen))
	}

	/// Side-band frames: the A.4 legs (`0x17`/`0x19`) seal under the
	/// classical family — their inner MLS message rides the classical
	/// groups and is re-minted at the current epoch (`rewrapSideBand`), so
	/// keying the outer seal by `pq_epoch` would leave the two clocks
	/// unrelated. Every other side-band frame seals under the PQ family
	/// (`HeaderKeyPQ(recvGroup.pq, current pq_epoch)`) EXCEPT the one
	/// pre-A.3 frame whose recv-PQ group doesn't exist yet — the
	/// initiator's `BOOTSTRAP_KP` (`0x13`, before `recvGroup.pq` is
	/// founded) — which falls back to the classical family (book, "Send
	/// rule"). The classical branches (the A.4 legs, book "Send rule" —
	/// "with side-band padding still applied") and the PQ branch both pad to
	/// `sideBandPadTo`; the pre-A.3 fallback goes out through the message
	/// path's own unpadded `seal(frame)` instead — not because the padding
	/// section carves out an explicit BOOTSTRAP_KP exemption (it doesn't),
	/// but because the Send rule routes this one frame through the
	/// classical `seal` path, and that path's frames are never padded (book,
	/// "Send rule" — pre-A.3 fallback; "Frame length prefix & padding" —
	/// "message frames and return welcomes ... are never padded").
	func sealSideBand(_ frame: Data) throws -> Data {
		guard let recv = recvGroup else { throw TwoMLSError.notEstablished }
		guard let tag = frame.first else { throw TwoMLSError.truncatedSection }
		switch tag {
		case Frames.pqEKTag, Frames.pqCTTag:
			let padTo = sideBandPadTo(frameLen: frame.count)
			return try sealWith(
				try headerKey(recv.classical), frame: frame, padTo: padTo)
		default:
			if let recvPQ = recv.pq {
				let padTo = sideBandPadTo(frameLen: frame.count)
				return try sealWith(
					try headerKeyPQ(recvPQ), frame: frame, padTo: padTo)
			} else {
				return try seal(frame)
			}
		}
	}

	// MARK: - Standalone welcome / handoff delivery (slice 11, session-lifecycle.md:32-38)

	/// ACCEPTOR-ORIENTED (Bob, whose `recvGroup` is populated from
	/// construction — Group_A, joined at `receive`): the read-only PLAINTEXT
	/// `currentStaple` iff it is still the bare `0x01` birth welcome, else
	/// `nil` — NO gate, NO seal. This is the sign-over input a host's
	/// contract-26 handoff-blob minting binds `sha256` over, so a RESTORED
	/// owed-but-not-installed Bob (who has no `EstablishResult.welcome` any
	/// more) can still mint the envelope at all. An initiator's own
	/// `currentStaple` happens to be the same welcome shape pre-join —
	/// unlike the acceptor's `0x0B` handoff, an initiator's app payload is
	/// never signed over `initialWelcome()`'s bytes directly by the engine;
	/// a value host composing the payload shape (`setInitialAppPayload`)
	/// reads this to fold the welcome into what it signs.
	public func initialWelcome() -> Data? {
		currentStaple.first == Frames.apqWelcomeTag ? currentStaple : nil
	}

	/// ACCEPTOR-ORIENTED (slice 11, session-lifecycle.md:32-38): the gated,
	/// SEALED standalone deliverable — a message-path frame every acceptor
	/// message-path frame must be sealed under `HeaderKey(recvGroup)` like
	/// (header-encryption.md:286-88, 327-35), re-sealed under a fresh nonce
	/// on every call (mirrors the initiator's own `pendingOutbound()`
	/// re-send unlinkability) — never `advanceStateSeq` (a PURE read, not a
	/// take+persist sink). `nil` once `currentStaple` has moved past the
	/// establishment staples (a fold/bind has landed), OR on an initiator
	/// call (`recvGroup == nil`: Alice has not yet joined Group_B, so there
	/// is nothing here to seal under — her own welcome travels the
	/// invitation channel via `pendingOutbound()` instead) — a clean `nil`
	/// rather than a confusing `.notEstablished` from `seal`, since calling
	/// this at all on that side is a caller error, not a runtime race.
	/// Throws `.establishmentEnvelopeRequired` while the contract-26 handoff
	/// is still owed — a bare, unauthenticated `0x01` standalone welcome is
	/// exactly the emission door the gate exists to close.
	public func standaloneWelcome() throws -> Data? {
		try ensureEstablishmentDelegated()
		guard recvGroup != nil else { return nil }
		switch currentStaple.first {
		case Frames.apqWelcomeTag, Frames.establishmentHandoffTag:
			return try seal(currentStaple)
		default:
			return nil
		}
	}

	// MARK: - Receive

	/// Trial-decrypt `blob` against both receive windows —
	/// `recvHeaderKeys` (classical) FIRST, then `recvHeaderKeysPQ` (PQ),
	/// newest epoch first in each (book, "Receive rule"). `nil` on
	/// exhaustion: an out-of-window frame and garbage are indistinguishable,
	/// by construction.
	func tryOpen(_ blob: Data) -> Data? {
		let nonceSize = classicalProvider.aeadNonceSize
		guard blob.count > nonceSize else { return nil }
		let nonce = Data(blob.prefix(nonceSize))
		let ciphertext = Data(blob.dropFirst(nonceSize))
		for epoch in recvHeaderKeys.keys.sorted(by: >) {
			guard let key = recvHeaderKeys[epoch],
				let frame = try? openFrame(
					key: key, nonce: nonce, ciphertext: ciphertext)
			else { continue }
			return frame
		}
		for epoch in recvHeaderKeysPQ.keys.sorted(by: >) {
			guard let key = recvHeaderKeysPQ[epoch],
				let frame = try? openFrame(
					key: key, nonce: nonce, ciphertext: ciphertext)
			else { continue }
			return frame
		}
		return nil
	}

	/// One candidate key's AEAD open + length-prefix strip, reusing the
	/// frame codec's own prefix-then-remainder reader: the plaintext is
	/// `[u32-LE frame_len][frame][zero padding]`, and reading the prefix
	/// returns exactly `frame_len` bytes, dropping any trailing zero
	/// padding into the discarded remainder before the trailing-byte-strict
	/// decoder ever sees it (book header-encryption.md, "Frame length
	/// prefix & padding").
	private func openFrame(key: Data, nonce: Data, ciphertext: Data) throws -> Data {
		let plaintext = try classicalProvider.aeadOpen(
			key: key, nonce: nonce, aad: nil, ciphertext: ciphertext)
		return try Frames.readPrefixedThenRemainder(plaintext).section
	}

	/// `tryOpen(blob) ?? blob` — lets a receive entry point accept a sealed
	/// blob OR an already-opened frame straight through: an opened frame
	/// fails AEAD under every window key (book, "Receive rule" —
	/// "a receiver convenience only; the metadata-hiding property is a
	/// sender guarantee").
	func openOrRaw(_ blob: Data) -> Data {
		tryOpen(blob) ?? blob
	}

	/// One §A.3/§A.4/§A.5 side-band frame kind, for `OpenedFrameKind`'s
	/// `.pqSideBand` classification — mirrors the tags `Frames.swift`
	/// already owns; this just names them for host routing (book, "Host
	/// routing and the API").
	public enum PqFrameKind: Sendable, Equatable {
		case bootstrapKP
		case bootstrapWelcome
		case ratchetEK
		case ratchetCT
		case rekeyUpd
		case rekeyCommit
	}

	public enum OpenedFrameKind: Sendable, Equatable {
		case message
		case pqSideBand(PqFrameKind)
	}

	public struct OpenedFrame: Sendable, Equatable {
		public let kind: OpenedFrameKind
		public let frame: Data
	}

	/// `tryOpen`, then classify the opened frame's leading tag so a host can
	/// route it without ever seeing the (now header-hidden) tag on the wire
	/// (book, "Host routing and the API"). `nil` on `tryOpen` exhaustion; an
	/// opened-but-unrecognized tag is `.decryptionFailed` — a sealed frame
	/// only ever carries one of this module's own tags.
	public func openIncoming(_ blob: Data) throws -> OpenedFrame? {
		guard let frame = tryOpen(blob) else { return nil }
		guard let tag = frame.first else { throw TwoMLSError.truncatedSection }
		switch tag {
		case Frames.apqWelcomeTag, Frames.messageFrameTag, Frames.establishmentHandoffTag:
			return OpenedFrame(kind: .message, frame: frame)
		case Frames.pqBootstrapKPTag:
			return OpenedFrame(kind: .pqSideBand(.bootstrapKP), frame: frame)
		case Frames.pqBootstrapWelcomeTag:
			return OpenedFrame(kind: .pqSideBand(.bootstrapWelcome), frame: frame)
		case Frames.pqEKTag:
			return OpenedFrame(kind: .pqSideBand(.ratchetEK), frame: frame)
		case Frames.pqCTTag:
			return OpenedFrame(kind: .pqSideBand(.ratchetCT), frame: frame)
		case Frames.pqRekeyUpdTag:
			return OpenedFrame(kind: .pqSideBand(.rekeyUpd), frame: frame)
		case Frames.pqRekeyCommitTag:
			return OpenedFrame(kind: .pqSideBand(.rekeyCommit), frame: frame)
		default:
			throw TwoMLSError.decryptionFailed
		}
	}

	// MARK: - Capture

	/// Capture THIS session's own send-PQ group's `HeaderKeyPQ` at its
	/// CURRENT `pq_epoch` into `recvHeaderKeysPQ`, then prune to the flat
	/// keep-newest `pqHeaderWindow`. No-op while the send-PQ half is
	/// deferred (pre-A.3 Group_B). Idempotent per `pq_epoch`.
	///
	/// Call sites, traced against every place `sendGroup.pq`'s epoch
	/// actually advances or the half is founded: `initiate` (Alice founds
	/// it directly); `pqBootstrapRespond` (Bob founds it); `owePQBind` — the
	/// SINGLE funnel every discharge-triggering commit on `sendGroup.pq`
	/// runs through (§A.3's `pqBootstrapJoin`, §A.4's `pqRatchetBind`,
	/// §A.5's `pqRekeyApply` all call it, and it is where the pathless
	/// PARTIAL commit actually lands — not at each call site); and
	/// `pqRekeyRespond` (the committer's own `includePath: true` commit on
	/// `sendPQ`, a second, independent advance in the same §A.5 round).
	/// `applyBind` moves only `recvGroup.pq` (and reads, never commits,
	/// `sendGroup.pq` for its PSK export) — traced and confirmed it never
	/// advances `sendGroup.pq`'s epoch, so it needs no call here.
	mutating func recordPQHeaderKey() throws {
		guard let send = sendGroup, let pq = send.pq else { return }
		let epoch = pq.context.epoch
		if recvHeaderKeysPQ[epoch] == nil {
			recvHeaderKeysPQ[epoch] = try headerKeyPQ(pq)
		}
		if recvHeaderKeysPQ.count > Self.pqHeaderWindow {
			let evict = recvHeaderKeysPQ.keys.sorted(by: >).dropFirst(
				Self.pqHeaderWindow)
			for key in evict { recvHeaderKeysPQ[key] = nil }
		}
	}
}
