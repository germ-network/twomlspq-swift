import Foundation
import MLSCodec
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes

// MARK: - Header encryption (slice 9, PR2)
//
// Every blob that leaves the library past establishment is one opaque
// `SealedFrame = [12B nonce][classicalProvider.aeadSeal ct+tag]` — the AEAD
// covering `[u32-LE frame_len][frame]` under empty AAD (book
// header-encryption.md, "Sealed frame"/"Frame length prefix & padding"; no
// padding this slice). The header AEAD is always the classical provider,
// for BOTH key families: only which group half DERIVES the key differs
// (book, "Key schedule"). Direction: seal under MY recv group's key at its
// current epoch; receive = trial-open over MY send group's windows (book,
// "Send rule"/"Receive rule").

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

	/// The shared seal primitive (book, "Sealed frame"): a fresh
	/// `aeadNonceSize` (12) random nonce, AEAD-sealed over
	/// `[u32-LE frame.count][frame]` with empty AAD. `aeadSeal` returns
	/// `ct‖tag`, so the wire blob is `nonce ‖ ct ‖ tag`. No padding this
	/// slice (Fork A, deferred to a follow-up).
	func sealWith(_ key: Data, frame: Data) throws -> Data {
		var plaintext = Data()
		Frames.pushSection(frame, into: &plaintext)
		let nonce = classicalProvider.randomBytes(classicalProvider.aeadNonceSize)
		let sealed = try classicalProvider.aeadSeal(
			key: key, nonce: nonce, aad: nil, plaintext: plaintext)
		return nonce + sealed
	}

	/// Message-path frames (`0x01` standalone welcomes and `0x03` message
	/// frames — `encrypt`'s output, welcome-or-commit staple included): seal
	/// under `HeaderKey(recvGroup.classical, current epoch)` (book, "Send
	/// rule"). Throws `.notEstablished` with no recv group — the
	/// initiator's pre-establishment welcome travels unsealed on the
	/// invitation channel instead (never routed through here; PR3 will
	/// HPKE-envelope it).
	func seal(_ frame: Data) throws -> Data {
		guard let recv = recvGroup else { throw TwoMLSError.notEstablished }
		return try sealWith(try headerKey(recv.classical), frame: frame)
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
	/// rule").
	func sealSideBand(_ frame: Data) throws -> Data {
		guard let recv = recvGroup else { throw TwoMLSError.notEstablished }
		guard let tag = frame.first else { throw TwoMLSError.truncatedSection }
		let key: Data
		switch tag {
		case Frames.pqEKTag, Frames.pqCTTag:
			key = try headerKey(recv.classical)
		default:
			if let recvPQ = recv.pq {
				key = try headerKeyPQ(recvPQ)
			} else {
				key = try headerKey(recv.classical)
			}
		}
		return try sealWith(key, frame: frame)
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
	/// frame codec's own section reader — the plaintext is exactly
	/// `[u32-LE frame_len][frame]` (no padding this slice), so a single
	/// `readSections(count: 1)` both bounds-checks the prefix and rejects
	/// any trailing bytes.
	private func openFrame(key: Data, nonce: Data, ciphertext: Data) throws -> Data {
		let plaintext = try classicalProvider.aeadOpen(
			key: key, nonce: nonce, aad: nil, ciphertext: ciphertext)
		return try Frames.readSections(plaintext, count: 1)[0]
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
		case Frames.apqWelcomeTag, Frames.messageFrameTag:
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
