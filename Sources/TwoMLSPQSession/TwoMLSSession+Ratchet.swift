import Foundation
import MLSCodec
import MLSProfileRFC9420
import TwoMLSPQCrypto

// MARK: - §A.4 PQ ratchet

@available(iOS 26, macOS 26, *)
extension TwoMLSSession {
	/// Decrypt+authenticate one §A.4 leg (shared by `pqRatchetRespond` and
	/// `pqRatchetBind`): the content-type gate runs BEFORE decrypting — a
	/// Commit smuggled behind the tag must not spend a handshake generation —
	/// then `unprotect`, the inner-tag check, and a peer-sender check. Any
	/// failure to decrypt an untrusted leg (a tampered/replayed/foreign-epoch
	/// frame) surfaces as the non-fatal `.decryptionFailed`, never a raw
	/// `MLS.*` teardown error (§12). Mutates `group` (spends a generation);
	/// call only after the inflight/epoch-floor guards already passed.
	private mutating func processA4Leg(
		on group: inout MLS.RFC9420.Group, innerTag: UInt8, message: MLS.RFC9420.Message
	) throws -> Data {
		guard case .privateMessage(let pm) = message, pm.contentType == .application else {
			throw TwoMLSError.decryptionFailed
		}
		let out: MLS.RFC9420.Group.Unprotected
		do {
			out = try group.unprotect(classicalProvider, message: pm)
		} catch {
			throw TwoMLSError.decryptionFailed
		}
		guard case .application(let content) = out.content else {
			throw TwoMLSError.decryptionFailed
		}
		let (tag, payload) = try Frames.decodePQLegContent(content)
		guard tag == innerTag, out.sender != group.myLeafIndex else {
			throw TwoMLSError.decryptionFailed
		}
		return payload
	}

	/// Self-driven, whichever side holds `pqTurnMine`: generate a fresh
	/// ML-KEM ephemeral, frame its `ek` as a `0x17` leg on `sendGroup.classical`,
	/// and park it awaiting the peer's CT. Classical-only mutation.
	private mutating func stageRatchet() throws {
		guard var send = sendGroup else { throw TwoMLSError.notEstablished }
		let eph = try MLKEM768KEM.generateEphemeral()
		let inner = Frames.encodePQLegContent(tag: Frames.pqEKTag, payload: eph.ek)
		let appPM = try send.classical.protect(
			classicalProvider, applicationData: inner, authenticatedData: Data(),
			signingKey: identity.signingKey)
		sendGroup = send

		let messageBytes = try MLS.RFC9420.Message.privateMessage(appPM).mlsEncoded()
		pendingSideBand = Frames.encodePQLeg(
			tag: Frames.pqEKTag, messageBytes: messageBytes)
		pqInflight = .initiating(PQEphemeral(secretKey: eph.secretKey, ek: eph.ek))
	}

	/// The responder: receive the initiator's `0x17` EK (decrypted off my
	/// `recvGroup.classical` — the initiator's send group), seal a fresh `S`
	/// to it under the `ctSealPSK` both sides can derive off `recvGroup.pq`
	/// (my mirror of the initiator's PQ half, at its current epoch), and emit
	/// the `0x19` CT on my OWN `sendGroup.classical` — not the mirror the EK
	/// arrived in, which may hold an uncommitted proposal of my own.
	public mutating func pqRatchetRespond(_ frame: Data) throws -> Data {
		let (tag, messageBytes) = try Frames.decodePQLeg(frame)
		guard tag == Frames.pqEKTag else { throw TwoMLSError.unsupportedSideBandTag(tag) }
		let msg = try MLS.RFC9420.Message(mlsEncoded: messageBytes)
		guard case .privateMessage(let pm) = msg else { throw TwoMLSError.decryptionFailed }

		guard var recv = recvGroup, recv.pq != nil else { throw TwoMLSError.notEstablished }
		guard pm.epoch >= recv.classical.context.epoch else { throw TwoMLSError.staleFrame }
		if case .responding = pqInflight {
			throw TwoMLSError.duplicateSideBand
		} else if pqInflight != nil {
			throw TwoMLSError.sessionNotReady
		}
		guard pendingProposal == nil else { throw TwoMLSError.sessionNotReady }
		guard var send = sendGroup else { throw TwoMLSError.notEstablished }

		let ek = try processA4Leg(
			on: &recv.classical, innerTag: Frames.pqEKTag, message: msg)
		recvGroup = recv

		let psk = try CTSeal.ctSealPSK(group: recv.pq!, pqProvider: pqProvider)
		let (s, wireCT) = try CTSeal.seal(ek: ek, ctSealPSK: psk, aead: classicalProvider)

		let inner = Frames.encodePQLegContent(tag: Frames.pqCTTag, payload: wireCT)
		let appPM = try send.classical.protect(
			classicalProvider, applicationData: inner, authenticatedData: Data(),
			signingKey: identity.signingKey)
		sendGroup = send

		let outMessageBytes = try MLS.RFC9420.Message.privateMessage(appPM).mlsEncoded()
		let outFrame = Frames.encodePQLeg(
			tag: Frames.pqCTTag, messageBytes: outMessageBytes)
		pqInflight = .responding(secret: s, wireCT: wireCT)
		pendingSideBand = outFrame
		return outFrame
	}

	/// The initiator: receive the responder's `0x19` CT (decrypted off my
	/// `recvGroup.classical` — the responder's send group), open `S` against
	/// the `ctSealPSK` derived off `sendGroup.pq` (the same group/epoch the
	/// responder sealed against, via its `recvGroup.pq` mirror) using the
	/// ephemeral secret key held since `stageRatchet`, then owe the bind
	/// (`owePQBind(s:)`, §4c). `CTSeal.open`'s AEAD failure is the explicit
	/// reject for a tampered/misdirected CT — it propagates as thrown, not a
	/// silent no-op.
	public mutating func pqRatchetBind(_ frame: Data) throws {
		let (tag, messageBytes) = try Frames.decodePQLeg(frame)
		guard tag == Frames.pqCTTag else { throw TwoMLSError.unsupportedSideBandTag(tag) }
		let msg = try MLS.RFC9420.Message(mlsEncoded: messageBytes)
		guard case .privateMessage(let pm) = msg else { throw TwoMLSError.decryptionFailed }

		guard var recv = recvGroup else { throw TwoMLSError.notEstablished }
		guard pm.epoch >= recv.classical.context.epoch else { throw TwoMLSError.staleFrame }
		guard pendingProposal == nil, owedBind == nil else {
			throw TwoMLSError.sessionNotReady
		}
		guard case .initiating(let eph) = pqInflight else {
			throw TwoMLSError.sessionNotReady
		}
		guard let sendPQ = sendGroup?.pq else { throw TwoMLSError.notEstablished }

		let wireCT = try processA4Leg(
			on: &recv.classical, innerTag: Frames.pqCTTag, message: msg)
		recvGroup = recv

		let psk = try CTSeal.ctSealPSK(group: sendPQ, pqProvider: pqProvider)
		let s = try CTSeal.open(
			wireCT: wireCT, secretKey: eph.secretKey, ctSealPSK: psk,
			aead: classicalProvider)

		try owePQBind(s: s)
		// §13g/§12#2: clear BOTH — the spent EK must not be re-handed by
		// `pqPendingOutbound`, and `maybeStageNextRound`'s
		// `pendingSideBand == nil` gate must reopen, or the self-driver
		// wedges for life.
		pqInflight = nil
		pendingSideBand = nil
	}

	/// Peek the parked `0x17`/`0x19`/`0x1B`/`0x1D` side-band frame, if any —
	/// non-mutating re the round; the host sends it alongside the message
	/// frame.
	public func pqPendingOutbound() -> Data? {
		pendingSideBand
	}

	/// Best-effort: if the parked side-band leg was minted at an epoch
	/// `sendGroup.classical` has since moved past, re-mint it (EK from the
	/// held `.initiating` ephemeral, CT from the held `.responding` wireCT)
	/// at the current epoch and re-park. Classical carrier only. Never
	/// throws — a failure here just leaves the stale leg parked for the next
	/// call to retry.
	// internal: used by Messaging.prepareToEncrypt/encrypt
	internal mutating func rewrapSideBand() {
		guard let pending = pendingSideBand, var send = sendGroup else { return }
		// Also the intended no-op for a parked `0x1B`/`0x1D` §A.5 leg:
		// `decodePQLeg` only recognizes `0x17`/`0x19`, so it throws and `try?`
		// early-returns here. Correct — a PQ-group Upd′/Commit′ sits at a
		// `pq_epoch` that cannot move mid-round, so it never needs re-minting.
		guard let (tag, messageBytes) = try? Frames.decodePQLeg(pending) else { return }
		guard let message = try? MLS.RFC9420.Message(mlsEncoded: messageBytes),
			case .privateMessage(let pm) = message
		else { return }
		guard pm.epoch < send.classical.context.epoch else { return }

		let payload: Data
		switch tag {
		case Frames.pqEKTag:
			guard case .initiating(let eph) = pqInflight else { return }
			payload = eph.ek
		case Frames.pqCTTag:
			guard case .responding(_, let wireCT) = pqInflight else { return }
			payload = wireCT
		default:
			return
		}

		guard
			let appPM = try? send.classical.protect(
				classicalProvider,
				applicationData: Frames.encodePQLegContent(
					tag: tag, payload: payload),
				authenticatedData: Data(), signingKey: identity.signingKey),
			let reEncoded = try? MLS.RFC9420.Message.privateMessage(appPM).mlsEncoded()
		else {
			return
		}
		sendGroup = send
		pendingSideBand = Frames.encodePQLeg(tag: tag, messageBytes: reEncoded)
	}

	/// Self-drive (A.4 arm only — the A.5 `send_pq_leaf_lags` branch is
	/// deferred). No-op unless it's my turn, both halves are established, and
	/// nothing else is outstanding (an inflight round, an owed bind, or an
	/// already-parked side-band leg). Best-effort: swallows `stageRatchet`'s
	/// throw rather than surfacing it out of `encrypt`.
	// internal: used by Messaging.encrypt
	internal mutating func maybeStageNextRound() {
		guard pqTurnMine, isFullyEstablished, pqInflight == nil, owedBind == nil,
			pendingSideBand == nil
		else {
			return
		}
		try? stageRatchet()
	}
}
