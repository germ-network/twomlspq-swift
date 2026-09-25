import Foundation
import GermConvenience
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
	/// `MLS.*` teardown error. Mutates `group` (spends a generation);
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
			signingKey: try sendClassicalSigningKey())
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
	public mutating func pqRatchetRespond(_ inbound: Data) throws -> SideBandResult {
		// Entry: the peer's `0x17` EK leg arrives header-sealed.
		let frame = openOrRaw(inbound)
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
		// No-custody guard, before `processA4Leg`'s write-back —
		// this responder frames its `0x19` reply on `send.classical`.
		guard !noCustody.contains(.sendClassical) else {
			throw TwoMLSError.leafCustodyUnavailable
		}

		let ek = try processA4Leg(
			on: &recv.classical, innerTag: Frames.pqEKTag, message: msg)
		recvGroup = recv

		let psk = try CTSeal.ctSealPSK(
			group: recv.pq.tryUnwrap(TwoMLSError.notEstablished), pqProvider: pqProvider
		)
		let (s, wireCT) = try CTSeal.seal(ek: ek, ctSealPSK: psk, aead: classicalProvider)

		let inner = Frames.encodePQLegContent(tag: Frames.pqCTTag, payload: wireCT)
		let appPM = try send.classical.protect(
			classicalProvider, applicationData: inner, authenticatedData: Data(),
			signingKey: try sendClassicalSigningKey())
		sendGroup = send

		let outMessageBytes = try MLS.RFC9420.Message.privateMessage(appPM).mlsEncoded()
		let outFrame = Frames.encodePQLeg(
			tag: Frames.pqCTTag, messageBytes: outMessageBytes)
		pqInflight = .responding(secret: s, wireCT: wireCT)
		pendingSideBand = outFrame
		let sealed = try sealSideBand(outFrame)

		// Return cadence: classical carrier only (the PQ half is read-only
		// here — `ctSealPSK`/derivation, never committed) → `.core`.
		advanceStateSeq()
		return SideBandResult(frame: sealed, update: try stateUpdate(kind: .core))
	}

	/// The initiator: receive the responder's `0x19` CT (decrypted off my
	/// `recvGroup.classical` — the responder's send group), open `S` against
	/// the `ctSealPSK` derived off `sendGroup.pq` (the same group/epoch the
	/// responder sealed against, via its `recvGroup.pq` mirror) using the
	/// ephemeral secret key held since `stageRatchet`, then owe the bind
	/// (`owePQBind(s:)`). `CTSeal.open`'s AEAD failure is the explicit
	/// reject for a tampered/misdirected CT — it propagates as thrown, not a
	/// silent no-op.
	public mutating func pqRatchetBind(_ inbound: Data) throws -> StateUpdate {
		// Entry: the peer's `0x19` CT leg arrives header-sealed.
		let frame = openOrRaw(inbound)
		let (tag, messageBytes) = try Frames.decodePQLeg(frame)
		guard tag == Frames.pqCTTag else { throw TwoMLSError.unsupportedSideBandTag(tag) }
		let msg = try MLS.RFC9420.Message(mlsEncoded: messageBytes)
		guard case .privateMessage(let pm) = msg else { throw TwoMLSError.decryptionFailed }

		// The fatal name check, at every PQ door, right after the
		// untrusted decode — mirrors Rust's `pq_ratchet_bind`
		// (decode, then `check_not_wedged`, then its state-shape guards).
		guard pqWedge == nil else { throw TwoMLSError.pqSideBandWedged }

		guard var recv = recvGroup else { throw TwoMLSError.notEstablished }
		guard pendingProposal == nil, owedBind == nil else {
			throw TwoMLSError.sessionNotReady
		}
		guard case .initiating(let eph) = pqInflight else {
			throw TwoMLSError.sessionNotReady
		}
		guard var send = sendGroup, let sendPQ = send.pq else {
			throw TwoMLSError.notEstablished
		}
		// No-custody guard, before anything is consumed — this
		// door's `owePQBind` commits `sendGroup.pq`.
		guard !noCustody.contains(.sendPQ) else {
			throw TwoMLSError.leafCustodyUnavailable
		}

		// DUAL-FORM, matching Rust's own `pq_ratchet_bind` —
		// a responder whose round predates the classical carriers may only
		// be able to re-send the LEGACY, PQ-carried form of its CT (the
		// payload is MLS-encrypted to us, so it can't rebuild the classical
		// one); refusing it would strand an otherwise-completable round.
		// Classify by the leg's OWN `group_id`, never by comparing epochs
		// across families: the classical form rides `recv.classical` (the
		// responder's send-classical, our recv mirror) at the current
		// epoch floor; the legacy PQ form rides `send.pq` (our own
		// send-PQ, the responder's recv-PQ mirror) instead, with no epoch
		// floor — a PQ-carried leg sits at a `pq_epoch` that cannot move
		// mid-round.
		let wireCT: Data
		if pm.groupID == recv.classical.context.groupID {
			guard pm.epoch >= recv.classical.context.epoch else {
				throw TwoMLSError.staleFrame
			}
			wireCT = try processA4Leg(
				on: &recv.classical, innerTag: Frames.pqCTTag, message: msg)
			recvGroup = recv
		} else if pm.groupID == sendPQ.context.groupID {
			var sendPQMutable = sendPQ
			wireCT = try processA4Leg(
				on: &sendPQMutable, innerTag: Frames.pqCTTag, message: msg)
			send.pq = sendPQMutable
			sendGroup = send
		} else {
			throw TwoMLSError.decryptionFailed
		}

		let psk = try CTSeal.ctSealPSK(group: sendPQ, pqProvider: pqProvider)
		let s = try CTSeal.open(
			wireCT: wireCT, secretKey: eph.secretKey, ctSealPSK: psk,
			aead: classicalProvider)

		try owePQBind(s: s)
		// Clear BOTH — the spent EK must not be re-handed by
		// `pqPendingOutbound`, and `maybeStageNextRound`'s
		// `pendingSideBand == nil` gate must reopen, or the self-driver
		// wedges for life.
		pqInflight = nil
		pendingSideBand = nil

		// Return cadence: `owePQBind` just committed `sendGroup.pq` → `.checkpoint`.
		advanceStateSeq()
		return try stateUpdate(kind: .checkpoint)
	}

	/// Peek the parked `0x17`/`0x19`/`0x1B`/`0x1D` side-band frame, if any —
	/// non-mutating re the round; the host sends it alongside the message
	/// frame. Sealed on exit: re-seals the retained plaintext under a
	/// fresh nonce on every call (never caches the sealed bytes), so
	/// repeated peeks of the same parked leg are byte-different but open to
	/// the same plaintext — matching `seal`/`sealSideBand`'s own contract.
	/// `nil` both when nothing is parked and, defensively, if sealing itself
	/// fails (never falls back to returning the leg unsealed). Also `nil`
	/// while `owesEstablishmentEnvelope` (defense-in-depth): every
	/// side-band round-starter already gates on
	/// `ensureEstablishmentDelegated()` before ever parking a leg, so this
	/// should be unreachable in practice, but matches the Rust peer's own
	/// `pq_pending_outbound` gating rather than relying solely on that.
	public func pqPendingOutbound() -> Data? {
		guard !owesEstablishmentEnvelope, let pending = pendingSideBand else { return nil }
		return try? sealSideBand(pending)
	}

	/// Best-effort: if the parked side-band leg is due for re-minting, do so
	/// (EK from the held `.initiating` ephemeral, CT from the held
	/// `.responding` wireCT) at the current classical epoch and re-park.
	/// Never throws — a failure here just leaves the stale leg parked for
	/// the next call to retry.
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

		// Classify the parked leg by its OWN `group_id` —
		// exactly Rust's `leg_carrier` — never by comparing a PQ epoch to a
		// classical one. Classical → due once `send.classical`'s epoch has
		// moved past the wrap (the steady-state case). PQ + EK → due
		// UNCONDITIONALLY, whatever the epochs say: a migrated round's EK
		// form is itself what's stale (book wire-format.md:86-92, "an
		// old-form EK is migrated, not answered … the first send after
		// such a restore converts it"). PQ + CT is exempt either way —
		// unrebuildable (the payload is MLS-encrypted to the peer) and it
		// never needs re-minting: the CT re-sent as parked opens under
		// either family (`tryOpen`).
		let due: Bool
		if pm.groupID == send.classical.context.groupID {
			due = pm.epoch < send.classical.context.epoch
		} else if let sendPQ = send.pq, pm.groupID == sendPQ.context.groupID,
			tag == Frames.pqEKTag
		{
			due = true
		} else {
			due = false
		}
		guard due else { return }

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
			let signingKey = try? sendClassicalSigningKey(),
			let appPM = try? send.classical.protect(
				classicalProvider,
				applicationData: Frames.encodePQLegContent(
					tag: tag, payload: payload),
				authenticatedData: Data(), signingKey: signingKey),
			let reEncoded = try? MLS.RFC9420.Message.privateMessage(appPM).mlsEncoded()
		else {
			return
		}
		sendGroup = send
		pendingSideBand = Frames.encodePQLeg(tag: tag, messageBytes: reEncoded)
	}

	/// Self-drive: an A.4 ratchet, or — when our own recv-PQ leaf lags and
	/// the peer has folded our catch-up target — the §A.5 catch-up
	/// instead. No-op unless it's my turn, both halves are established, and
	/// nothing else is outstanding (an inflight round, an owed bind, or an
	/// already-parked side-band leg). Also skips while
	/// `sendClassical`/`sendPQ` is in `noCustody` — `stageRatchet` would
	/// fail anyway (it signs on `sendClassical`), but a wedged/no-custody
	/// session's auto-driver must never even attempt to open a round it
	/// cannot complete. The A.4 arm is best-effort (swallows
	/// `stageRatchet`'s throw); a staging failure in the A.5 arm is not
	/// retried as an A.4 — a transient failure just retries on the next
	/// send. Returns whether it staged an A.5 (an A.4 mutates only the
	/// classical carrier, so it never needs to report anything here).
	// internal: used by Messaging.encrypt
	@discardableResult
	internal mutating func maybeStageNextRound() -> Bool {
		guard pqTurnMine, isFullyEstablished, pqInflight == nil, owedBind == nil,
			pendingSideBand == nil, pqWedge == nil,
			!noCustody.contains(.sendClassical), !noCustody.contains(.sendPQ)
		else {
			return false
		}
		if !noCustody.contains(.recvPQ), rekeyDue() {
			return (try? stageRekey()) != nil
		}
		try? stageRatchet()
		return false
	}

	/// Either leaf of our recv-PQ group presenting an id other than its
	/// owner's current canonical id (`protocol-flows.md:56`). Our own lag
	/// opens only once the peer has folded our own offer — observed as our
	/// leaf in `recvGroup.classical` already presenting `mine.current` —
	/// so a peer that never folds a catch-up offer (a deployed host that
	/// never runs A.2, e.g.) leaves this session ratcheting A.4 instead of
	/// stalled on a §A.5 it can never complete. The peer's own lag opens
	/// the reciprocal round too, deferred under the deployed-compatible
	/// profile until the peer's own A.5 has landed — observed as its leaf
	/// in our send-PQ presenting its current canonical id (protocol doc §4
	/// C2). Only the receive group's leaves trigger: reading our own
	/// send-PQ leaf here would be the deployed engine's own anomaly.
	func rekeyDue() -> Bool {
		guard let recvPQ = recvGroup?.pq, let sendPQ = sendGroup?.pq else { return false }
		return Self.opensRekey(
			ownLeafLags: ownLeafLagsHead(in: recvPQ),
			ownTargetFolded: ownRekeyTargetFolded(),
			peerLeafLags: peerLeafLagsHead(in: recvPQ),
			peerOwnA5Landed: !peerLeafLagsHead(in: sendPQ),
			profile: profile)
	}

	private func ownLeafLagsHead(in group: MLS.RFC9420.Group) -> Bool {
		guard let head = auth.mine.current else { return false }
		guard let leaf = try? Self.ownLeaf(of: group),
			let id = try? basicIdentifier(leaf.credential)
		else { return false }
		return id != head
	}

	/// Has the peer already canonicalized our current credential? Read off
	/// our own leaf in `recvGroup.classical` — the peer's view of us we
	/// mirror — rather than `auth.mine` itself, which advances the moment
	/// WE canonicalize, well before the peer has folded anything.
	private func ownRekeyTargetFolded() -> Bool {
		guard let recvClassical = recvGroup?.classical, let head = auth.mine.current else {
			return true
		}
		guard let leaf = try? Self.ownLeaf(of: recvClassical),
			let id = try? basicIdentifier(leaf.credential)
		else { return true }
		return id == head
	}

	/// The non-self leaf of `group` presenting an id other than the peer's
	/// current canonical one.
	private func peerLeafLagsHead(in group: MLS.RFC9420.Group) -> Bool {
		guard let head = auth.theirs.current else { return false }
		guard
			let entry = group.tree.nonBlankLeaves().first(where: {
				$0.index != group.myLeafIndex
			}),
			let leaf = try? MLS.RFC9420.LeafNode(mlsEncoded: entry.record.encoded),
			let id = try? basicIdentifier(leaf.credential)
		else { return false }
		return id != head
	}
}
