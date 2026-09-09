import Foundation
import MLSCodec
import MLSCombiner
import MLSProfileRFC9420

// MARK: - §A.5 PQ re-key (mechanical — no credential rotation; Chunk 2)

/// Host tag routing for every side-band frame this module parks or expects:
/// `0x03` `processIncoming` (app message); `0x13`/`0x15` bootstrap
/// (`pqBootstrapRespond`/`pqBootstrapJoin`); `0x17`/`0x19` ratchet
/// (`pqRatchetRespond`/`pqRatchetBind`); `0x1B`/`0x1D` re-key
/// (`pqRekeyRespond`/`pqRekeyApply`, this section). A host dispatches on the
/// frame's leading tag byte; `pqPendingOutbound()` peeks whichever of these
/// this session has parked.
///
/// A §A.5 round re-keys ONE PQ group with a standalone `updatePath` Commit′,
/// ending in the reused A.4/A.3 bind: the turn-holder (INITIATOR) proposes a
/// plain self-Update into her `recvGroup.pq` mirror (`pqRekeyBegin`); the
/// peer (COMMITTER) folds it into an `includePath: true` commit on the
/// group it actually owns — `sendGroup.pq` (`pqRekeyRespond`); the
/// initiator applies that Commit′, exports `S` off the freshly-rekeyed
/// group, and owes the classical bind (`pqRekeyApply`, reusing `owePQBind`).
/// This mechanical form carries no credential/signature-key rotation — every
/// leaf keeps its identity (`.updated`, never `.credentialReplaced`); that
/// handoff is Chunk 2 (§15).
@available(iOS 26, macOS 26, *)
extension TwoMLSSession {
	/// The initiator (whoever holds `pqTurnMine`) begins an §A.5 round:
	/// propose a plain (non-rotating) self-Update into `recvGroup.pq` — the
	/// peer's own PQ group, mirrored here, and the one about to be re-keyed
	/// — and park it as a `0x1B` side-band frame. Idempotent while a begin
	/// is already outstanding, like `pqBootstrapBegin`.
	public mutating func pqRekeyBegin() throws -> Data {
		if case .rekeyInitiated = pqInflight, let pending = pendingSideBand {
			return pending
		}
		guard pqTurnMine, isFullyEstablished, pqInflight == nil, owedBind == nil,
			pendingProposal == nil, pendingSideBand == nil
		else {
			throw TwoMLSError.sessionNotReady
		}
		guard var recv = recvGroup, var recvPQ = recv.pq else {
			throw TwoMLSError.notEstablished
		}

		let (message, _) = try recvPQ.proposeUpdate(
			pqProvider, signingKey: identity.signingKey, framing: .publicMessage)
		recv.pq = recvPQ
		recvGroup = recv

		let updBytes = try message.mlsEncoded()
		let frame = Frames.encodePQRekeyUpd(updBytes)
		pqInflight = .rekeyInitiated(updMessage: updBytes)
		pendingSideBand = frame
		return frame
	}

	/// The committer — never the turn-holder (§13 M5: `!pqTurnMine`) —
	/// receives the peer's `0x1B` Upd′, verifies it against `sendGroup.pq`
	/// (the group actually being re-keyed), folds it into an `includePath:
	/// true` commit there — optionally carrying a fresh cross-party `0xFF02`
	/// PSK exported off `recvGroup.pq` (the initiator's own send-PQ mirror,
	/// event-driven off `lastCrossInjectedPQ`, §13 F3) — and parks the
	/// result as a `0x1D` side-band frame. Every export/write-back is
	/// deferred to the success point after the commit lands (§13 M3): a
	/// throw above that discards the local `recv`/`send` copies untouched.
	public mutating func pqRekeyRespond(_ frame: Data) throws -> Data {
		guard !pqTurnMine, pqInflight == nil, owedBind == nil else {
			throw TwoMLSError.sessionNotReady
		}
		guard var send = sendGroup, var sendPQ = send.pq else {
			throw TwoMLSError.notEstablished
		}
		guard var recv = recvGroup, recv.pq != nil else {
			throw TwoMLSError.notEstablished
		}

		return try withDeployedWireWidth {
			let updBytes = try Frames.decodePQRekeyUpd(frame)
			guard
				case .publicMessage(let updPub) = try MLS.RFC9420.Message(
					mlsEncoded: updBytes)
			else {
				throw TwoMLSError.malformedSideBandMessage
			}

			let verified: MLS.RFC9420.VerifiedProposal
			do {
				verified = try sendPQ.verifying(pqProvider, proposal: updPub)
			} catch {
				throw TwoMLSError.decryptionFailed
			}
			guard case .update = verified.proposal,
				case .member(let senderLeaf) = verified.sender,
				senderLeaf != sendPQ.myLeafIndex
			else {
				throw TwoMLSError.rekeyProposalRejected
			}

			var proposalStore = MLS.RFC9420.ProposalStore()
			let ref = try proposalStore.insert(verified, pqProvider)

			var pskStore = MLS.Combiner.PSKStore()
			var proposals: [MLS.RFC9420.ProposalOrRef] = [.reference(ref)]
			let recvPQEpoch = recv.pq!.context.epoch
			var crossInjectedEpoch: UInt64?
			if lastCrossInjectedPQ != recvPQEpoch {
				var recvPQForExport = recv.pq!
				let crossPSK = try MLS.Combiner.ExportedPsk.export(
					from: &recvPQForExport, pqProvider,
					componentID: Self.crossPartyComponentID)
				recv.pq = recvPQForExport
				pskStore.register(crossPSK)
				proposals.append(
					.proposal(
						crossPSK.proposal(
							nonce: pqProvider.randomBytes(
								pqProvider.hashSize))))
				crossInjectedEpoch = recvPQEpoch
			}

			let transition = try sendPQ.committing(
				pqProvider, proposals: proposals, proposalStore: proposalStore,
				signingKey: identity.signingKey,
				randomness: try .generate(pqProvider),
				includePath: true, framing: .publicMessage, psk: pskStore.resolver()
			)
			let adopted = transition.group
			let sent = transition.takeOutput()
			let commitBytes = try sent.message.mlsEncoded()
			let pending = sent.takePending()
			try TwoPartyRules.validateRekeyCommitEffects(pending.effects)
			let advanced = try pending.apply(onto: adopted)
			sendPQ = advanced.group
			try TwoPartyRules.ensureTwoParty(sendPQ)

			send.pq = sendPQ
			sendGroup = send
			if let crossInjectedEpoch {
				recvGroup = recv
				lastCrossInjectedPQ = crossInjectedEpoch
			}

			let responseFrame = Frames.encodePQRekeyCommit(commitBytes)
			pqInflight = .rekeyResponded
			pendingSideBand = responseFrame
			return responseFrame
		}
	}

	/// The initiator applies the committer's `0x1D` Commit′: re-verifies the
	/// parked Upd′ and re-inserts it into a fresh `ProposalStore` (§13 M1 —
	/// `validating` resolves a `.reference` only from the store this call
	/// itself supplies), pre-registers the committer's cross-party PSK off a
	/// throwaway copy of `sendGroup.pq` (§13 M3 — never written back, so a
	/// retry after a later failure re-derives the same value rather than
	/// risking `componentSecretConsumed` on the real group), validates the
	/// mechanical rekey effects, applies the Commit′ to `recvGroup.pq`,
	/// exports `S` off the freshly-rekeyed group, and owes the classical
	/// bind (`owePQBind(s:)`, slice 3 reuse).
	public mutating func pqRekeyApply(_ frame: Data) throws {
		guard pendingProposal == nil, owedBind == nil else {
			throw TwoMLSError.sessionNotReady
		}
		guard case .rekeyInitiated(let updMessage) = pqInflight else {
			throw TwoMLSError.sessionNotReady
		}
		guard var recv = recvGroup, var recvPQ = recv.pq else {
			throw TwoMLSError.notEstablished
		}
		guard let sendPQ = sendGroup?.pq else { throw TwoMLSError.notEstablished }

		try withDeployedWireWidth {
			let commitBytes = try Frames.decodePQRekeyCommit(frame)
			guard
				case .publicMessage(let commitPub) = try MLS.RFC9420.Message(
					mlsEncoded: commitBytes)
			else {
				throw TwoMLSError.malformedSideBandMessage
			}
			guard
				case .publicMessage(let updPub) = try MLS.RFC9420.Message(
					mlsEncoded: updMessage)
			else {
				throw TwoMLSError.malformedSideBandMessage
			}

			let verifiedUpd: MLS.RFC9420.VerifiedProposal
			do {
				verifiedUpd = try recvPQ.verifying(pqProvider, proposal: updPub)
			} catch {
				throw TwoMLSError.decryptionFailed
			}
			var proposalStore = MLS.RFC9420.ProposalStore()
			_ = try proposalStore.insert(verifiedUpd, pqProvider)

			let sendPQEpoch = sendPQ.context.epoch
			var pskStore = MLS.Combiner.PSKStore()
			let needsPreRegister = lastSendPQExported != sendPQEpoch
			if needsPreRegister {
				var pqForExport = sendPQ
				let crossPSK = try MLS.Combiner.ExportedPsk.export(
					from: &pqForExport, pqProvider,
					componentID: Self.crossPartyComponentID)
				pskStore.register(crossPSK)
			}

			let pending: MLS.RFC9420.PendingCommit
			do {
				pending = try recvPQ.validating(
					pqProvider, commit: commitPub, proposals: proposalStore,
					psk: pskStore.resolver())
			} catch {
				throw TwoMLSError.decryptionFailed
			}
			try TwoPartyRules.validateRekeyCommitEffects(pending.effects)
			let transition = try pending.apply(onto: recvPQ)
			recvPQ = transition.group
			try TwoPartyRules.ensureTwoParty(recvPQ)

			// §13 M2: export `S` off the just-rekeyed group and stamp the
			// watermark right after — mirrors `pqBootstrapJoin` (the export
			// consumes this exact `(group, epoch, component)` leaf).
			let recvPQEpochAfterRekey = recvPQ.context.epoch
			let sExport = try MLS.Combiner.ExportedPsk.export(
				from: &recvPQ, pqProvider, componentID: Self.crossPartyComponentID)
			recv.pq = recvPQ
			recvGroup = recv
			lastCrossInjectedPQ = recvPQEpochAfterRekey

			try owePQBind(s: sExport.psk)
			if needsPreRegister {
				lastSendPQExported = sendPQEpoch
			}
			pqInflight = nil
			pendingSideBand = nil
		}
	}
}
