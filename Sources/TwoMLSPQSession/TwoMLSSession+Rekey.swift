import Foundation
import GermConvenience
import MLSCodec
import MLSCombiner
import MLSProfileRFC9420

// MARK: - §A.5 PQ re-key

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
/// The proposed leaf may present the SAME id and key (`.updated`, a plain
/// encryption-key-only refresh — `pqRekeyBegin`'s routine, non-rotating
/// case) or a changed presentation — the SAME id under a freshly-minted
/// signature key, or a move to an already-canonical credential id — which
/// swift-mls always reports as `.credentialReplaced` (its effect fires on
/// EITHER the id or the presented signing key changing), never `.updated`,
/// regardless of whether the id itself moved (group-rules rule 4 /
/// `valid_successor`'s same-id arm — protocol doc §1/§3/D6):
/// `pqRekeyRespond`'s id-based gate (`validatePQLeafMove`,
/// `CredentialAuthentication.swift`) checks this before the commit is even
/// built, `validateRekeyCommitEffects` validates the resulting shape, and
/// both `pqRekeyRespond`/`pqRekeyApply` re-adjudicate the actually-applied
/// effects as a backstop before any write-back. These checks run id-based
/// against the classical `AuthCore` (D2) — the PQ arms track no canonical
/// sequence of their own.
@available(iOS 26, macOS 26, *)
extension TwoMLSSession {
	/// The initiator (whoever holds `pqTurnMine`) begins an §A.5 round:
	/// propose a plain (non-rotating) self-Update into `recvGroup.pq` — the
	/// peer's own PQ group, mirrored here, and the one about to be re-keyed
	/// — and park it as a `0x1B` side-band frame. Idempotent while a begin
	/// is already outstanding, like `pqBootstrapBegin`.
	public mutating func pqRekeyBegin() throws -> SideBandResult {
		// Slice 11: the non-emittable gate.
		try ensureEstablishmentDelegated()
		if case .rekeyInitiated = pqInflight, let pending = pendingSideBand {
			let sealed = try sealSideBand(pending)
			advanceStateSeq()
			return SideBandResult(
				frame: sealed, update: try stateUpdate(kind: .checkpoint))
		}
		guard pqTurnMine, isFullyEstablished, pqInflight == nil, owedBind == nil,
			pendingProposal == nil, pendingSideBand == nil
		else {
			throw TwoMLSError.sessionNotReady
		}
		guard var recv = recvGroup, var recvPQ = recv.pq else {
			throw TwoMLSError.notEstablished
		}
		// No-custody guard, before anything is consumed.
		guard !noCustody.contains(.recvPQ) else {
			throw TwoMLSError.leafCustodyUnavailable
		}

		// D3: the Upd′ is a key-only move — the leaf keeps the id it
		// already presents, and mints a fresh signature key for it,
		// mirroring the classical routine offer's own shape.
		let ownPQID = try basicIdentifier(Self.ownLeaf(of: recvPQ).credential)
		let (signingKey, signatureKey) = try TwoMLSIdentity.mintSignatureKeypair()
		let freshKey = LeafKey(signingKey: signingKey, signatureKey: signatureKey)
		let (message, _) = try recvPQ.proposeUpdate(
			pqProvider,
			sign: MLS.RFC9420.signingClosure(
				pqProvider, current: try recvPQSigningKey(),
				new: freshKey.signingKey),
			framing: .publicMessage,
			newIdentity: MLS.RFC9420.NewSigningIdentity(
				credential: .basic(identity: ownPQID),
				signatureKey: freshKey.signatureKey))
		recv.pq = recvPQ
		recvGroup = recv
		var updatedLeafKeys = leafKeys
		updatedLeafKeys.recvPQ.replace(freshKey, for: ownPQID)
		leafKeys = updatedLeafKeys

		// (DEBUG only): a fault point AFTER the write-back above but
		// before the next throwing call — proves a fault here leaves
		// `recvGroup`/`leafKeys` fully written back.
		#if DEBUG
			if TwoMLSSessionTestHooks.shouldFault("pqRekeyBegin.afterWriteBack") {
				throw InjectedTestFault(name: "pqRekeyBegin.afterWriteBack")
			}
		#endif

		let updBytes = try message.mlsEncoded()
		let frame = Frames.encodePQRekeyUpd(updBytes)
		// The mint's own drop of a parked Upd′ (`SessionMigration.swift`'s
		// `droppedRekeyTarget` handling) already clears any `recvPQ.pending`
		// entry staged for it, unless it is a still-lagging leaf's rule-7
		// catch-up key.
		pqInflight = .rekeyInitiated(updMessage: updBytes)
		pendingSideBand = frame
		let sealed = try sealSideBand(frame)

		// Return cadence (slice 8a): stages an Upd′ into `recvGroup.pq` — no epoch
		// change, but the PQ tree's pending state changed → `.checkpoint`.
		advanceStateSeq()
		return SideBandResult(frame: sealed, update: try stateUpdate(kind: .checkpoint))
	}

	/// The committer — never the turn-holder (§13 M5: `!pqTurnMine`) —
	/// receives the peer's `0x1B` Upd′, verifies it against `sendGroup.pq`
	/// (the group actually being re-keyed), folds it into an `includePath:
	/// true` commit there — optionally carrying a fresh cross-party `0xFF02`
	/// PSK exported off `recvGroup.pq` (the initiator's own send-PQ mirror,
	/// event-driven off `lastCrossInjectedPQ`, §13) — and parks the
	/// result as a `0x1D` side-band frame. The proposer's leaf may keep its id
	/// (any signature-key change) or catch up to an already-canonical one
	/// (`validatePQLeafMove` against `auth.theirs`); the C1 announced id, when
	/// present, is cross-checked against the proposed leaf's id. Every check
	/// runs before any mutation, so a rejected round leaves `self` untouched.
	/// Every export/write-back is deferred to the success point after the
	/// commit lands (§13 M3): a throw above that discards the local
	/// `recv`/`send` copies untouched.
	public mutating func pqRekeyRespond(_ inbound: Data) throws -> SideBandResult {
		guard !pqTurnMine, pqInflight == nil, owedBind == nil else {
			throw TwoMLSError.sessionNotReady
		}
		guard var send = sendGroup, var sendPQ = send.pq else {
			throw TwoMLSError.notEstablished
		}
		guard var recv = recvGroup, recv.pq != nil else {
			throw TwoMLSError.notEstablished
		}
		// No-custody guard, before anything is consumed — this
		// door commits `sendGroup.pq`.
		guard !noCustody.contains(.sendPQ) else {
			throw TwoMLSError.leafCustodyUnavailable
		}
		// Entry (PR2): the peer's `0x1B` Upd′ arrives header-sealed.
		let frame = openOrRaw(inbound)

		return try withDeployedWireConventions {
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
			guard case .update(let leafNode) = verified.proposal,
				case .member(let senderLeaf) = verified.sender,
				senderLeaf != sendPQ.myLeafIndex
			else {
				throw TwoMLSError.rekeyProposalRejected
			}
			// Outside the id-check do/catch below: a capability-less leaf
			// throws its own distinct `.leafCapabilityUnadvertised`, never
			// folded into `.rekeyProposalRejected`.
			try TwoPartyRules.ensureAdvertisesAPQCapabilities(
				leafNode, codepoints: codepoints)
			// No AppBinding leaf-advert gate here (contrast
			// `validateOfferedUpdate`'s classical-side one): PQ halves carry
			// NO binding (rule 8, group-rules.md:71-72), so the
			// "binding-carrying group" predicate `sendPQ` would be gated on
			// is always false.
			// Id-based AS gate (protocol doc §1/§3/D6, group-rules rule 4): the
			// sender's PQ leaf may keep its id (any signature-key change) or
			// move to an already-canonical one — `validatePQLeafMove` against
			// `auth.theirs`, read off the sender's CURRENT occupant on the live
			// tree; any failure (a non-canonical id, or an unsupported
			// credential) is this call's respond error.
			guard
				let currentRecord = sendPQ.tree.leaf(at: senderLeaf),
				let currentLeaf = try? MLS.RFC9420.LeafNode(
					mlsEncoded: currentRecord.encoded)
			else {
				throw TwoMLSError.rekeyProposalRejected
			}
			let proposerOldID: Data
			let proposerNewID: Data
			do {
				proposerOldID = try basicIdentifier(currentLeaf.credential)
				proposerNewID = try basicIdentifier(leafNode.credential)
				try validatePQLeafMove(
					oldID: proposerOldID, newID: proposerNewID, in: auth.theirs)
			} catch {
				throw TwoMLSError.rekeyProposalRejected
			}
			// C1 (protocol doc §4): the deployed engine announces the
			// handed-off id in the Upd′'s authenticated data — kept only for
			// compatibility; the leaf credential above is authoritative. A
			// present value that disagrees with it is rejected; absent is fine.
			let announcedID = updPub.content.authenticatedData
			guard announcedID.isEmpty || announcedID == proposerNewID else {
				throw TwoMLSError.rekeyProposalRejected
			}

			var proposalStore = MLS.RFC9420.ProposalStore()
			let ref = try proposalStore.insert(verified, pqProvider)

			var pskStore = MLS.Combiner.PSKStore()
			var proposals: [MLS.RFC9420.ProposalOrRef] = [.reference(ref)]
			let recvPQEpoch = try recv.pq.tryUnwrap(TwoMLSError.notEstablished).context
				.epoch
			var crossInjectedEpoch: UInt64?
			if lastCrossInjectedPQ != recvPQEpoch {
				var recvPQForExport = try recv.pq.tryUnwrap(
					TwoMLSError.notEstablished)
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

			// D3: the committer's own send-PQ path leaf mints a fresh key
			// too, straight onto `mine.current` — this is where our own
			// leaf catches up when it lags (`protocol-flows.md:696-708`).
			// When it doesn't lag, `pathID` is just the id the leaf already
			// presents, so the move stays key-only, as before.
			let ownSendPQID = try basicIdentifier(Self.ownLeaf(of: sendPQ).credential)
			let pathID = auth.mine.current ?? ownSendPQID
			let (signingKey, signatureKey) = try TwoMLSIdentity.mintSignatureKeypair()
			let freshKey = LeafKey(signingKey: signingKey, signatureKey: signatureKey)
			let transition = try sendPQ.committing(
				pqProvider, proposals: proposals, proposalStore: proposalStore,
				sign: MLS.RFC9420.signingClosure(
					pqProvider, current: try sendPQSigningKey(),
					new: freshKey.signingKey),
				randomness: try .generate(pqProvider),
				includePath: true, framing: .publicMessage,
				psk: pskStore.resolver(),
				newIdentity: MLS.RFC9420.NewSigningIdentity(
					credential: .basic(identity: pathID),
					signatureKey: freshKey.signatureKey)
			)
			return try withTransitionHandoff(transition) { adopted, sent in
				let commitBytes = try sent.message.mlsEncoded()
				let pending = sent.takePending()
				try TwoPartyRules.validateRekeyCommitEffects(pending.effects)
				// Backstop (defense in depth): adjudicate every
				// `.credentialReplaced` this Commit′ ACTUALLY carries, on LOCAL
				// copies, before any write-back — the proposer's leaf against
				// `theirs`, and this session's own (committer's) leaf against
				// `mine`, which now moves here whenever it lags; see
				// `adjudicatePQRekeyEffects`.
				try Self.adjudicatePQRekeyEffects(
					pending.effects, myLeaf: sendPQ.myLeafIndex, auth: auth)
				let advanced = try pending.apply(onto: adopted)
				sendPQ = advanced.group
				try TwoPartyRules.ensureTwoParty(sendPQ)

				// D3: the committer's own send-PQ leaf just moved to the
				// fresh key this round minted — go straight to `current`.
				// Our own commit applies in this same call, so there is no
				// window where the leaf could still lag afterward, and so
				// no `pending` entry to retain (contrast the opener's own
				// leaf, which stages under `pending` until the peer's
				// Commit′ applies).
				var updatedLeafKeys = leafKeys
				updatedLeafKeys.sendPQ = GroupKeySet(current: freshKey)

				send.pq = sendPQ
				sendGroup = send
				leafKeys = updatedLeafKeys

				// (DEBUG only): a fault point AFTER the write-back above but
				// before the next throwing call — proves a fault here leaves
				// `sendGroup`/`leafKeys` fully written back.
				#if DEBUG
					if TwoMLSSessionTestHooks.shouldFault(
						"pqRekeyRespond.afterWriteBack")
					{
						throw InjectedTestFault(
							name: "pqRekeyRespond.afterWriteBack")
					}
				#endif
				// The committer's own advance of `sendGroup.pq` (PR2) — a second,
				// independent commit from the initiator's later `owePQBind` one.
				try recordPQHeaderKey()
				if let crossInjectedEpoch {
					recvGroup = recv
					lastCrossInjectedPQ = crossInjectedEpoch
				}

				let responseFrame = Frames.encodePQRekeyCommit(commitBytes)
				pqInflight = .rekeyResponded
				pendingSideBand = responseFrame
				let sealed = try sealSideBand(responseFrame)

				// Return cadence (slice 8a): committed `sendGroup.pq` → `.checkpoint`.
				advanceStateSeq()
				return SideBandResult(
					frame: sealed, update: try stateUpdate(kind: .checkpoint),
					rotatedCredential: proposerOldID == proposerNewID
						? nil : proposerNewID)
			}
		}
	}

	/// The initiator applies the committer's `0x1D` Commit′: re-verifies the
	/// parked Upd′ and re-inserts it into a fresh `ProposalStore` (§13 M1 —
	/// `validating` resolves a `.reference` only from the store this call
	/// itself supplies), pre-registers the committer's cross-party PSK off a
	/// throwaway copy of `sendGroup.pq` (§13 M3 — never written back, so a
	/// retry after a later failure re-derives the same value rather than
	/// risking `componentSecretConsumed` on the real group), validates the
	/// mechanical rekey effects, adjudicates every `.credentialReplaced` the
	/// Commit′ actually carries (`adjudicatePQRekeyEffects` — the committer
	/// against `theirs`, our own proposed leaf against `mine`), applies the
	/// Commit′ to `recvGroup.pq`, exports `S` off the freshly-rekeyed group,
	/// and owes the classical bind (`owePQBind(s:)`, slice 3 reuse). The
	/// adjudication failure modes: `.invalidSuccession` for a non-canonical
	/// id; a shape failure stays `.invalidRekeyEffects`; a non-`.basic`
	/// credential surfaces as `.unsupportedCredential`, unmapped — chosen
	/// over remapping it, since it is already its own distinct, meaningful
	/// error. Any of these leaves `pqInflight` untouched, so an honest
	/// re-sent Commit′ still applies.
	public mutating func pqRekeyApply(_ inbound: Data) throws -> StateUpdate {
		// Entry (PR2): the peer's `0x1D` Commit′ arrives header-sealed.
		let frame = openOrRaw(inbound)

		return try withDeployedWireConventions {
			// Decode first, then the fatal name, then every
			// state-shape guard — mirrors Rust's own PQ-door order
			// (`check_not_wedged` runs before the `pq_inflight`/etc. shape
			// checks at every door, `mod.rs`). This moves the guards that
			// used to precede the decode below it.
			let commitBytes = try Frames.decodePQRekeyCommit(frame)
			guard
				case .publicMessage(let commitPub) = try MLS.RFC9420.Message(
					mlsEncoded: commitBytes)
			else {
				throw TwoMLSError.malformedSideBandMessage
			}

			guard pqWedge == nil else { throw TwoMLSError.pqSideBandWedged }

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
			// No-custody guard, before anything is consumed — this
			// door's `owePQBind` commits `sendGroup.pq`.
			guard !noCustody.contains(.sendPQ) else {
				throw TwoMLSError.leafCustodyUnavailable
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
			var expectedApplicationStorageIDs: Set<Data> = []
			if needsPreRegister {
				var pqForExport = sendPQ
				let crossPSK = try MLS.Combiner.ExportedPsk.export(
					from: &pqForExport, pqProvider,
					componentID: Self.crossPartyComponentID)
				pskStore.register(crossPSK)
				expectedApplicationStorageIDs = [crossPSK.storageID]
			}

			// Exact-id allow-list: only the cross-party `0xFF02` this round
			// pre-registers (legitimately none, when this epoch's export was
			// already remembered), never an external PSK or the attestation
			// (the mechanical rekey carries no `AppDataUpdate`) — before
			// `validating`.
			guard case .commit(let commitValue) = commitPub.content.content else {
				throw TwoMLSError.malformedSideBandMessage
			}
			try TwoPartyRules.validateInlineProposals(
				commitValue.proposals,
				expectedApplicationStorageIDs: expectedApplicationStorageIDs,
				expectedExternalPSKIDs: [],
				allowAttestation: false)

			let pending: MLS.RFC9420.PendingCommit
			do {
				pending = try recvPQ.validating(
					pqProvider, commit: commitPub, proposals: proposalStore,
					psk: pskStore.resolver())
			} catch {
				throw TwoMLSError.decryptionFailed
			}
			try TwoPartyRules.validateRekeyCommitEffects(pending.effects)
			try Self.adjudicatePQRekeyEffects(
				pending.effects, myLeaf: recvPQ.myLeafIndex, auth: auth)
			let transition = try pending.apply(onto: recvPQ)
			recvPQ = transition.group
			try TwoPartyRules.ensureTwoParty(recvPQ)

			// Promote my own recv-PQ leaf's key if this
			// Commit′ moved its presentation (a hand-built/migrated Upd′
			// carrying a `newIdentity`; the routine self-driven proposal
			// never does) — a same-key apply is `promoted`'s own no-op.
			// Generalized catch-up: retain `pending[mine.current]` when
			// the recv-PQ leaf still lags it after this apply — the PQ half of rule 7,
			// which a migrated/lagging session needs for a later self-drive
			// to consume; every other pending entry is still dropped, same
			// as before.
			var updatedLeafKeys = leafKeys
			let ownPQLeaf = try Self.ownLeaf(of: recvPQ)
			let ownPQID = try basicIdentifier(ownPQLeaf.credential)
			try updatedLeafKeys.recvPQ.promoted(
				presenting: ownPQLeaf.signatureKey, id: ownPQID)
			if let mineCurrent = auth.mine.current, ownPQID != mineCurrent,
				let catchUpKey = updatedLeafKeys.recvPQ.pending[mineCurrent]
			{
				updatedLeafKeys.recvPQ.pending = [mineCurrent: catchUpKey]
			} else {
				updatedLeafKeys.recvPQ.pending = [:]
			}

			// §13 M2: export `S` off the just-rekeyed group and stamp the
			// watermark right after — mirrors `pqBootstrapJoin` (the export
			// consumes this exact `(group, epoch, component)` leaf).
			let recvPQEpochAfterRekey = recvPQ.context.epoch
			let sExport = try MLS.Combiner.ExportedPsk.export(
				from: &recvPQ, pqProvider, componentID: Self.crossPartyComponentID)
			recv.pq = recvPQ
			recvGroup = recv
			lastCrossInjectedPQ = recvPQEpochAfterRekey
			leafKeys = updatedLeafKeys

			// (DEBUG only): a fault point AFTER the write-back above but
			// before the next throwing call — proves a fault here leaves
			// `recvGroup`/`leafKeys`/`lastCrossInjectedPQ` fully written
			// back even though the classical bind is never discharged.
			#if DEBUG
				if TwoMLSSessionTestHooks.shouldFault(
					"pqRekeyApply.afterWriteBackBeforeBind")
				{
					throw InjectedTestFault(
						name: "pqRekeyApply.afterWriteBackBeforeBind")
				}
			#endif
			try owePQBind(s: sExport.psk)
			if needsPreRegister {
				lastSendPQExported = sendPQEpoch
			}
			pqInflight = nil
			pendingSideBand = nil

			// Return cadence (slice 8a): `owePQBind` just committed `sendGroup.pq`
			// (and this call committed `recvGroup.pq`) → `.checkpoint`.
			advanceStateSeq()
			return try stateUpdate(kind: .checkpoint)
		}
	}

	/// The §A.5 rekey Commit′'s own PQ-side leaf-move adjudication, shared by
	/// `pqRekeyRespond`'s backstop and `pqRekeyApply`'s own check — the
	/// id-based counterpart to `TwoMLSSession+ClassicalCommit.swift`'s
	/// `canonicalize` (`AuthCore.adjudicate`'s classical-side seam), since the
	/// PQ arms run no AS adjudication of their own. `myLeaf` names which
	/// leaf, in the SAME PQ group `effects` was computed against, is this
	/// session's own — a moved leaf other than `myLeaf` is adjudicated
	/// against `auth.theirs`, a moved `myLeaf` against `auth.mine`. Pure:
	/// never mutates `auth`, and never calls `commit` (`validatePQLeafMove`
	/// doesn't either) — this is a check, not a canonicalization; the PQ AS
	/// has no persisted sequence of its own to advance.
	private static func adjudicatePQRekeyEffects(
		_ effects: MLS.RFC9420.CommitEffects, myLeaf: MLS.LeafIndex, auth: AuthCore
	) throws {
		for event in effects.events {
			guard case .credentialReplaced(let leaf, let old, let new) = event else {
				continue
			}
			// A non-`.basic` credential throws `.unsupportedCredential` here,
			// unmapped — this protocol layer's leaves never advertise
			// anything else, and it is already its own distinct error.
			let oldID = try basicIdentifier(old.credential)
			let newID = try basicIdentifier(new.credential)
			try validatePQLeafMove(
				oldID: oldID, newID: newID,
				in: leaf == myLeaf ? auth.mine : auth.theirs)
		}
	}
}
