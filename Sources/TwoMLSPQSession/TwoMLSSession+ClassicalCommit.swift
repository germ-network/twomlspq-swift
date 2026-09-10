import Foundation
import MLSCodec
import MLSCombiner
import MLSExtensions
import MLSProfileRFC9420

// MARK: - Send / receive (one app message; no commit) — classical fold/bind commit machinery

@available(iOS 26, macOS 26, *)
extension TwoMLSSession {
	/// §3a: approve the peer's currently-offered `Upd(self)` (identified by its
	/// digest), for `committingRound` to fold into the next commit. Matches
	/// only the LAST offer `processIncoming` surfaced — a digest that does not
	/// match (including "nothing offered") is `.proposalRejected`, never a
	/// silent no-op (§11, matching the Rust reference). Validated against
	/// `sendGroup.classical` — the group `committingRound` will actually fold
	/// it into — without disturbing that group otherwise: a rejected approval
	/// leaves `offeredProposal` intact (restored) so a later, different digest
	/// can still be approved.
	public mutating func queueProposal(digest: Data) throws {
		guard let offered = offeredProposal, offered.digest == digest else {
			throw TwoMLSError.proposalRejected
		}
		offeredProposal = nil
		do {
			try validateOfferedUpdate(offered)
		} catch {
			offeredProposal = offered
			throw error
		}
		queuedProposal = offered
	}

	/// The validation `queueProposal` (and, defensively, `committingRound`)
	/// runs on an offered Upd, without mutating any group except (slice 6) the
	/// AS's own bookkeeping: `send.classical.verifying(proposal:)`
	/// (non-consuming for a `PublicMessage`) authenticates the framing; the
	/// verified proposal must be a peer `.update` (`.member` sender, not this
	/// session's own leaf); its verified `.basic` identity must match the
	/// frame's unauthenticated `proposing` claim (§11 MF5 — `proposing` rides
	/// outside the AAD, so the wire claim alone proves nothing); and — slice 6
	/// — when its leaf's credential/signature key differs from the current
	/// occupant's (a `.credentialReplaced` shape), the peer's OWN rotation
	/// must be a valid successor of the peer's canonical head. Reject a peer
	/// naming one of MY OWN known ids outright (never a legitimate successor
	/// of THEIRS) before ever authorizing it — `theirs.validSuccessor` alone
	/// cannot see `mine`'s sequence, so this closes that gap explicitly. AS
	/// consult point 1 (slice 6): `auth.theirs.authorize` records the offer
	/// BEFORE `validSuccessorOfCurrent` gates it — `PartySequence.
	/// validSuccessor`'s own rollback check (an authorized-but-retired id
	/// falls through to the ordering check and is rejected) is what actually
	/// polices this, not the authorize call itself, so the ordering must be
	/// authorize-then-check for a genuinely NEW id to ever pass at all — a
	/// same-id "rotation" (`offeredID == theirs.current`, a key-only
	/// rotation or a genuine no-op) skips the authorize call entirely
	/// instead: `validSuccessorOfCurrent` already accepts it trivially
	/// (`pred == succ`), and authorizing an already-current id would
	/// otherwise leak into `authorizedNext` forever — `PartySequence.
	/// commit`'s own `current == id` early return never clears it. Value
	/// semantics: `auth` is mutated on a local copy, written back only
	/// once every check has passed, so a throw here leaves `self.auth`
	/// untouched exactly like a rejected digest leaves `offeredProposal`
	/// untouched (`queueProposal`'s own restore).
	private mutating func validateOfferedUpdate(
		_ offered: (digest: Data, proposing: Data, message: Data)
	) throws {
		guard let send = sendGroup else { throw TwoMLSError.proposalRejected }
		try withDeployedWireConventions {
			guard
				let offeredMessage = try? MLS.RFC9420.Message(
					mlsEncoded: offered.message),
				case .publicMessage(let updatePub) = offeredMessage
			else {
				throw TwoMLSError.proposalRejected
			}
			let verified: MLS.RFC9420.VerifiedProposal
			do {
				verified = try send.classical.verifying(
					classicalProvider, proposal: updatePub)
			} catch {
				throw TwoMLSError.proposalRejected
			}
			guard case .update(let leafNode) = verified.proposal,
				case .member(let senderLeaf) = verified.sender,
				senderLeaf != send.classical.myLeafIndex
			else {
				throw TwoMLSError.proposalRejected
			}
			guard let currentRecord = send.classical.tree.leaf(at: senderLeaf) else {
				throw TwoMLSError.proposalRejected
			}
			let currentLeaf = try MLS.RFC9420.LeafNode(
				mlsEncoded: currentRecord.encoded)
			guard case .basic(let offeredID) = leafNode.credential,
				offeredID == offered.proposing
			else {
				throw TwoMLSError.proposalRejected
			}

			let presentationChanged =
				currentLeaf.credential != leafNode.credential
				|| currentLeaf.signatureKey != leafNode.signatureKey
			guard presentationChanged else { return }

			guard !auth.mine.knownIDs.contains(offeredID) else {
				throw TwoMLSError.invalidSuccession
			}
			var authCopy = auth
			// CODE FIX 2: a same-id "rotation" is a no-op, not a new
			// authorization — authorizing it would leak into
			// `authorizedNext` forever, since `PartySequence.commit`'s own
			// `current == id` early return never clears it.
			if offeredID != authCopy.theirs.current {
				authCopy.theirs.authorize(offeredID)
			}
			guard authCopy.theirs.validSuccessorOfCurrent(offeredID) else {
				throw TwoMLSError.invalidSuccession
			}
			auth = authCopy
		}
	}

	/// Shared by the `0x00` fold-only arm and the `0x05` bind arm (§11 MF7 —
	/// Rust's own `staple_epoch_action`, factored out so the two arms cannot
	/// drift): behind the receive group's live epoch is an idempotent re-ride
	/// (the staple rides every frame until the sender's next commit) and a
	/// skip; ahead of it is `.epochDesync`; equal is the one live application.
	enum StapleEpochAction { case skip, apply }

	private static func classifyStapleEpoch(commitEpoch: UInt64, currentEpoch: UInt64) throws
		-> StapleEpochAction
	{
		if commitEpoch < currentEpoch { return .skip }
		guard commitEpoch == currentEpoch else { throw TwoMLSError.epochDesync }
		return .apply
	}

	/// §11 MF3: re-`verifying`+`insert` every `Upd(self)` staged into
	/// `recvGroup.classical` at its current epoch into a FRESH `ProposalStore`
	/// — swift-mls keeps no cross-call proposal cache (§13 M1), so
	/// `validating` can only resolve a commit's by-reference fold from a store
	/// THIS call supplies. A stale/foreign/tampered entry simply fails to
	/// verify and is skipped — `verifying` itself epoch-checks, so dropping it
	/// is harmless, not a required decode.
	private func rebuildStagedProposalStore(against classical: MLS.RFC9420.Group)
		-> MLS.RFC9420.ProposalStore
	{
		var store = MLS.RFC9420.ProposalStore()
		for staged in stagedUpdates {
			guard
				case .publicMessage(let stagedPub) = try? MLS.RFC9420.Message(
					mlsEncoded: staged.message),
				let verified = try? classical.verifying(
					classicalProvider, proposal: stagedPub)
			else {
				continue
			}
			_ = try? store.insert(verified, classicalProvider)
		}
		return store
	}

	/// §11 MF4: export+ledger `classical`'s CURRENT-epoch `0xFF02` cross-party
	/// PSK into `ledger`, unless that epoch is already there — mirrors the
	/// Rust `remember_send_psk`. Pure with respect to `self`: both parameters
	/// are `inout` local copies the caller owns, so a caller can discard both
	/// on failure and a retry re-derives (or re-reuses the ledgered value)
	/// cleanly — the -02 exporter tree consumes a `(group, epoch, component)`
	/// leaf on first export, so re-exporting an already-ledgered epoch would
	/// throw `componentSecretConsumed`.
	private func rememberSendCrossPSK(
		classical: inout MLS.RFC9420.Group,
		ledger: inout [UInt64: MLS.Combiner.ExportedPsk]
	) throws {
		let epoch = classical.context.epoch
		guard ledger[epoch] == nil else { return }
		let exported = try MLS.Combiner.ExportedPsk.export(
			from: &classical, classicalProvider, componentID: Self.crossPartyComponentID
		)
		ledger[epoch] = exported
		if ledger.count > Self.sendCrossPSKLedgerWindow {
			for evict in ledger.keys.sorted().prefix(
				ledger.count - Self.sendCrossPSKLedgerWindow)
			{
				ledger[evict] = nil
			}
		}
	}

	/// F4/§3c, slice 6: does `send`'s own classical leaf lag the canonical
	/// principal `candidate` already achieved on `recv`'s own leaf (the FIRST
	/// leaf to canonicalize a rotation, per `applyFoldCommit`/`applyBind`)?
	/// Both reads are tree-derived (never a cached claim), so this can never
	/// disagree with what the resolvers would sign with. `nil` when there is
	/// no outstanding candidate, either group is absent, or the send-leaf
	/// already presents the canonical id.
	private static func ownLeafCatchUpTarget(
		send: APQGroup?, recv: APQGroup?, candidate: RotationCandidate?
	) throws -> RotationCandidate? {
		guard let candidate, let send, let recv else { return nil }
		let sendOwnID = try basicIdentifier(Self.ownLeaf(of: send.classical).credential)
		guard sendOwnID != candidate.clientID else { return nil }
		let canonicalID = try basicIdentifier(Self.ownLeaf(of: recv.classical).credential)
		guard canonicalID == candidate.clientID else { return nil }
		return candidate
	}

	/// §3b/§11 MF6: a committing round on `sendGroup.classical` — folds the
	/// approved peer Update (`queuedProposal`, when present: a fold needs no
	/// license, since `queueProposal` already verified it against the live
	/// send group, and holding it IS the evidence), discharges an owed PQ
	/// bind (when `owedBind != nil` AND licensed), and/or — slice 6 — catches
	/// up my own send-leaf's presentation to my canonical principal
	/// (`ownLeafCatchUpTarget`, when it lags). Any of the three alone is
	/// enough to trigger a commit (the catch-up-only trigger is new: a plain
	/// `prepareToEncrypt()` with nothing queued or owed must still fire a
	/// commit once a rotation has canonicalized my recv-leaf but not yet my
	/// send-leaf). An owed bind rides ANY committing round this triggers,
	/// licensed or not (MF6): a fold (or a catch-up) that commits advances
	/// `sendGroup.classical` regardless, which would make an owed bind's
	/// reserved epoch stale and doom it, so any of those that commits must
	/// carry an outstanding bind along. Staple selection keys off `owed !=
	/// nil` (→ `0x05`), not `didCommit` (MF6). Reports whether a commit
	/// happened, and — fold only — the folded peer leaf's verified identity
	/// (MF5, never the unauthenticated wire `proposing`).
	// internal: used by Messaging.prepareToEncrypt
	internal mutating func committingRound() throws -> (
		didCommit: Bool, committedRemoteClientID: Data?
	) {
		let folded = queuedProposal
		let owed = owedBind
		let licensed: Bool
		if let peerApplied = peerAppliedSendEpoch, let send = sendGroup {
			licensed = peerApplied >= send.classical.context.epoch
		} else {
			licensed = false
		}
		// The `folded != nil ||` disjunct is DEFENSIVE and unreachable via the
		// public API today: a queued fold implies the peer already applied our
		// send epoch, so `licensed` is already true whenever `folded != nil`.
		// It stays so a fold can never strand an owed bind by advancing the
		// epoch without discharging it, should that invariant ever change.
		let willDischargeBind = owed != nil && (folded != nil || licensed)
		let catchUpCandidate = try Self.ownLeafCatchUpTarget(
			send: sendGroup, recv: recvGroup, candidate: rotationCandidate)
		guard folded != nil || willDischargeBind || catchUpCandidate != nil else {
			return (false, nil)
		}
		guard var send = sendGroup else { throw TwoMLSError.notEstablished }

		return try withDeployedWireConventions {
			var proposalStore = MLS.RFC9420.ProposalStore()
			var proposals: [MLS.RFC9420.ProposalOrRef] = []
			var store = MLS.Combiner.PSKStore()
			var committedRemoteClientID: Data?
			var pqCommitMessageForStaple: Data?
			// Slice 6, value semantics: `theirs.commit` can throw
			// (`.credentialRollback`), so it lands on a local copy, written
			// back only alongside `sendGroup`/etc. at this round's own
			// success point below.
			var authCopy = auth

			if let folded {
				guard
					let foldedMessage = try? MLS.RFC9420.Message(
						mlsEncoded: folded.message),
					case .publicMessage(let updatePub) = foldedMessage
				else {
					throw TwoMLSError.invalidFoldEffects
				}
				let verified: MLS.RFC9420.VerifiedProposal
				do {
					verified = try send.classical.verifying(
						classicalProvider, proposal: updatePub)
				} catch {
					throw TwoMLSError.invalidFoldEffects
				}
				guard case .update(let leafNode) = verified.proposal,
					case .basic(let remoteIdentity) = leafNode.credential
				else {
					throw TwoMLSError.invalidFoldEffects
				}
				let ref = try proposalStore.insert(verified, classicalProvider)
				proposals.append(.reference(ref))
				committedRemoteClientID = remoteIdentity
				// AS consult point 2 (slice 6): canonicalize the peer's
				// identity in OUR ledger BEFORE this commit is built —
				// idempotent (a no-op) for a routine, non-rotating fold,
				// since `remoteIdentity == theirs.current` already.
				try authCopy.theirs.commit(remoteIdentity)
			}

			if willDischargeBind {
				guard let owedValue = owed, let sendPQHalf = send.pq else {
					throw TwoMLSError.notEstablished
				}
				guard send.classical.context.epoch + 1 == owedValue.tEpoch,
					sendPQHalf.context.epoch == owedValue.pqEpoch
				else {
					throw TwoMLSError.epochDesync
				}

				var pqForExport = sendPQHalf
				let apqPSK = try MLS.Combiner.ExportedPsk.export(
					from: &pqForExport, pqProvider,
					componentID: codepoints.apqComponentID)
				send.pq = pqForExport
				store.register(apqPSK)

				let attestation = MLS.Combiner.ApqInfoUpdate(
					tEpoch: owedValue.tEpoch, pqEpoch: owedValue.pqEpoch)
				proposals.append(
					.proposal(
						apqPSK.proposal(
							nonce: classicalProvider.randomBytes(
								classicalProvider.hashSize))))
				// Deployed Rust carries this as an mls-rs `CustomProposal` —
				// `0x0008 ‖ opaque<V>(body)` — not swift-mls's typed,
				// unwrapped `.appDataUpdate` arm. `.custom` reproduces that
				// wrapper byte-for-byte.
				proposals.append(
					.proposal(
						.custom(
							type: .init(.appDataUpdate),
							body: try attestation.appDataUpdate(
								componentID: codepoints
									.apqComponentID
							).mlsEncoded())))
				pqCommitMessageForStaple = owedValue.pqCommitMessage
			}

			if var recv = recvGroup, recv.classical.context.epoch != lastCrossInjected {
				var crossForExport = recv.classical
				let crossPSK = try MLS.Combiner.ExportedPsk.export(
					from: &crossForExport, classicalProvider,
					componentID: Self.crossPartyComponentID)
				recv.classical = crossForExport
				recvGroup = recv
				store.register(crossPSK)
				lastCrossInjected = crossForExport.context.epoch
				proposals.append(
					.proposal(
						crossPSK.proposal(
							nonce: classicalProvider.randomBytes(
								classicalProvider.hashSize))))
			}

			// §11 MF4: remember the departing send epoch's own `0xFF02` export
			// BEFORE committing past it — an unlicensed fold needs no
			// evidence of the peer's progress, so a peer frame referencing
			// this exact epoch may still be in flight.
			var ledger = sendCrossPSKLedger
			try rememberSendCrossPSK(classical: &send.classical, ledger: &ledger)

			// F4/§3c: the own-leaf catch-up threads the rotation ring +
			// `newIdentity` through this SAME commit machinery — the ring's
			// `.framedContent` stays on the CURRENT (still-OLD) send key, so
			// the enclosing commit envelope verifies against the pre-commit
			// sender leaf; `.leafNode`/`.groupInfo` route to the candidate's
			// NEW key. Absent a catch-up, the single-key sugar over the
			// resolved current key suffices (identical to CP0/CP1).
			let sign: MLS.RFC9420.SigningClosure
			let newIdentity: MLS.RFC9420.NewSigningIdentity?
			if let catchUpCandidate {
				sign = MLS.RFC9420.signingClosure(
					classicalProvider, current: try sendClassicalSigningKey(),
					new: catchUpCandidate.signingKey)
				newIdentity = MLS.RFC9420.NewSigningIdentity(
					credential: .basic(identity: catchUpCandidate.clientID),
					signatureKey: catchUpCandidate.signatureKey)
			} else {
				sign = MLS.RFC9420.signingClosure(
					classicalProvider, try sendClassicalSigningKey())
				newIdentity = nil
			}

			let transition = try send.classical.committing(
				classicalProvider, proposals: proposals,
				proposalStore: proposalStore,
				sign: sign,
				randomness: try .generate(classicalProvider), includePath: true,
				framing: .publicMessage, psk: store.resolver(),
				newIdentity: newIdentity)
			let adopted = transition.group
			let sent = transition.takeOutput()
			let commitBytes = try sent.message.mlsEncoded()
			let pending = sent.takePending()
			let effects = pending.effects

			if willDischargeBind {
				try TwoPartyRules.validateBindClassicalEffects(
					effects, foldedPeerUpdate: folded != nil)
			} else {
				try TwoPartyRules.validateTwoPartyUpdateCommit(
					effects, foldedPeerUpdate: folded != nil,
					allowAppDataUpdate: false,
					orThrow: .invalidFoldEffects)
			}

			let advanced = try pending.apply(onto: adopted)
			send.classical = advanced.group
			// Should-fix (slice 6 review): symmetry with every apply arm's
			// own `ensureTwoParty(recv.classical)` — cheap and catches a
			// construction bug on the send side just as fast.
			try TwoPartyRules.ensureTwoParty(send.classical)

			// MF4: also remember the newly-landed epoch, so a crossed peer
			// commit referencing it still resolves even if this session
			// commits again before that peer commit arrives.
			try rememberSendCrossPSK(classical: &send.classical, ledger: &ledger)

			sendGroup = send
			sendCrossPSKLedger = ledger
			auth = authCopy

			if let pqCommitMessageForStaple {
				currentStaple = Frames.encodeAPQPrivateMessage(
					t: commitBytes, pq: pqCommitMessageForStaple)
				owedBind = nil
				pqTurnMine = false
			} else {
				currentStaple = Frames.encodeMlsMessageStaple(commitBytes)
			}
			// Either way this round is now fully spent: the fold it carried
			// (if any) is consumed, and any still-unapproved offer is bound
			// to the epoch this commit just left behind (§11 MF8's "the peer
			// re-proposes at the new epoch once it sees this commit's
			// staple").
			queuedProposal = nil
			offeredProposal = nil
			return (true, committedRemoteClientID)
		}
	}

	/// §3c/checkpoint 3: the `0x00` fold-only commit staple apply arm.
	/// Classifies the commit's epoch against `recvGroup.classical`'s live
	/// epoch (the shared classifier, MF7) before consuming anything;
	/// re-inserts every staged `Upd(self)` (MF3) so the commit's by-reference
	/// fold resolves regardless of which staged Upd the peer approved;
	/// live-injects the send-group `0xFF02` ledger (MF4); validates the
	/// fold-only effects shape; applies; `ensureTwoParty`. Value semantics:
	/// only local `recv`/`send`/`ledger` copies are touched, written back to
	/// `self` on success — any throw above that point burns no state.
	// internal: used by Messaging.handleStaple
	internal mutating func applyFoldCommit(_ commitBytes: Data) throws -> StapleApplyResult {
		// The commit's injected `0xFF02` PSK is `ComponentID`-bearing, like
		// the `0x05` bind's — decode and construct at the deployed width
		// (§11 #6/MF7), so the whole body lives in one scope.
		try withDeployedWireConventions {
			guard
				case .publicMessage(let commitPub) = try MLS.RFC9420.Message(
					mlsEncoded: commitBytes)
			else {
				throw TwoMLSError.malformedSideBandMessage
			}
			guard var recv = recvGroup else { throw TwoMLSError.notEstablished }

			switch try Self.classifyStapleEpoch(
				commitEpoch: commitPub.content.epoch,
				currentEpoch: recv.classical.context.epoch)
			{
			case .skip: return .notApplied
			case .apply: break
			}

			// Slice 6: a `0x00` staple may now be EITHER a folded peer
			// Update/rotation OR a solo own-leaf catch-up (`committingRound`'s
			// third trigger, §3c) — purely structural, mirroring `applyBind`'s
			// own `foldedPeerUpdate` detection, never a trusted claim.
			guard case .commit(let commitValue) = commitPub.content.content else {
				throw TwoMLSError.malformedSideBandMessage
			}
			let foldedPeerUpdate = commitValue.proposals.contains { entry in
				if case .reference = entry { return true }
				return false
			}

			let proposalStore = rebuildStagedProposalStore(against: recv.classical)

			guard var send = sendGroup else { throw TwoMLSError.notEstablished }
			var ledger = sendCrossPSKLedger
			var store = MLS.Combiner.PSKStore()
			try rememberSendCrossPSK(classical: &send.classical, ledger: &ledger)
			for exported in ledger.values { store.register(exported) }

			let pending = try recv.classical.validating(
				classicalProvider, commit: commitPub, proposals: proposalStore,
				psk: store.resolver())
			let effects = pending.effects
			try TwoPartyRules.validateTwoPartyUpdateCommit(
				effects, foldedPeerUpdate: foldedPeerUpdate,
				allowAppDataUpdate: false,
				orThrow: .invalidFoldEffects)
			// AS consult point 3 (slice 6): every `.credentialReplaced` effect
			// this commit carries — my own leaf catching up, and/or the
			// peer's own-leaf catch-up — validated BEFORE the group advances.
			try auth.adjudicate(effects)
			let myLeaf = recv.classical.myLeafIndex
			let advanced = try pending.apply(onto: recv.classical)
			recv.classical = advanced.group
			try TwoPartyRules.ensureTwoParty(recv.classical)

			// Value semantics extend to `auth` (§11's discipline, slice 6):
			// `canonicalize` is pure and can throw (a rollback `commit`
			// would), so it is computed into a local copy and written back
			// only alongside `recv`/`send` below — a throw above burns none
			// of `recv`, `send`, or `auth`.
			let (authCopy, newSender, ownCanonicalized) = try Self.canonicalize(
				effects, myLeaf: myLeaf, from: auth)

			recvGroup = recv
			sendGroup = send
			sendCrossPSKLedger = ledger
			stagedUpdates = []
			auth = authCopy
			return StapleApplyResult(
				applied: true, newSender: newSender,
				ownCredentialCanonicalized: ownCanonicalized)
		}
	}

	/// Slice 6: fold every `.credentialReplaced` effect an already-adjudicated
	/// commit carried into a NEW `AuthCore` — pure (throws before returning,
	/// never mutates `auth` in place), so `applyFoldCommit`/`applyBind` can
	/// hold the result in a local copy and write it back only alongside
	/// `recv`/`send`, at their own success point. `myLeaf` names which leaf,
	/// in the SAME classical group the effects were computed against, is
	/// this session's own — a moved OTHER leaf canonicalizes `theirs` (the
	/// peer's own-leaf catch-up, or the first fold of their rotating `Upd`,
	/// surfaced as `newSender`); a moved OWN leaf canonicalizes `mine` (the
	/// first canonicalization of a rotation this session authored, surfaced
	/// as `ownCredentialCanonicalized`).
	private static func canonicalize(
		_ effects: MLS.RFC9420.CommitEffects, myLeaf: MLS.LeafIndex, from auth: AuthCore
	) throws -> (auth: AuthCore, newSender: Data?, ownCredentialCanonicalized: Bool) {
		var updated = auth
		var newSender: Data?
		var ownCredentialCanonicalized = false
		for event in effects.events {
			guard case .credentialReplaced(let leaf, _, let new) = event else {
				continue
			}
			let newID = try basicIdentifier(new.credential)
			if leaf == myLeaf {
				try updated.mine.commit(newID)
				ownCredentialCanonicalized = true
			} else {
				try updated.theirs.commit(newID)
				newSender = newID
			}
		}
		return (updated, newSender, ownCredentialCanonicalized)
	}

	/// The single wrapped `0x0008` attestation a commit's effects carry, if any —
	/// `applyBind`'s self-parsed stand-in for `MLS.Combiner.ApqInfoUpdate.extract`,
	/// which scans only the TYPED `.appDataUpdate` effect and so never finds the
	/// deployed wrapped form (`CommitEffect.customProposal`, from the ambient
	/// `withDeployedWireConventions` sets up). Mirrors `extract`'s own contract
	/// exactly: `nil` for none, `MLS.Combiner.Error.attestationMismatch` for more
	/// than one or for a malformed/wrong-component one — never silently ignored.
	private static func extractWrappedAttestation(
		from effects: MLS.RFC9420.CommitEffects, componentID: MLS.Extensions.ComponentID
	) throws -> MLS.Combiner.ApqInfoUpdate? {
		var found: MLS.Combiner.ApqInfoUpdate?
		for event in effects.events {
			guard case .customProposal(let type, let body) = event,
				type == .init(.appDataUpdate)
			else {
				continue
			}
			guard found == nil else { throw MLS.Combiner.Error.attestationMismatch }
			let appDataUpdate = try MLS.Extensions.AppDataUpdate(mlsEncoded: body)
			found = try MLS.Combiner.ApqInfoUpdate.decode(
				from: appDataUpdate, componentID: componentID)
		}
		return found
	}

	/// Self-parsed stand-in for `MLS.Combiner.verifyFullCommitAttestation`
	/// (draft §6.1's FULL-commit epoch attestation check), sourced from the
	/// deployed wrapped `0x0008` proposal instead of swift-mls's typed
	/// `.appDataUpdate` arm — see `extractWrappedAttestation`. Replicates the
	/// combiner helper's checks exactly: each half carries exactly one
	/// attestation, the two copies agree, and each attests the ACTUAL
	/// post-apply epoch of both halves — so a tampered, absent, or
	/// cross-half-mismatched attestation is rejected identically to the
	/// typed-arm path this replaces.
	private static func verifyWrappedFullCommitAttestation(
		classicalEffects: MLS.RFC9420.CommitEffects,
		pqEffects: MLS.RFC9420.CommitEffects,
		classicalEpoch: UInt64,
		pqEpoch: UInt64,
		codepoints: MLS.Combiner.Codepoints
	) throws -> MLS.Combiner.ApqInfoUpdate {
		guard
			let classical = try extractWrappedAttestation(
				from: classicalEffects, componentID: codepoints.apqComponentID),
			let pq = try extractWrappedAttestation(
				from: pqEffects, componentID: codepoints.apqComponentID)
		else {
			throw MLS.Combiner.Error.attestationMismatch
		}
		guard classical == pq,
			classical.tEpoch == classicalEpoch,
			classical.pqEpoch == pqEpoch
		else {
			throw MLS.Combiner.Error.attestationMismatch
		}
		return classical
	}

	/// §4c/§11 #2/#5, Bob: apply Alice's `0x05` bind staple (a fold may ride
	/// it too — the SAME commit that discharges the bind can fold an approved
	/// peer Update by reference, §11 MF1). Classifies the classical commit's
	/// epoch with the shared classifier (MF7) before consuming anything.
	/// Gated on `pqInflight` being `.bootstrapResponded`/`.responding`/
	/// `.rekeyResponded` so a bind cannot land outside a founded-and-not-yet-
	/// bound state. Applies the PQ half before
	/// the classical half — the classical discharge's `apq_psk` (`0xFF01`) is
	/// exported off the PQ half's POST-commit epoch. Only `S` is resolved
	/// lazily, inside the PQ `validating` call's `psk` closure (the profile
	/// invokes it only after that commit's framing signature and membership
	/// tag verify); the classical half's `apq_psk` is exported eagerly, ahead
	/// of its own `validating` call, and the cross-party `0xFF02` is resolved
	/// via the send-group ledger (MF4) rather than an unconditional fresh
	/// export — a fold-then-bind+fold at one peer epoch makes a second bare
	/// export here reachable (`componentSecretConsumed`), and a crossed
	/// concurrent commit may reference an epoch this session has already
	/// committed past (the -02 exporter tree retains only the current
	/// epoch's frontier). The actual guard against a forged staple burning
	/// any single-shot leaf is not laziness but value semantics: the whole
	/// body works on local copies (`recv`/`send`/`ledger`), written back to
	/// `self` only on success at the very end — any throw above that point
	/// (a bad signature, a bad membership tag, a bad effects shape, or a
	/// failed attestation) discards every export this call made. Returns
	/// whether the bind was actually applied (`false` for an idempotent
	/// re-ride).
	// internal: used by Messaging.handleStaple
	internal mutating func applyBind(_ staple: Data) throws -> StapleApplyResult {
		// The commit messages decoded below carry `ComponentID`-bearing
		// proposals (the injected external PSK and both `AppDataUpdate`s) —
		// their decode, not just their construction, must run at the
		// deployed wire width (§11 #6), so the whole body lives in one scope.
		try withDeployedWireConventions {
			let (tBytes, pqBytes) = try Frames.decodeAPQPrivateMessage(staple)
			guard
				case .publicMessage(let tPub) = try MLS.RFC9420.Message(
					mlsEncoded: tBytes)
			else {
				throw TwoMLSError.malformedSideBandMessage
			}
			guard
				case .publicMessage(let pqPub) = try MLS.RFC9420.Message(
					mlsEncoded: pqBytes)
			else {
				throw TwoMLSError.malformedSideBandMessage
			}
			guard var recv = recvGroup, recv.pq != nil else {
				throw TwoMLSError.notEstablished
			}
			guard var send = sendGroup, send.pq != nil else {
				throw TwoMLSError.notEstablished
			}

			switch try Self.classifyStapleEpoch(
				commitEpoch: tPub.content.epoch,
				currentEpoch: recv.classical.context.epoch)
			{
			case .skip: return .notApplied
			case .apply: break
			}
			switch pqInflight {
			case .bootstrapResponded, .responding, .rekeyResponded:
				break
			default:
				throw TwoMLSError.sessionNotReady
			}

			// §11 MF1: does this commit ALSO fold a peer Update by reference
			// (a fold+bind `0x05`), or is it a bare bind? Purely structural —
			// `committingRound` only ever emits a `.reference` entry when a
			// fold rode — so this determines the exact `.updated`-count the
			// whitelist below expects, never trusted claims from elsewhere.
			guard case .commit(let commitValue) = tPub.content.content else {
				throw TwoMLSError.malformedSideBandMessage
			}
			let foldedPeerUpdate = commitValue.proposals.contains { entry in
				if case .reference = entry { return true }
				return false
			}

			// Mirrors the id `owePQBind` builds on Alice's side (LE64(epoch) ‖
			// groupID ‖ [0x52]) against `recv.pq!`'s PRE-apply epoch/group id —
			// the same `(group, epoch)` Alice's `sendPQ` named there — so the
			// resolver matches the exact injected id, not any `.external` PSK
			// (§11 #5).
			let expectedInjectedID =
				withUnsafeBytes(of: recv.pq!.context.epoch.littleEndian) {
					Data($0)
				}
				+ recv.pq!.context.groupID + Data([0x52])

			var sendPQ = send.pq!
			let sendPQEpochBeforeExport = sendPQ.context.epoch
			let pqPending = try recv.pq!.validating(
				pqProvider, commit: pqPub, proposals: MLS.RFC9420.ProposalStore(),
				psk: { identifier in
					guard case .external(let pskID, _) = identifier,
						pskID == expectedInjectedID
					else {
						return nil
					}
					// §A.4: `S` was already sealed/held at `pqRatchetRespond` —
					// reuse it rather than exporting a fresh one off `sendPQ`
					// (which A.4 never spends here at all).
					if case .responding(let secret, _) = pqInflight {
						return secret
					}
					let exported = try MLS.Combiner.ExportedPsk.export(
						from: &sendPQ, pqProvider,
						componentID: Self.crossPartyComponentID)
					return exported.psk
				})
			let pqEffects = pqPending.effects
			try TwoPartyRules.validateBindPQEffects(pqEffects)
			let pqTransition = try pqPending.apply(onto: recv.pq!)
			recv.pq = pqTransition.group
			send.pq = sendPQ
			switch pqInflight {
			case .bootstrapResponded, .rekeyResponded:
				lastSendPQExported = sendPQEpochBeforeExport
			default:
				break
			}

			var apqSource = recv.pq!
			let apqPSK = try MLS.Combiner.ExportedPsk.export(
				from: &apqSource, pqProvider, componentID: codepoints.apqComponentID
			)
			recv.pq = apqSource

			let proposalStore = rebuildStagedProposalStore(against: recv.classical)
			var ledger = sendCrossPSKLedger
			var store = MLS.Combiner.PSKStore()
			store.register(apqPSK)
			try rememberSendCrossPSK(classical: &send.classical, ledger: &ledger)
			for exported in ledger.values { store.register(exported) }

			let tPending = try recv.classical.validating(
				classicalProvider, commit: tPub,
				proposals: proposalStore,
				psk: store.resolver())
			let classicalEffects = tPending.effects
			try TwoPartyRules.validateBindClassicalEffects(
				classicalEffects, foldedPeerUpdate: foldedPeerUpdate)
			// AS consult point 3 (slice 6): the PQ half never carries a
			// `.credentialReplaced` (`validateBindPQEffects` stays strict),
			// so only the classical half's effects need adjudicating.
			try auth.adjudicate(classicalEffects)
			let myLeaf = recv.classical.myLeafIndex
			let tTransition = try tPending.apply(onto: recv.classical)
			recv.classical = tTransition.group

			_ = try Self.verifyWrappedFullCommitAttestation(
				classicalEffects: classicalEffects, pqEffects: pqEffects,
				classicalEpoch: recv.classical.context.epoch,
				pqEpoch: recv.pq!.context.epoch, codepoints: codepoints)

			try TwoPartyRules.ensureTwoParty(recv.pq!)
			try TwoPartyRules.ensureTwoParty(recv.classical)

			// Value semantics extend to `auth` — computed into a local copy,
			// written back only alongside `recv`/`send` below.
			let (authCopy, newSender, ownCanonicalized) = try Self.canonicalize(
				classicalEffects, myLeaf: myLeaf, from: auth)

			recvGroup = recv
			sendGroup = send
			sendCrossPSKLedger = ledger
			stagedUpdates = []
			pqTurnMine = true
			pqInflight = nil
			pendingSideBand = nil
			auth = authCopy
			return StapleApplyResult(
				applied: true, newSender: newSender,
				ownCredentialCanonicalized: ownCanonicalized)
		}
	}
}
