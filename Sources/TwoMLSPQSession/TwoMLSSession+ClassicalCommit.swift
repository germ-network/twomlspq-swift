import Foundation
import MLSCodec
import MLSCombiner
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
	/// runs on an offered Upd, without mutating any group: `send.classical.
	/// verifying(proposal:)` (non-consuming for a `PublicMessage`) authenticates
	/// the framing; the verified proposal must be a peer `.update` (`.member`
	/// sender, not this session's own leaf); its leaf's credential/signature
	/// key must be UNCHANGED from the current occupant's — slice 5 is
	/// fold-only, so any `.credentialReplaced` shape is rejected here, before
	/// it ever reaches a commit; and its verified `.basic` identity must match
	/// the frame's unauthenticated `proposing` claim (§11 MF5 — `proposing`
	/// rides outside the AAD, so the wire claim alone proves nothing).
	private func validateOfferedUpdate(
		_ offered: (digest: Data, proposing: Data, message: Data)
	) throws {
		guard let send = sendGroup else { throw TwoMLSError.proposalRejected }
		try withDeployedWireWidth {
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
			guard currentLeaf.credential == leafNode.credential,
				currentLeaf.signatureKey == leafNode.signatureKey
			else {
				throw TwoMLSError.proposalRejected
			}
			guard case .basic(let identity) = leafNode.credential,
				identity == offered.proposing
			else {
				throw TwoMLSError.proposalRejected
			}
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

	/// §3b/§11 MF6: a committing round on `sendGroup.classical` — folds the
	/// approved peer Update (`queuedProposal`, when present: a fold needs no
	/// license, since `queueProposal` already verified it against the live
	/// send group, and holding it IS the evidence) and/or discharges an owed
	/// PQ bind (when `owedBind != nil` AND licensed). An owed bind rides ANY
	/// committing round this triggers, licensed or not (MF6): a fold that
	/// commits advances `sendGroup.classical` regardless, which would make an
	/// owed bind's reserved epoch stale and doom it, so a fold that commits
	/// must carry an outstanding bind along. Staple selection keys off
	/// `owed != nil` (→ `0x05`), not `didCommit` (MF6). Reports whether a
	/// commit happened, and — fold only — the folded peer leaf's verified
	/// identity (MF5, never the unauthenticated wire `proposing`).
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
		guard folded != nil || willDischargeBind else {
			return (false, nil)
		}
		guard var send = sendGroup else { throw TwoMLSError.notEstablished }

		return try withDeployedWireWidth {
			var proposalStore = MLS.RFC9420.ProposalStore()
			var proposals: [MLS.RFC9420.ProposalOrRef] = []
			var store = MLS.Combiner.PSKStore()
			var committedRemoteClientID: Data?
			var pqCommitMessageForStaple: Data?

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
				proposals.append(
					.proposal(
						try attestation.proposal(
							componentID: codepoints.apqComponentID)))
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

			let transition = try send.classical.committing(
				classicalProvider, proposals: proposals,
				proposalStore: proposalStore,
				signingKey: identity.signingKey,
				randomness: try .generate(classicalProvider), includePath: true,
				framing: .publicMessage, psk: store.resolver())
			let adopted = transition.group
			let sent = transition.takeOutput()
			let commitBytes = try sent.message.mlsEncoded()
			let pending = sent.takePending()

			if willDischargeBind {
				try TwoPartyRules.validateBindClassicalEffects(
					pending.effects, foldedPeerUpdate: folded != nil)
			} else {
				try TwoPartyRules.validateTwoPartyUpdateCommit(
					pending.effects, foldedPeerUpdate: true,
					allowAppDataUpdate: false,
					orThrow: .invalidFoldEffects)
			}

			let advanced = try pending.apply(onto: adopted)
			send.classical = advanced.group

			// MF4: also remember the newly-landed epoch, so a crossed peer
			// commit referencing it still resolves even if this session
			// commits again before that peer commit arrives.
			try rememberSendCrossPSK(classical: &send.classical, ledger: &ledger)

			sendGroup = send
			sendCrossPSKLedger = ledger

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
	internal mutating func applyFoldCommit(_ commitBytes: Data) throws -> Bool {
		// The commit's injected `0xFF02` PSK is `ComponentID`-bearing, like
		// the `0x05` bind's — decode and construct at the deployed width
		// (§11 #6/MF7), so the whole body lives in one scope.
		try withDeployedWireWidth {
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
			case .skip: return false
			case .apply: break
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
			try TwoPartyRules.validateTwoPartyUpdateCommit(
				pending.effects, foldedPeerUpdate: true, allowAppDataUpdate: false,
				orThrow: .invalidFoldEffects)
			let advanced = try pending.apply(onto: recv.classical)
			recv.classical = advanced.group
			try TwoPartyRules.ensureTwoParty(recv.classical)

			recvGroup = recv
			sendGroup = send
			sendCrossPSKLedger = ledger
			stagedUpdates = []
			return true
		}
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
	internal mutating func applyBind(_ staple: Data) throws -> Bool {
		// The commit messages decoded below carry `ComponentID`-bearing
		// proposals (the injected external PSK and both `AppDataUpdate`s) —
		// their decode, not just their construction, must run at the
		// deployed wire width (§11 #6), so the whole body lives in one scope.
		try withDeployedWireWidth {
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
			case .skip: return false
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
			let tTransition = try tPending.apply(onto: recv.classical)
			recv.classical = tTransition.group

			_ = try MLS.Combiner.verifyFullCommitAttestation(
				classicalEffects: classicalEffects, pqEffects: pqEffects,
				classicalEpoch: recv.classical.context.epoch,
				pqEpoch: recv.pq!.context.epoch, codepoints: codepoints)

			try TwoPartyRules.ensureTwoParty(recv.pq!)
			try TwoPartyRules.ensureTwoParty(recv.classical)

			recvGroup = recv
			sendGroup = send
			sendCrossPSKLedger = ledger
			stagedUpdates = []
			pqTurnMine = true
			pqInflight = nil
			pendingSideBand = nil
			return true
		}
	}
}
