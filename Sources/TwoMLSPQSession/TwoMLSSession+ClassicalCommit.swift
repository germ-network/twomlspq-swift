import Foundation
import GermConvenience
import MLSCodec
import MLSCombiner
import MLSExtensions
import MLSProfileRFC9420
import SecretBytes

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
	public mutating func queueProposal(digest: Data) throws -> StateUpdate {
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

		// Return cadence (slice 8a): classical-only mutation → `.core`.
		advanceStateSeq()
		return try stateUpdate(kind: .core)
	}

	/// The validation `queueProposal` runs on an offered Upd; `committingRound`
	/// re-verifies at commit time only the framing and the `.update`/non-own-
	/// leaf shape, not this function's `proposing` match or the AS successor
	/// check — a path unreachable via the public API (`queuedProposal` is set
	/// only by `queueProposal`), kept there defensively. Neither mutates any
	/// group except (slice 6) the AS's own bookkeeping: `send.classical.
	/// verifying(proposal:)` (non-consuming for a `PublicMessage`)
	/// authenticates the framing; the verified proposal must be a peer
	/// `.update` (`.member` sender, not this session's own leaf); its verified
	/// `.basic` identity must match the frame's unauthenticated `proposing`
	/// claim (§11 MF5 — `proposing` rides outside the AAD, so the wire claim
	/// alone proves nothing); and — slice 6 — when its leaf's credential/
	/// signature key differs from the current occupant's (a
	/// `.credentialReplaced` shape), the peer's OWN rotation must be a valid
	/// successor of the peer's canonical head. Reject a peer
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
			// The enclosing `verifying(proposal:)` above authenticates only
			// the FRAMING — the sender's CURRENT leaf's signature over the
			// proposal — never the EMBEDDED replacement leaf's own RFC 9420 section 7.3
			// validity (`LeafNode.verifySignature` covers its own
			// signature; `validatePolicy` covers capabilities/credential-
			// type mutual support/`required_capabilities`). Both run here,
			// before this approval can ever authorize anything, against
			// EVERY current member — including the sender's own current
			// leaf — mirroring the roster a real commit validates against
			// (`currentMemberRoster`).
			do {
				try leafNode.verifySignature(
					classicalProvider,
					placement: .inGroup(
						groupID: send.classical.context.groupID,
						leafIndex: senderLeaf))
				let roster = try Self.currentMemberRoster(of: send.classical)
				try leafNode.validatePolicy(
					.updateProposal(replacing: currentLeaf),
					groupRequirements: send.classical.context.extensions
						.requiredCapabilities(),
					memberCredentialTypes: roster.credentialTypes,
					memberCapabilities: roster.byLeaf.values)
			} catch {
				throw TwoMLSError.proposalRejected
			}
			try TwoPartyRules.ensureAdvertisesAPQCapabilities(
				leafNode, codepoints: codepoints)
			// Rule 8 tail (group-rules.md:77-78): "Leaves advertise the
			// extension type, so a binding-carrying group can only ever
			// contain capability-bearing leaves." The peer's offered Update
			// replaces their occupied leaf — when THIS classical group
			// already carries an AppBinding, the replacement leaf must
			// advertise `0xF0A2` too, gated on the group actually being
			// bound (an unbound group never required leaf capability).
			if try AppBinding.read(fromExtensionsOf: send.classical.context) != nil {
				try ensureAppBindingCreatorLeafAdvert(leafNode)
			}
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

	/// Resolve `commit`'s by-reference own-Update proposals —
	/// the framed store (`rebuildStagedProposalStore`) first, then, only
	/// for refs still missing, the caller's own `ownOfferWindow` blob,
	/// cross-checked against this session's own persisted record
	/// (`self.ownOfferWindow`). Nothing here mutates `self`; `recv` is the
	/// caller's own local copy (not yet written back), so every path is
	/// safe to run before any other consuming step in `applyFoldCommit`/
	/// `applyBind`.
	///
	/// Authenticates BEFORE ever demanding or loading anything. When
	/// refs are missing, a probe `validating` call — over the FRAMED store
	/// ONLY (never the window: not loaded yet) and a PSK resolver that
	/// always returns `nil` — resolves proposal references before PSKs
	/// (swift-mls `validating`), so `GroupError.unknownProposalReference`
	/// here means the staple's framing signature and membership tag have
	/// ALREADY verified, and a ref is genuinely missing: only THEN does
	/// this throw `.ownOfferWindowRequired` (no window supplied) or load
	/// the window. Any other error — a bad signature, a bad membership
	/// tag, or anything else `validating` would have thrown regardless —
	/// propagates unchanged, exactly as it would have without this
	/// detection step: a forged commit naming a bogus ref never reaches
	/// `.ownOfferWindowRequired`.
	///
	/// Returns the store the REAL `validating` call should use, and
	/// whether a named ref still went unresolved (`windowLacked`) — the
	/// caller maps a subsequent `unknownProposalReference` from that real
	/// call to `.ownOfferUnavailable` ONLY when this is `true` — every
	/// other `unknownProposalReference` propagates raw, matching prior
	/// behavior for a session with no window record at all.
	private func resolvingOwnProposals(
		commit: MLS.RFC9420.PublicMessage, recv: APQGroup,
		ownOfferWindow suppliedWindow: SecretArchive?
	) throws -> (store: MLS.RFC9420.ProposalStore, windowLacked: Bool) {
		let store = rebuildStagedProposalStore(against: recv.classical)
		guard case .commit(let commitValue) = commit.content.content else {
			throw TwoMLSError.malformedSideBandMessage
		}
		let missingRefs: [MLS.HashReference] = commitValue.proposals.compactMap {
			guard case .reference(let ref) = $0, store[ref] == nil else { return nil }
			return ref
		}
		guard !missingRefs.isEmpty, let record = ownOfferWindow else {
			// Nothing missing, or this session has no window record at all
			// — continue exactly as today.
			return (store, false)
		}

		do {
			_ = try recv.classical.validating(
				classicalProvider, commit: commit, proposals: store,
				psk: { _ in nil })
			// Resolved without the window after all — nothing left to do.
			return (store, false)
		} catch MLS.RFC9420.GroupError.unknownProposalReference {
			// Authenticated AND missing — fall through to demand/load.
		}

		guard let suppliedWindow else { throw TwoMLSError.ownOfferWindowRequired }
		let offers = try OwnOfferWindow.loadAndVerify(suppliedWindow, record: record)
		var augmented = store
		let lacked = OwnOfferWindow.insertNamed(
			missingRefs, from: offers, into: &augmented, recvClassical: recv.classical,
			myLeafIndex: recv.classical.myLeafIndex, epoch: record.epoch,
			groupID: record.groupID, provider: classicalProvider)
		return (augmented, !lacked.isEmpty)
	}

	/// §11 MF4: export+ledger `classical`'s CURRENT-epoch `0xFF02` cross-party
	/// PSK into `ledger`, unless that epoch is already there — mirrors the
	/// Rust `remember_send_psk`. Pure with respect to `self`: both parameters
	/// are `inout` local copies the caller owns, so a caller can discard both
	/// on failure and a retry re-derives (or re-reuses the ledgered value)
	/// cleanly — the -02 exporter tree consumes a `(group, epoch, component)`
	/// leaf on first export, so re-exporting an already-ledgered epoch would
	/// throw `componentSecretConsumed`.
	// internal: used by Messaging.joinGroupBIfNeeded
	internal func rememberSendCrossPSK(
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

	/// The own-leaf catch-up (§3c; generalized catch-up): does
	/// `send`'s own classical leaf "lag" — present an id other than
	/// `mineCurrent` (`auth.mine.current`)? No candidate is needed to answer
	/// that: `mine.current` only ever moves once SOME leaf has already
	/// canonicalized the new id (`canonicalize`'s `mine.commit`, run when my
	/// OWN recv-leaf's rotation is folded), so a send-leaf lag against it is
	/// exactly "the recv leaf got there first" — the same condition the old
	/// candidate-based check derived less directly, plus every migrated or
	/// rule-7-supplied lag a candidate could never explain. The read is
	/// tree-derived (never a cached claim), so this can never disagree with
	/// what the stored key set would sign with. Returns the TARGET id, not a
	/// candidate record — the key itself always comes from
	/// `leafKeys.sendClassical.pending`, never `rotationCandidate.
	/// signingKey` directly — `nil` when the group is absent, there is no
	/// canonical principal yet, or the send-leaf already presents it.
	private static func ownLeafCatchUpTarget(
		send: APQGroup?, mineCurrent: Data?
	) throws -> Data? {
		guard let send, let mineCurrent else { return nil }
		let sendOwnID = try basicIdentifier(Self.ownLeaf(of: send.classical).credential)
		guard sendOwnID != mineCurrent else { return nil }
		return mineCurrent
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
	/// send-leaf). Evidence-gating (`protocol-flows.md` §Evidence-gating): the
	/// catch-up fires only on a LICENSED round, so every committing round is
	/// either a fold (holding the peer's proposal is evidence) or licensed —
	/// which is exactly why an owed bind rides every round that commits (MF6):
	/// every such round already carries evidence, and one that committed past
	/// an unapplied bind would keep the bind's reserved epoch forever
	/// `.epochDesync` (`protocol-flows.md` §Evidence-gating). An unlicensed
	/// catch-up is deferred, never dropped — `rotationCandidate` persists and
	/// the peer's next inbound frame re-stamps the license. Staple selection
	/// keys off `owed != nil` (→ `0x05`), not `didCommit` (MF6). Reports
	/// whether a commit happened, and — fold only — the folded peer leaf's
	/// verified identity (MF5, never the unauthenticated wire `proposing`).
	// internal: used by Messaging.prepareToEncrypt
	internal mutating func committingRound() throws -> (
		didCommit: Bool, committedRemoteClientID: Data?
	) {
		// Take the slot before anything else runs — approval
		// and authorization are one unit (`PartySequence.revoke`'s own
		// doc); a commit this round fails to build must not leave the
		// approval sitting untouched, silently retriable forever with no
		// compensating withdrawal. Any throw from here on, not only from
		// `committing` itself, withdraws a still-outstanding (not yet
		// canonical) authorization for the folded offer's id.
		let folded = queuedProposal
		queuedProposal = nil
		do {
			return try committingRoundBody(folded: folded)
		} catch {
			if let folded, !auth.theirs.history.contains(folded.proposing) {
				auth.theirs.revoke(folded.proposing)
			}
			throw error
		}
	}

	private mutating func committingRoundBody(
		folded: (digest: Data, proposing: Data, message: Data)?
	) throws -> (didCommit: Bool, committedRemoteClientID: Data?) {
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
		// The catch-up (§3c), now evidence-gated (`protocol-flows.md` §Evidence-gating):
		// the catch-up fires only on a LICENSED round, so every committing
		// round is either a fold (holding the peer's proposal IS the evidence)
		// or licensed — an unlicensed commit could otherwise produce a staple
		// nothing bridges and permanently lose a PQ epoch at the peer. The
		// catch-up is DEFERRED, never dropped: `rotationCandidate` persists,
		// and the peer's next inbound frame re-stamps the license
		// (`stampLicenseIfOffered`), so the very next `prepareToEncrypt`
		// performs it.
		let catchUpTargetID =
			licensed
			? try Self.ownLeafCatchUpTarget(
				send: sendGroup, mineCurrent: auth.mine.current)
			: nil
		// The pending-key lookup runs only when there IS a catch-up target
		// — never unconditionally — and is captured now, on `self.leafKeys`,
		// before anything in this round mutates state.
		let catchUpKey: LeafKey? = try catchUpTargetID.map { target in
			guard let key = leafKeys.sendClassical.pending[target] else {
				throw TwoMLSError.credentialUnknown
			}
			return key
		}
		guard folded != nil || willDischargeBind || catchUpTargetID != nil else {
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
				try TwoPartyRules.ensureAdvertisesAPQCapabilities(
					leafNode, codepoints: codepoints)
				// Rule 8 tail (group-rules.md:77-78), same gate as
				// `validateOfferedUpdate`'s: re-checked here (defense in
				// depth, not redundant — `queueProposal`'s validation and
				// this fold happen at different times) against the SAME
				// pre-commit `send.classical` this fold is about to land in.
				if try AppBinding.read(fromExtensionsOf: send.classical.context)
					!= nil
				{
					try ensureAppBindingCreatorLeafAdvert(leafNode)
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
			// Same reasoning, `0xFF03` attachment component (+Attachment.swift).
			var attachmentLedger = sendAttachmentLedger
			try rememberSendAttachmentComponent(
				classical: &send.classical, ledger: &attachmentLedger)

			// §3c: the own-leaf catch-up threads the rotation ring +
			// `newIdentity` through this SAME commit machinery — the ring's
			// `.framedContent` stays on the CURRENT (still-OLD) send key, so
			// the enclosing commit envelope verifies against the pre-commit
			// sender leaf; `.leafNode`/`.groupInfo` route to the candidate's
			// NEW key. Absent a catch-up, the single-key sugar over the
			// resolved current key suffices (identical to CP0/CP1).
			let sign: MLS.RFC9420.SigningClosure
			let newIdentity: MLS.RFC9420.NewSigningIdentity?
			if let catchUpTargetID, let catchUpKey {
				sign = MLS.RFC9420.signingClosure(
					classicalProvider, current: try sendClassicalSigningKey(),
					new: catchUpKey.signingKey)
				newIdentity = MLS.RFC9420.NewSigningIdentity(
					credential: .basic(identity: catchUpTargetID),
					signatureKey: catchUpKey.signatureKey)
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
			return try withTransitionHandoff(transition) { adopted, sent in
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

				// The catch-up's target key is now what `send.classical`'s
				// own leaf presents — promote it, on a local copy, right
				// after the apply that actually moved it.
				var updatedLeafKeys = leafKeys
				if let catchUpTargetID, let catchUpKey {
					try updatedLeafKeys.sendClassical.promoted(
						presenting: catchUpKey.signatureKey,
						id: catchUpTargetID)
				}

				// MF4: also remember the newly-landed epoch, so a crossed peer
				// commit referencing it still resolves even if this session
				// commits again before that peer commit arrives.
				try rememberSendCrossPSK(
					classical: &send.classical, ledger: &ledger)
				try rememberSendAttachmentComponent(
					classical: &send.classical, ledger: &attachmentLedger)

				// (DEBUG only): a fault point right at this round's
				// write-back — proves every local copy above (`send`,
				// `ledger`, `attachmentLedger`, `authCopy`, `updatedLeafKeys`)
				// is still write-back-only-on-success: a fault here must
				// leave every one of `self`'s corresponding fields untouched.
				#if DEBUG
					if TwoMLSSessionTestHooks.shouldFault(
						"committingRound.beforeWriteBack")
					{
						throw InjectedTestFault(
							name: "committingRound.beforeWriteBack")
					}
				#endif
				sendGroup = send
				sendCrossPSKLedger = ledger
				sendAttachmentLedger = attachmentLedger
				auth = authCopy
				leafKeys = updatedLeafKeys
				// (DEBUG only): a fault point AFTER the write-back above but
				// before the next throwing call — proves a fault here leaves
				// `self` fully write-back-complete (unlike the point above,
				// which proves the OPPOSITE: nothing wrote back at all).
				#if DEBUG
					if TwoMLSSessionTestHooks.shouldFault(
						"committingRound.afterWriteBackBeforeRendezvous")
					{
						throw InjectedTestFault(
							name:
								"committingRound.afterWriteBackBeforeRendezvous"
						)
					}
				#endif
				// Classical epoch just advanced (a bare fold, or a fold+bind
				// discharge sharing this same commit) — capture its rendezvous
				// address before this round's caller (`prepareToEncrypt`) mints
				// its own `StateUpdate`.
				try recordListenRendezvous()

				if let pqCommitMessageForStaple {
					currentStaple = Frames.encodeAPQPrivateMessage(
						t: commitBytes, pq: pqCommitMessageForStaple)
					owedBind = nil
					pqTurnMine = false
				} else {
					currentStaple = Frames.encodeMlsMessageStaple(commitBytes)
				}
				// Either way this round is now fully spent: the fold it carried
				// (if any) is consumed — `queuedProposal` is already nil,
				// taken at `committingRound`'s own entry — and any still-
				// unapproved offer is bound to the epoch this commit just
				// left behind (§11 MF8's "the peer re-proposes at the new
				// epoch once it sees this commit's staple").
				offeredProposal = nil
				return (true, committedRemoteClientID)
			}
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
	internal mutating func applyFoldCommit(
		_ commitBytes: Data, ownOfferWindow: SecretArchive? = nil
	) throws -> StapleApplyResult {
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

			// Resolve own-Update by-reference proposals — the
			// framed store first, then (only for refs still missing) the
			// own-offer window, authenticated first. Right after the
			// commit decode and the epoch classification, before anything
			// else consumes `send`/the ledgers — mirrors `applyBind`'s own
			// placement.
			let (proposalStore, windowLacked) = try resolvingOwnProposals(
				commit: commitPub, recv: recv, ownOfferWindow: ownOfferWindow)

			guard var send = sendGroup else { throw TwoMLSError.notEstablished }
			var ledger = sendCrossPSKLedger
			var store = MLS.Combiner.PSKStore()
			try rememberSendCrossPSK(classical: &send.classical, ledger: &ledger)
			// Same reasoning, `0xFF03` attachment component (+Attachment.swift).
			var attachmentLedger = sendAttachmentLedger
			try rememberSendAttachmentComponent(
				classical: &send.classical, ledger: &attachmentLedger)
			for exported in ledger.values { store.register(exported) }

			// Exact-id allow-list: only the currently-ledgered cross-party
			// `0xFF02` epochs, no external PSK, and never the attestation (a
			// fold-only commit is a PARTIAL, never a bind discharge) — before
			// `validating`.
			try TwoPartyRules.validateInlineProposals(
				commitValue.proposals,
				expectedApplicationStorageIDs: Set(
					ledger.values.map { $0.storageID }),
				expectedExternalPSKIDs: [],
				allowAttestation: false)

			let pending: MLS.RFC9420.PendingCommit
			do {
				pending = try recv.classical.validating(
					classicalProvider, commit: commitPub,
					proposals: proposalStore,
					psk: store.resolver())
			} catch MLS.RFC9420.GroupError.unknownProposalReference where windowLacked {
				// The supplied window lacked a named ref — terminal,
				// same authenticated-commit guarantee `resolvingOwnProposals`
				// already established (its own probe ran this exact
				// `validating` shape first).
				throw TwoMLSError.ownOfferUnavailable
			}
			let effects = pending.effects
			try TwoPartyRules.validateTwoPartyUpdateCommit(
				effects, foldedPeerUpdate: foldedPeerUpdate,
				allowAppDataUpdate: false,
				orThrow: .invalidFoldEffects)
			// AS consult point 3 (slice 6): every `.credentialReplaced` effect
			// this commit carries — my own leaf catching up, and/or the
			// peer's own-leaf catch-up — validated BEFORE the group advances,
			// each against ITS OWN party (`adjudicate`'s `myLeaf`).
			let myLeaf = recv.classical.myLeafIndex
			try auth.adjudicate(effects, myLeaf: myLeaf)
			let advanced = try pending.apply(onto: recv.classical)
			recv.classical = advanced.group
			try TwoPartyRules.ensureTwoParty(recv.classical)
			// CAPTURE-ON-ENTRY (+Attachment.swift): ledger the recv group's
			// NEWLY-CURRENT epoch's `0xFF03` component right after it lands —
			// `exportAttachmentCEKRecv` is a pure read with no live-export
			// fallback, so this epoch must already be ledgered before a
			// caller can ever ask for it.
			var recvAttachmentLedgerLocal = recvAttachmentLedger
			try rememberRecvAttachmentComponent(
				classical: &recv.classical, ledger: &recvAttachmentLedgerLocal)

			// Value semantics extend to `auth` (§11's discipline, slice 6):
			// `canonicalize` is pure and can throw (a rollback `commit`
			// would), so it is computed into a local copy and written back
			// only alongside `recv`/`send` below — a throw above burns none
			// of `recv`, `send`, or `auth`.
			let (authCopy, newSender, ownCanonicalized) = try Self.canonicalize(
				effects, myLeaf: myLeaf, from: auth)
			// Promote + retain, on the post-`canonicalize` local `authCopy`
			// (never `self.auth`, which only writes back below) — every own
			// proposal goes stale at this exact advance, whichever leaf
			// actually moved.
			let updatedLeafKeys = try Self.updateRecvClassicalKeys(
				leafKeys, classical: recv.classical,
				authCopy: authCopy, rotationCandidateID: rotationCandidate?.clientID
			)

			recvGroup = recv
			sendGroup = send
			sendCrossPSKLedger = ledger
			sendAttachmentLedger = attachmentLedger
			recvAttachmentLedger = recvAttachmentLedgerLocal
			stagedUpdates = []
			// Drain the own-offer window record — `recvGroup.
			// classical`'s epoch just advanced, the only two sites it ever
			// does (here and `applyBind`'s own success point below), and
			// the host may delete its stored blob once this call's own
			// archive is durable (`ownOfferWindowID`'s own doc).
			self.ownOfferWindow = nil
			auth = authCopy
			leafKeys = updatedLeafKeys
			return StapleApplyResult(
				applied: true, newSender: newSender,
				ownCredentialCanonicalized: ownCanonicalized)
		}
	}

	/// The full-leaf-validation roster `validateOfferedUpdate` needs
	/// (`LeafNode.validatePolicy`'s `memberCredentialTypes`/
	/// `memberCapabilities`): every non-blank leaf of `group`, INCLUDING
	/// the sender's own current one — mirrors swift-mls's own (internal,
	/// so re-derived here) `currentMemberRoster()`, the same roster a real
	/// commit validates against.
	private static func currentMemberRoster(of group: MLS.RFC9420.Group) throws -> (
		byLeaf: [MLS.LeafIndex: MLS.RFC9420.Capabilities],
		credentialTypes: Set<MLS.RFC9420.CredentialType>
	) {
		var byLeaf: [MLS.LeafIndex: MLS.RFC9420.Capabilities] = [:]
		var credentialTypes: Set<MLS.RFC9420.CredentialType> = []
		for entry in group.tree.nonBlankLeaves() {
			let leaf = try MLS.RFC9420.LeafNode(mlsEncoded: entry.record.encoded)
			byLeaf[entry.index] = leaf.capabilities
			credentialTypes.insert(leaf.credential.credentialType)
		}
		return (byLeaf, credentialTypes)
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
			guard case .credentialReplaced(let leaf, let old, let new) = event else {
				continue
			}
			let newID = try basicIdentifier(new.credential)
			// Every own-leaf move now changes the signature key (D3), so a
			// same-id move is no longer rare — it is the routine case. Only
			// an id change is worth surfacing to the host; a same-id
			// key-only move canonicalizes nothing and sets neither flag.
			let idChanged = try basicIdentifier(old.credential) != newID
			// Canonicalize only a credential NEW to the sequence — one
			// neither already in `history` nor `pinned`. A leaf moving to
			// an id that's already known is a legitimate catch-up (the
			// same-id case is `commit`'s own no-op; landing on an already-
			// canonical, non-head id, or on a pinned evicted-but-presented
			// id, is a catch-up too), never something for `commit`'s own
			// rollback check to see — `commit` stays strict, so calling it
			// on an id it would treat as a rollback candidate is simply
			// skipped here rather than caught after the fact.
			// `AuthCore.validateSuccession` (run at `adjudicate`) remains
			// the only rollback gate.
			guard idChanged else { continue }
			if leaf == myLeaf {
				if !(updated.mine.history.contains(newID)
					|| updated.mine.pinned.contains(newID))
				{
					try updated.mine.commit(newID)
				}
				ownCredentialCanonicalized = true
			} else {
				if !(updated.theirs.history.contains(newID)
					|| updated.theirs.pinned.contains(newID))
				{
					try updated.theirs.commit(newID)
				}
				newSender = newID
			}
		}
		return (updated, newSender, ownCredentialCanonicalized)
	}

	/// recv-classical's post-apply promote + retention, shared by
	/// `applyFoldCommit`/`applyBind`'s own success points — the only two
	/// sites `recvGroup.classical`'s epoch actually advances, so this is
	/// exactly when every own proposal (and so every dead `pending[t]`
	/// entry) goes stale. `authCopy` is `canonicalize`'s OWN return value,
	/// never `self.auth`, which is written back only alongside this same
	/// call's own success point. Both promote and retain run
	/// unconditionally: `promoted` is itself idempotent (a no-op when the
	/// presented key is already `current`), so calling it on every apply —
	/// not only when `canonicalize` reports OUR OWN leaf moved
	/// (`ownCanonicalized`) — makes `leafKeys` track what the tree actually
	/// presents rather than depend on that AS-level event agreeing with it;
	/// retention likewise runs regardless, since `stagedUpdates` goes stale
	/// at every advance regardless of which leaf this particular commit
	/// moved. Generalized catch-up: the retained rule-4 target is
	/// `authCopy.mine.current` itself whenever the post-apply leaf still
	/// lags it — subsumes the born-dedicated-only case.
	private static func updateRecvClassicalKeys(
		_ leafKeys: LeafKeys, classical: MLS.RFC9420.Group,
		authCopy: AuthCore, rotationCandidateID: Data?
	) throws -> LeafKeys {
		var updated = leafKeys
		let ownLeaf = try Self.ownLeaf(of: classical)
		let ownID = try basicIdentifier(ownLeaf.credential)
		try updated.recvClassical.promoted(presenting: ownLeaf.signatureKey, id: ownID)
		let candidateCanonicalized =
			rotationCandidateID.map {
				!isRotationCandidateOutstanding(
					$0, mineHistory: authCopy.mine.history)
			} ?? true
		let ruleFourTarget: Data? = {
			guard let mineCurrent = authCopy.mine.current, ownID != mineCurrent else {
				return nil
			}
			return mineCurrent
		}()
		updated.recvClassical.retainRecvClassical(
			candidateID: rotationCandidateID,
			candidateCanonicalized: candidateCanonicalized,
			ruleFourTarget: ruleFourTarget)
		return updated
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
	/// failed attestation) discards every export this call made, and the one
	/// lone stamp (`lastSendPQExported`) is deferred to the same success
	/// point rather than written mid-body. Returns whether the bind was
	/// actually applied (`false` for an idempotent re-ride).
	// internal: used by Messaging.handleStaple
	internal mutating func applyBind(
		_ staple: Data, ownOfferWindow: SecretArchive? = nil
	) throws -> StapleApplyResult {
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
			// allow-list below expects, never trusted claims from elsewhere.
			guard case .commit(let commitValue) = tPub.content.content else {
				throw TwoMLSError.malformedSideBandMessage
			}
			let foldedPeerUpdate = commitValue.proposals.contains { entry in
				if case .reference = entry { return true }
				return false
			}

			// Resolve own-Update by-reference proposals here,
			// EARLY — right after the commit decode, before anything in the
			// PQ half below runs. Valid because the PQ half never touches
			// `recv.classical` (only `recv.pq`), so this authenticates and
			// resolves against exactly the same, still-untouched classical
			// state the PQ half runs alongside, not after.
			let (proposalStore, windowLacked) = try resolvingOwnProposals(
				commit: tPub, recv: recv, ownOfferWindow: ownOfferWindow)

			// Mirrors the id `owePQBind` builds on Alice's side (LE64(epoch) ‖
			// groupID ‖ [0x52]) against `recv.pq!`'s PRE-apply epoch/group id —
			// the same `(group, epoch)` Alice's `sendPQ` named there — so the
			// resolver matches the exact injected id, not any `.external` PSK
			// (§11 #5).
			let recvPQ = try recv.pq.tryUnwrap(TwoMLSError.notEstablished)
			let expectedInjectedID =
				withUnsafeBytes(of: recvPQ.context.epoch.littleEndian) {
					Data($0)
				}
				+ recvPQ.context.groupID + Data([0x52])

			// Exact-id allow-list, PQ half: exactly the injected external
			// `S` plus the attestation — before `validating`, so a
			// spliced-in extra/wrong proposal never reaches signature
			// verification.
			guard case .commit(let pqCommitValue) = pqPub.content.content else {
				throw TwoMLSError.malformedSideBandMessage
			}
			try TwoPartyRules.validateInlineProposals(
				pqCommitValue.proposals,
				expectedApplicationStorageIDs: [],
				expectedExternalPSKIDs: [expectedInjectedID],
				allowAttestation: true)

			var sendPQ = try send.pq.tryUnwrap(TwoMLSError.notEstablished)
			let sendPQEpochBeforeExport = sendPQ.context.epoch
			// The `lastSendPQExported` stamp is deferred to this function's
			// success point (it is a `self` write, and several throwing steps —
			// including the new classical-half PSK guard below — run after the
			// PQ apply).
			var pendingSendPQExportedStamp: UInt64?
			// swift-mls invokes the resolver exactly once per PSK id the
			// commit names, so the flag is exact: a bind that applies without
			// naming the injected external `S` silently skips the fresh PQ
			// entropy while its attestation claims a FULL commit.
			var sawInjectedS = false
			let pqPending = try recv.pq.tryUnwrap(TwoMLSError.notEstablished)
				.validating(
					pqProvider, commit: pqPub,
					proposals: MLS.RFC9420.ProposalStore(),
					psk: { identifier in
						guard case .external(let pskID, _) = identifier,
							pskID == expectedInjectedID
						else {
							return nil
						}
						sawInjectedS = true
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
			guard sawInjectedS else { throw TwoMLSError.missingBindPSK }
			let pqTransition = try pqPending.apply(
				onto: recv.pq.tryUnwrap(TwoMLSError.notEstablished))
			recv.pq = pqTransition.group
			send.pq = sendPQ
			switch pqInflight {
			case .bootstrapResponded, .rekeyResponded:
				pendingSendPQExportedStamp = sendPQEpochBeforeExport
			default:
				break
			}

			var apqSource = try recv.pq.tryUnwrap(TwoMLSError.notEstablished)
			let apqPSK = try MLS.Combiner.ExportedPsk.export(
				from: &apqSource, pqProvider, componentID: codepoints.apqComponentID
			)
			recv.pq = apqSource

			var ledger = sendCrossPSKLedger
			var store = MLS.Combiner.PSKStore()
			store.register(apqPSK)
			try rememberSendCrossPSK(classical: &send.classical, ledger: &ledger)
			// Same reasoning, `0xFF03` attachment component (+Attachment.swift).
			var attachmentLedger = sendAttachmentLedger
			try rememberSendAttachmentComponent(
				classical: &send.classical, ledger: &attachmentLedger)
			for exported in ledger.values { store.register(exported) }

			// Exact-id allow-list, classical half: the current PQ epoch's
			// `apq_psk`, plus whatever cross-party `0xFF02` epochs are
			// currently ledgered (legitimately zero or more — event-driven
			// off `lastCrossInjected`) — before `validating`.
			try TwoPartyRules.validateInlineProposals(
				commitValue.proposals,
				expectedApplicationStorageIDs: Set(
					ledger.values.map { $0.storageID }
				)
				.union([apqPSK.storageID]),
				expectedExternalPSKIDs: [],
				allowAttestation: true)

			// The library's recording resolver replaces the port's own
			// `sawAPQPSK` flag: `MLS.Combiner.verifyFullCommit`'s
			// `verifyApqPskBound` half inspects the `ResolutionRecord` after
			// the fact instead of a closure-captured bool.
			let (classicalResolver, pskRecord) = store.recordingResolver()
			let tPending: MLS.RFC9420.PendingCommit
			do {
				tPending = try recv.classical.validating(
					classicalProvider, commit: tPub,
					proposals: proposalStore,
					psk: classicalResolver)
			} catch MLS.RFC9420.GroupError.unknownProposalReference where windowLacked {
				// The supplied window lacked a named ref — terminal,
				// same authenticated-commit guarantee `resolvingOwnProposals`
				// already established for this staple.
				throw TwoMLSError.ownOfferUnavailable
			}
			let classicalEffects = tPending.effects
			try TwoPartyRules.validateBindClassicalEffects(
				classicalEffects, foldedPeerUpdate: foldedPeerUpdate)
			// AS consult point 3 (slice 6): the PQ half never carries a
			// `.credentialReplaced` (`validateBindPQEffects` stays strict),
			// so only the classical half's effects need adjudicating, each
			// against ITS OWN party (`adjudicate`'s `myLeaf`).
			let myLeaf = recv.classical.myLeafIndex
			try auth.adjudicate(classicalEffects, myLeaf: myLeaf)
			let tTransition = try tPending.apply(onto: recv.classical)
			recv.classical = tTransition.group
			// CAPTURE-ON-ENTRY (+Attachment.swift): ledger the recv group's
			// NEWLY-CURRENT epoch's `0xFF03` component right after it lands —
			// same reasoning as `applyFoldCommit`'s own capture.
			var recvAttachmentLedgerLocal = recvAttachmentLedger
			try rememberRecvAttachmentComponent(
				classical: &recv.classical, ledger: &recvAttachmentLedgerLocal)

			// Bundles the §6.1 attestation check (both halves attest the
			// same, actual post-commit epoch pair) AND §6.2 (the classical
			// half's `validating` actually resolved the current PQ epoch's
			// `apq_psk`) — the library's de-conflated FULL-commit check.
			_ = try MLS.Combiner.verifyFullCommit(
				classicalEffects: classicalEffects, pqEffects: pqEffects,
				classicalEpoch: recv.classical.context.epoch,
				pqEpoch: recv.pq.tryUnwrap(TwoMLSError.notEstablished).context
					.epoch,
				record: pskRecord, expected: apqPSK, codepoints: codepoints)

			try TwoPartyRules.ensureTwoParty(
				recv.pq.tryUnwrap(TwoMLSError.notEstablished))
			try TwoPartyRules.ensureTwoParty(recv.classical)

			// Value semantics extend to `auth` — computed into a local copy,
			// written back only alongside `recv`/`send` below.
			let (authCopy, newSender, ownCanonicalized) = try Self.canonicalize(
				classicalEffects, myLeaf: myLeaf, from: auth)
			// Same promote + retain as `applyFoldCommit` — this is the
			// OTHER (and only other) site `recvGroup.classical`'s epoch
			// advances.
			let updatedLeafKeys = try Self.updateRecvClassicalKeys(
				leafKeys, classical: recv.classical,
				authCopy: authCopy, rotationCandidateID: rotationCandidate?.clientID
			)

			recvGroup = recv
			sendGroup = send
			sendCrossPSKLedger = ledger
			sendAttachmentLedger = attachmentLedger
			recvAttachmentLedger = recvAttachmentLedgerLocal
			stagedUpdates = []
			// Drain the own-offer window record — see
			// `applyFoldCommit`'s own comment; this is the ONLY other site
			// `recvGroup.classical`'s epoch advances.
			self.ownOfferWindow = nil
			pqTurnMine = true
			pqInflight = nil
			pendingSideBand = nil
			if let pendingSendPQExportedStamp {
				lastSendPQExported = pendingSendPQExportedStamp
			}
			auth = authCopy
			leafKeys = updatedLeafKeys
			return StapleApplyResult(
				applied: true, newSender: newSender,
				ownCredentialCanonicalized: ownCanonicalized)
		}
	}
}
