import Foundation
import MLSCodec
import MLSCombiner
import MLSProfileRFC9420

// MARK: - Send / receive (one app message; no commit) — messaging loop

@available(iOS 26, macOS 26, *)
extension TwoMLSSession {
	/// Stage a routine `Upd(self)` into the **receive** group (the peer's send
	/// group, where the peer folds it) — framed `.publicMessage` to match the
	/// Rust reference's control-message framing (m4). Requires `isEstablished`:
	/// the initiator cannot send before its first inbound frame joins Group_B.
	///
	/// First runs a `committingRound` (§4b/§5/§3c) — folding an approved peer
	/// Update, discharging an owed bind if one is licensed, and/or catching up
	/// my own send-leaf's presentation — into a FULL commit on
	/// `sendGroup.classical`, stapling either a bare `0x00` fold or the `0x05`
	/// bind pair, so `encrypt` then protects the app on the newly-advanced
	/// epoch. `didCommit` reports whether that happened; `committedRemoteClientID`
	/// is set only when a fold rode.
	///
	/// `rotating`, when non-nil, authors a classical principal rotation
	/// (slice 6): mint a fresh signature keypair for `rotating` (or, if it
	/// already names the single outstanding `rotationCandidate`, reuse that
	/// candidate's key — idempotent), then stage it as the `Upd(self)` via
	/// the rotation ring + `NewSigningIdentity` instead of the routine
	/// single-key form. Rejects `rotating` naming my own recv-leaf's
	/// CURRENT id outright (`.credentialUnknown`) — that offer could never
	/// canonicalize (`PartySequence.commit`'s own `current == id` no-op),
	/// so it would sit `.pending` forever. F2's one-generation cap: a
	/// DIFFERENT id while a candidate is still outstanding is
	/// `.rotationInFlight`, UNLESS the wedge relaxation applies — the
	/// outstanding candidate never canonicalized (`auth.mine.history` does
	/// not yet contain it) AND `recvGroup.classical`'s epoch has moved past
	/// the epoch its `Upd` was staged at, so the peer can no longer fold
	/// that now-stale proposal. A candidate that DID canonicalize is never
	/// replaced this way — dropping it would strand the very key both
	/// classical leaves may already present, bricking the session; a
	/// second rotation on an already-converged leaf must instead wait for
	/// a later slice's PQ catch-up.
	public mutating func prepareToEncrypt(rotating: Data? = nil) throws -> PrepareResult {
		guard recvGroup != nil, sendGroup != nil else {
			throw TwoMLSError.notEstablished
		}
		// Slice 11 (Fable MAJ-6): the non-emittable gate, BEFORE `committingRound()`
		// — a commit landing here before install would replace the bare
		// `0x01` staple and make `installEstablishmentEnvelope` fail
		// `.sessionNotReady` forever.
		try ensureEstablishmentDelegated()
		let (didCommit, committedRemoteClientID) = try committingRound()
		rewrapSideBand()

		guard var recv = recvGroup else { throw TwoMLSError.notEstablished }

		let message: MLS.RFC9420.Message
		let proposing: Data
		var mintedCandidate: RotationCandidate?

		// CODE FIX 2: rotating "to" the id already occupying my own
		// recv-leaf can never converge — `PartySequence.commit(current)`
		// early-returns as a no-op, so the offer would sit `.pending`
		// forever with no fold ever able to canonicalize it.
		let myCurrentID = try basicIdentifier(Self.ownLeaf(of: recv.classical).credential)

		// Slice 11, §C.4 (Fable CRIT-2): the recv-leaf catch-up — my own
		// recv-leaf still lags my canonical principal (the born-dedicated
		// acceptor's Group_A leaf presenting the invitation identity while
		// `auth.mine.current` is already D) AND custody over the lagging
		// key is still held. Explicit `rotating:` wins over this implicit
		// arm (checked first, below) UNLESS it names D itself — closing the
		// `rotating == auth.mine.current` hole (Messaging:65-99 would
		// otherwise mint a 2nd D keypair and leak `authorize(D)` into
		// `authorizedNext` forever, since `PartySequence.commit`'s own
		// `current == id` early return never canonicalizes a no-op).
		if rotating == nil, let custody = recvLeafPrincipal,
			myCurrentID != auth.mine.current,
			custody.clientID == myCurrentID
		{
			let (catchUpMessage, _) = try recv.classical.proposeUpdate(
				classicalProvider,
				sign: MLS.RFC9420.signingClosure(
					classicalProvider, current: custody.signingKey,
					new: identity.signingKey),
				framing: .publicMessage,
				newIdentity: MLS.RFC9420.NewSigningIdentity(
					credential: .basic(identity: identity.clientID),
					signatureKey: identity.signatureKey))
			message = catchUpMessage
			proposing = identity.clientID
		} else if let rotating {
			guard !rotating.isEmpty else { throw TwoMLSError.credentialUnknown }
			guard rotating != myCurrentID else { throw TwoMLSError.credentialUnknown }

			if rotating == auth.mine.current {
				// Naming the identity already canonical isn't a NEW
				// rotation — route it to the SAME catch-up this session
				// would perform implicitly, if custody is still held; else
				// there is nothing to catch up AND no legitimate rotation
				// target here either.
				guard let custody = recvLeafPrincipal,
					custody.clientID == myCurrentID
				else {
					throw TwoMLSError.credentialUnknown
				}
				let (catchUpMessage, _) = try recv.classical.proposeUpdate(
					classicalProvider,
					sign: MLS.RFC9420.signingClosure(
						classicalProvider, current: custody.signingKey,
						new: identity.signingKey),
					framing: .publicMessage,
					newIdentity: MLS.RFC9420.NewSigningIdentity(
						credential: .basic(identity: identity.clientID),
						signatureKey: identity.signatureKey))
				message = catchUpMessage
				proposing = identity.clientID
			} else {
				let candidate: RotationCandidate
				if let existing = rotationCandidate, existing.clientID == rotating {
					// Idempotent: re-stage under the SAME candidate key rather
					// than minting a new one, which would strand whichever leaf
					// already presents the existing candidate's key.
					candidate = existing
				} else {
					if let existing = rotationCandidate {
						// CODE FIX 1: the wedge relaxation may replace a
						// candidate only when it is DEAD — never canonicalized
						// (absent from `auth.mine.history`) — AND the peer can
						// no longer fold its now-stale proposal
						// (`recvGroup.classical`'s epoch has moved past the
						// epoch it was staged at). A candidate that DID
						// converge means a rotation already landed on this
						// leaf; replacing it here would drop the very key both
						// classical leaves may already present, bricking every
						// later `encrypt`/`prepareToEncrypt` — so a second
						// rotation on a converged leaf is rejected outright
						// (F2's one-generation cap) until a later slice's PQ
						// catch-up.
						guard
							!auth.mine.history.contains(
								existing.clientID),
							recv.classical.context.epoch
								> existing.proposedAtRecvEpoch
						else {
							throw TwoMLSError.rotationInFlight
						}
					}
					let (signingKey, signatureKey) =
						try TwoMLSIdentity.mintSignatureKeypair()
					candidate = RotationCandidate(
						clientID: rotating, signingKey: signingKey,
						signatureKey: signatureKey,
						proposedAtRecvEpoch: recv.classical.context.epoch)
				}

				// MF5/the ring: `.framedContent` stays on the recv-leaf's
				// CURRENT key (still OLD — recv-classical has not
				// canonicalized yet), so the peer's `verifying(proposal:)`
				// checks it against the pre-commit sender leaf; `.leafNode`
				// routes to the candidate's NEW key, which is what the
				// peer's AS validates as a successor.
				let (rotatingMessage, _) = try recv.classical.proposeUpdate(
					classicalProvider,
					sign: MLS.RFC9420.signingClosure(
						classicalProvider,
						current: try recvClassicalSigningKey(),
						new: candidate.signingKey),
					framing: .publicMessage,
					newIdentity: MLS.RFC9420.NewSigningIdentity(
						credential: .basic(identity: candidate.clientID),
						signatureKey: candidate.signatureKey))
				message = rotatingMessage
				proposing = candidate.clientID
				mintedCandidate = candidate
			}
		} else {
			// §3b: after `canonicalized_own`, my recv-leaf presents the NEW
			// credential, and a routine (non-rotating) `Upd` must sign under
			// it — read straight off the tree rather than trusting bookkeeping.
			proposing = try basicIdentifier(Self.ownLeaf(of: recv.classical).credential)
			let (routineMessage, _) = try recv.classical.proposeUpdate(
				classicalProvider, signingKey: try recvClassicalSigningKey(),
				framing: .publicMessage)
			message = routineMessage
		}

		// MF4: value semantics — every throwing call above ran on the LOCAL
		// `recv` copy (and minted a candidate only into a local var); only
		// on success do we write back `recvGroup`, `rotationCandidate`, and
		// `auth.mine`'s authorization.
		recvGroup = recv
		if let mintedCandidate {
			rotationCandidate = mintedCandidate
			auth.mine.authorize(mintedCandidate.clientID)
		}

		let proposalBytes = try message.mlsEncoded()
		// `sha256` for the deployed classical suite (curve25519ChaCha), matching
		// the book's fixed sha256 for `proposal_hash`.
		let proposalHash = try classicalProvider.hash(proposalBytes)
		pendingProposal = (
			proposing: proposing, message: proposalBytes, hash: proposalHash
		)
		// §11 MF3: retain every Upd(self) staged this recv epoch — not just the
		// latest — so a `0x00`/`0x05` staple that folds an earlier one by
		// reference can still resolve it.
		stagedUpdates.append((digest: proposalHash, message: proposalBytes))

		// Return cadence (slice 8a): classical-only mutation → `.core`. `didCommit`
		// installed a fresh `currentStaple` (`committingRound`'s success
		// point) iff it folded/discharged/caught-up — stamp the durability
		// watermark at THIS call's own (just-bumped) `stateSeq` exactly then.
		advanceStateSeq()
		if didCommit { markStapleInstalled() }
		let update = try stateUpdate(kind: .core)
		return PrepareResult(
			proposalMessage: proposalBytes, proposalHash: proposalHash,
			didCommit: didCommit, committedRemoteClientID: committedRemoteClientID,
			update: update, dependsOnSeq: currentStapleSeq
		)
	}

	/// Seal `app` on the send group with the pending proposal's hash as its
	/// carried `authenticated_data`, and frame it alongside that proposal and
	/// the current staple. The AEAD binds the hash to *this* app message, not
	/// to the frame's separate proposal section — proposal integrity is its own
	/// MLS leaf signature, checked when folded (`queueProposal`/
	/// `committingRound`/`applyFoldCommit`, slice 5) (M1).
	public mutating func encrypt(_ app: Data) throws -> EncryptResult {
		// Slice 11 (Fable MAJ-6): the non-emittable gate.
		try ensureEstablishmentDelegated()
		guard let pending = pendingProposal else { throw TwoMLSError.noPendingProposal }
		guard var send = sendGroup else { throw TwoMLSError.notEstablished }
		let appPM = try send.classical.protect(
			classicalProvider, applicationData: app, authenticatedData: pending.hash,
			signingKey: try sendClassicalSigningKey())
		sendGroup = send
		pendingProposal = nil

		// The app section is a full `Message`, not a bare `PrivateMessage` (M2) —
		// matches the proposal section, which already carries a full `Message`.
		let appBytes = try MLS.RFC9420.Message.privateMessage(appPM).mlsEncoded()
		let proposalSection = Frames.encodeProposalSection(
			proposing: pending.proposing, message: pending.message)
		let frame = Frames.encodeMessageFrame(
			staple: currentStaple, proposal: proposalSection, app: appBytes)
		// A co-stapled side-band frame pads up to this (unsealed) length.
		lastMessageFrameLen = frame.count

		// §A.4 self-drive: both best-effort (never throw out of `encrypt`) —
		// `rewrapSideBand` re-mints a stale parked leg at the epoch this send
		// just moved to; `maybeStageNextRound` then stages the next EK if it's
		// my turn and nothing else is outstanding.
		rewrapSideBand()
		maybeStageNextRound()

		// Sealed on exit (PR2, header-encryption.md "Send rule"): every
		// outbound message-path frame is header-sealed under the recv
		// group's current classical key.
		let sealedFrame = try seal(frame)

		// Return cadence (slice 8a): classical-only mutation → `.core`.
		advanceStateSeq()
		let update = try stateUpdate(kind: .core)
		return EncryptResult(frame: sealedFrame, update: update)
	}

	/// Slice 11, §C.2/§C.5: which pre-verified `0x0B` (envelope, welcome)
	/// pair `processIncomingApproved` pins, or the absence of one for plain
	/// `processIncoming` — threaded through the shared dispatch below so the
	/// two public entry points share every code path except this.
	private enum EstablishmentApproval {
		case unapproved
		case approved(envelopeDigest: Data, welcomeDigest: Data, expectedCreator: Data)
	}

	/// Decode a frame, apply its staple (join Group_B, a `0x00` fold, or a
	/// `0x05` bind — idempotently, when the staple merely re-rides a commit
	/// already applied off an earlier frame), decrypt the app section against
	/// the receive group, and surface the peer's staged proposal uninterpreted
	/// (`queueProposal` is the approval step that folds it). Slice 11, §C.5:
	/// also dispatches a STANDALONE `0x01`/`0x0B` frame (no `0x03` wrapper),
	/// and PAUSES on a `0x0B` (stapled or standalone) while `recvGroup ==
	/// nil` rather than joining — see `IncomingResult`.
	public mutating func processIncoming(_ inbound: Data) throws -> IncomingResult {
		try dispatchIncoming(inbound, approval: .unapproved)
	}

	/// Slice 11, §C.2: re-feed a frame carrying a `0x0B` pair the caller has
	/// already verified out of band, pinned by digest over EXACTLY the two
	/// `0x0B` sections — not "same inbound only": ANY frame carrying that
	/// approved pair is approvable, including a LATER re-staple (how a
	/// dropped early frame heals). Stateless: both digests must match else
	/// this re-pauses (`.pendingEstablishment`, never joins) exactly like an
	/// unapproved `processIncoming` would. §D Fable F4: the approval is
	/// consulted IFF the frame carries a `0x0B` section AND `recvGroup ==
	/// nil` — every other input processes exactly as `processIncoming`, so
	/// approval can never launder a bare welcome.
	public mutating func processIncomingApproved(
		_ inbound: Data, approvedEnvelopeDigest: Data, approvedWelcomeDigest: Data,
		expectedCreator: Data
	) throws -> IncomingResult {
		try dispatchIncoming(
			inbound,
			approval: .approved(
				envelopeDigest: approvedEnvelopeDigest,
				welcomeDigest: approvedWelcomeDigest,
				expectedCreator: expectedCreator))
	}

	private mutating func dispatchIncoming(
		_ inbound: Data, approval: EstablishmentApproval
	) throws -> IncomingResult {
		// Entry (PR2): transparently removes the header seal if present,
		// else passes an already-opened frame straight through (book,
		// "Receive rule" convenience).
		let frame = openOrRaw(inbound)
		guard let tag = frame.first else { throw TwoMLSError.truncatedSection }
		switch tag {
		case Frames.messageFrameTag:
			return try processMessageFrame(frame, approval: approval)
		case Frames.establishmentHandoffTag:
			return try processStandaloneHandoff(frame, approval: approval)
		case Frames.apqWelcomeTag:
			return try processStandaloneWelcome(frame)
		default:
			throw TwoMLSError.unsupportedFrameTag(tag)
		}
	}

	/// The `0x03` message-frame path: pauses on a `0x0B` staple while
	/// `recvGroup == nil` (unless `approval` already pins its exact pair, in
	/// which case it joins and decrypts in one step) — otherwise decodes and
	/// decrypts normally, `handleStaple` extracting/dedup-ing an already-
	/// joined `0x0B`'s inner welcome same as it always has for `0x01`.
	private mutating func processMessageFrame(
		_ frame: Data, approval: EstablishmentApproval
	) throws -> IncomingResult {
		let (staple, proposalSection, appSection) = try Frames.decodeMessageFrame(frame)
		if staple.first == Frames.establishmentHandoffTag, recvGroup == nil {
			let (envelope, welcome) = try Frames.decodeEstablishmentHandoff(staple)
			if case .approved(
				let envelopeDigest, let welcomeDigest, let expectedCreator) =
				approval,
				try classicalProvider.hash(envelope) == envelopeDigest,
				try classicalProvider.hash(welcome) == welcomeDigest
			{
				return try joinAndDecrypt(
					welcome: welcome, proposalSection: proposalSection,
					appSection: appSection,
					mode: .approved(expectedCreator))
			}
			return .pendingEstablishment(
				PendingEstablishment(envelope: envelope, welcome: welcome))
		}
		let appMessage = try MLS.RFC9420.Message(mlsEncoded: appSection)
		guard case .privateMessage(let appPM) = appMessage else {
			throw TwoMLSError.appSectionNotPrivateMessage
		}
		// Return cadence (slice 8a): `applyBind` rides this method's staple
		// dispatch and moves `recvGroup.pq`, so the kind can't be a static
		// per-site tag here — snapshot both PQ trees' epoch before/after the
		// staple applies and tag `.checkpoint` iff either actually moved.
		// (`stateUpdate(kind:)`'s sticky invariant is the actual guarantee
		// against an un-checkpointed move surviving a later throw in this
		// same method; this snapshot only picks the precise kind up front.)
		let pqManifestBefore = pqEpochManifest
		let stapleResult = try handleStaple(staple)
		let result = try decryptAppSection(
			appPM: appPM, proposalSection: proposalSection, stapleResult: stapleResult,
			pqManifestBefore: pqManifestBefore)
		return .decrypted(result)
	}

	/// Standalone `0x01` (§C.5): a factored Group_B join under `.bare` mode,
	/// no app section — the FIRST join is state-advancing (`.joined`,
	/// Fable F3), an idempotent re-delivery is `.ignored`.
	private mutating func processStandaloneWelcome(_ frame: Data) throws -> IncomingResult {
		guard let expectedCreator = auth.theirs.current else {
			throw TwoMLSError.unknownIdentity
		}
		let digest = try classicalProvider.hash(frame)
		guard recvGroup == nil else {
			try dedupJoinedWelcome(digest: digest)
			return .ignored
		}
		let newSender = try joinGroupB(innerWelcome: frame, mode: .bare(expectedCreator))
		advanceStateSeq()
		return .joined(newSender: newSender, update: try stateUpdate(kind: .core))
	}

	/// Standalone `0x0B` (§C.5): PAUSES ONLY while `recvGroup == nil` — an
	/// approved re-feed joins in the same call; already joined, this dedups
	/// on the INNER welcome digest (`.ignored`) or rejects a different one
	/// (`.unexpectedWelcome`) — NEVER re-pauses post-join.
	private mutating func processStandaloneHandoff(
		_ frame: Data, approval: EstablishmentApproval
	) throws -> IncomingResult {
		let (envelope, welcome) = try Frames.decodeEstablishmentHandoff(frame)
		guard recvGroup == nil else {
			try dedupJoinedWelcome(digest: try classicalProvider.hash(welcome))
			return .ignored
		}
		if case .approved(let envelopeDigest, let welcomeDigest, let expectedCreator) =
			approval,
			try classicalProvider.hash(envelope) == envelopeDigest,
			try classicalProvider.hash(welcome) == welcomeDigest
		{
			let newSender = try joinGroupB(
				innerWelcome: welcome, mode: .approved(expectedCreator))
			advanceStateSeq()
			return .joined(newSender: newSender, update: try stateUpdate(kind: .core))
		}
		return .pendingEstablishment(
			PendingEstablishment(envelope: envelope, welcome: welcome))
	}

	/// The approved-join analogue of `processMessageFrame`'s ordinary
	/// decrypt path: the join itself IS this call's staple apply (a fresh
	/// join is never a "remote commit apply" — `applied: false`, mirroring
	/// `StapleApplyResult.notApplied` — `newSender` is the sole adoption
	/// signal, TwoMLSSession.swift's own `newSender` doc).
	private mutating func joinAndDecrypt(
		welcome: Data, proposalSection: Data, appSection: Data,
		mode: APQGroup.JoinCreatorMode
	) throws -> IncomingResult {
		let appMessage = try MLS.RFC9420.Message(mlsEncoded: appSection)
		guard case .privateMessage(let appPM) = appMessage else {
			throw TwoMLSError.appSectionNotPrivateMessage
		}
		let pqManifestBefore = pqEpochManifest
		let newSender = try joinGroupB(innerWelcome: welcome, mode: mode)
		let stapleResult = StapleApplyResult(
			applied: false, newSender: newSender, ownCredentialCanonicalized: false)
		let result = try decryptAppSection(
			appPM: appPM, proposalSection: proposalSection, stapleResult: stapleResult,
			pqManifestBefore: pqManifestBefore)
		return .decrypted(result)
	}

	/// The shared "decrypt the app section, surface the peer's staged
	/// proposal, mint this call's `StateUpdate`" tail — factored out of
	/// `processMessageFrame` so `joinAndDecrypt` (the approved-join path)
	/// can share it exactly, differing only in how `stapleResult` was
	/// produced.
	private mutating func decryptAppSection(
		appPM: MLS.RFC9420.PrivateMessage, proposalSection: Data,
		stapleResult: StapleApplyResult, pqManifestBefore: PQEpochManifest
	) throws -> DecryptResult {
		guard var recv = recvGroup else { throw TwoMLSError.notEstablished }
		let unprotected = try recv.classical.unprotect(classicalProvider, message: appPM)
		recvGroup = recv

		guard case .application(let data) = unprotected.content else {
			throw TwoMLSError.unprotectedContentNotApplication
		}

		let (proposing, proposalMessage) = try Frames.decodeProposalSection(proposalSection)
		// `sha256` for the deployed classical suite, matching the book's fixed
		// sha256 for `proposal_hash`.
		let digest = try classicalProvider.hash(proposalMessage)
		stampLicenseIfOffered(proposalMessage)
		// §11 MF8: replace whatever offer was previously surfaced,
		// unconditionally — single-occupancy, latest-wins, exactly like the
		// approved tally it feeds.
		offeredProposal = (digest: digest, proposing: proposing, message: proposalMessage)

		let kind: BlobKind = pqEpochManifest == pqManifestBefore ? .core : .checkpoint
		advanceStateSeq()
		let update = try stateUpdate(kind: kind)
		return DecryptResult(
			applicationMessage: data, sender: unprotected.sender,
			epoch: unprotected.epoch,
			authenticatedData: unprotected.authenticatedData,
			didApplyRemoteCommit: stapleResult.applied,
			newSender: stapleResult.newSender,
			ownCredentialCanonicalized: stapleResult.ownCredentialCanonicalized,
			queuedProposal: QueuedProposal(digest: digest, proposing: proposing),
			update: update)
	}

	/// `0x01`/`0x0B` welcome → join Group_B if this staple hasn't been
	/// joined yet (idempotent otherwise, dedup-ing on the INNER `0x01`
	/// welcome digest — Fable F5); `0x00` mlsMessage → the fold-only commit
	/// apply arm (§11 checkpoint 3); `0x05` apqPrivateMessage → `applyBind`.
	/// Returns whether a remote commit was actually applied (`false` for a
	/// welcome/handoff, or an idempotent skip of a commit already applied
	/// off an earlier frame). A `0x0B` staple only ever reaches this arm
	/// already joined (`processMessageFrame` pauses on it first while
	/// `recvGroup == nil`), so it only ever dedups here, never joins.
	@discardableResult
	private mutating func handleStaple(_ staple: Data) throws -> StapleApplyResult {
		guard let tag = staple.first else { throw TwoMLSError.truncatedSection }
		switch Frames.stapleKind(tag) {
		case .welcome:
			return try applyWelcomeStaple(staple)
		case .establishmentHandoff:
			let (_, welcome) = try Frames.decodeEstablishmentHandoff(staple)
			return try applyWelcomeStaple(welcome)
		case .mlsMessage:
			let commitBytes = try Frames.decodeMlsMessageStaple(staple)
			return try applyFoldCommit(commitBytes)
		case .apqPrivateMessage:
			return try applyBind(staple)
		case .unsupported(let tag):
			throw TwoMLSError.unsupportedStapleTag(tag)
		}
	}

	private mutating func applyWelcomeStaple(_ welcome: Data) throws -> StapleApplyResult {
		guard recvGroup == nil else {
			try dedupJoinedWelcome(digest: try classicalProvider.hash(welcome))
			return .notApplied
		}
		guard let expectedCreator = auth.theirs.current else {
			throw TwoMLSError.unknownIdentity
		}
		let newSender = try joinGroupB(innerWelcome: welcome, mode: .bare(expectedCreator))
		return StapleApplyResult(
			applied: false, newSender: newSender, ownCredentialCanonicalized: false)
	}

	/// §5/§11 #8: the discharge license. If `proposalMessage` (every frame's
	/// routine staged proposal) decodes as a `PublicMessage` `Update` that
	/// verifies against MY OWN `sendGroup.classical` — framed by the peer's
	/// own leaf there, not mine — the peer has evidently applied at least my
	/// current send epoch, so `prepareToEncrypt` may discharge an owed bind
	/// against it. Any other shape (a decode failure, a stale/foreign epoch,
	/// a failed signature, or a proposal apparently framed by my own leaf) is
	/// silently not-a-license, not an error — this is an additional read on
	/// data `processIncoming` already carries uninterpreted, not a required
	/// decode.
	///
	/// Seam: this checks the Update verifies against `sendGroup.classical`
	/// and was framed by a leaf other than my own, but never compares the
	/// Update's credential against `proposing` (the frame's carried sender
	/// id) — not a forgery vector today, since the Update is itself
	/// signature- and membership-tag-authenticated; only relevant once
	/// `proposing` names something other than "my one peer."
	private mutating func stampLicenseIfOffered(_ proposalMessage: Data) {
		withDeployedWireConventions {
			guard let message = try? MLS.RFC9420.Message(mlsEncoded: proposalMessage),
				case .publicMessage(let updatePub) = message,
				let send = sendGroup
			else {
				return
			}
			guard
				let verified = try? send.classical.verifying(
					classicalProvider, proposal: updatePub),
				case .member(let senderLeaf) = verified.sender,
				senderLeaf != send.classical.myLeafIndex
			else {
				return
			}
			peerAppliedSendEpoch = send.classical.context.epoch
		}
	}

	/// Dedup guard for a staple/standalone welcome or handoff whose INNER
	/// `0x01` welcome digest is `digest`: `recvGroup` is already set, so no
	/// further join can happen here — either this exact digest is the one
	/// already joined (idempotent re-delivery) or it isn't
	/// (`.unexpectedWelcome`, covering both a genuinely different welcome
	/// and the acceptor's `recvGroup`-from-birth topology, whose
	/// `joinedWelcomeDigest` is always `nil` — Fable F1/T1/T2).
	private func dedupJoinedWelcome(digest: Data) throws {
		guard let joined = joinedWelcomeDigest, joined == digest else {
			throw TwoMLSError.unexpectedWelcome
		}
	}

	/// Slice 11, §C.5 (Fable F5): the shared join primitive for all four
	/// callers (stapled/standalone × `0x01`/`0x0B`) — join Group_B from the
	/// INNER `0x01` welcome bytes under `mode`. Callers must have already
	/// established `recvGroup == nil` (a genuinely new join); a re-delivery
	/// dedups via `dedupJoinedWelcome` instead of ever reaching here. Admits
	/// the joined creator into `auth.theirs` when it differs from what this
	/// session already tracks (the born-dedicated adoption, one-shot —
	/// PSK-authenticated by the join itself), returning that id as the
	/// caller's `newSender`.
	private mutating func joinGroupB(
		innerWelcome staple: Data, mode: APQGroup.JoinCreatorMode
	) throws -> Data? {
		let digest = try classicalProvider.hash(staple)
		let (tBytes, pqBytes) = try Frames.decodeAPQWelcome(staple)
		guard pqBytes.isEmpty else { throw TwoMLSError.fullEstablishmentStapleUnsupported }

		// Parse BEFORE the one-shot `0xFF02` exporter leaf is consumed — a
		// malformed or foreign welcome must leave the leaf unspent so the
		// peer's genuine frame still joins (Rust is ledger-first for the same
		// reason: `remember_send_psk` no-ops once an epoch is ledgered, so a
		// retry never re-exports an already-consumed `(group, epoch, component)`).
		let welcome = try MLS.RFC9420.Welcome(mlsEncoded: tBytes)

		// Derive my own copy of the cross-party PSK off MY Group_A (the session's
		// send group here — I am the initiator joining Group_B) rather than
		// trusting any wire-carried value (m6), via the ledger-aware idempotent
		// exporter. §11 MF4: this consumes `sendGroup.classical`'s (Group_A's)
		// epoch-1 `0xFF02` leaf — the exact `(group, epoch, component)` the
		// send-side ledger otherwise "remembers" lazily on first commit. Seed
		// it with this already-derived value so `committingRound`'s first
		// `0x00`/`0x05` round doesn't attempt a second, failing export of the
		// same leaf.
		guard var groupA = sendGroup else { throw TwoMLSError.notEstablished }
		var ledger = sendCrossPSKLedger
		try rememberSendCrossPSK(classical: &groupA.classical, ledger: &ledger)
		guard let crossPSK = ledger[groupA.classical.context.epoch] else {
			throw TwoMLSError.notEstablished  // unreachable: just remembered
		}
		// Same reasoning, `0xFF03` attachment component (+Attachment.swift) —
		// Group_A is this session's send group, so this is a send-side capture.
		var attachmentLedger = sendAttachmentLedger
		try rememberSendAttachmentComponent(
			classical: &groupA.classical, ledger: &attachmentLedger)

		var groupB = try APQGroup.joinClassicalOnly(
			welcome: welcome, credentials: try identity.classicalJoinCredentials,
			crossPSK: crossPSK, mode: mode,
			provider: classicalProvider, codepoints: codepoints)
		try TwoPartyRules.ensureTwoParty(groupB.classical)
		// CAPTURE-ON-ENTRY (+Attachment.swift): `groupB` becomes `recvGroup`
		// for the FIRST time below — ledger its birth epoch's `0xFF03`
		// component now, mirroring `receive`'s own recv-group-creation
		// capture.
		var recvAttachmentLedgerLocal = recvAttachmentLedger
		try rememberRecvAttachmentComponent(
			classical: &groupB.classical, ledger: &recvAttachmentLedgerLocal)

		// App-state binding: the return welcome must carry back exactly THIS
		// session's own binding — read off Group_A (`groupA.classical`, this
		// session's send group) rather than any wire-carried claim — so an
		// absent or different binding here is a strip/downgrade or
		// wrong-relationship welcome (book group-rules.md rule 8, mirrors
		// Rust's `test_return_welcome_without_app_binding_rejected`). Group_B
		// is classical-only at this point (`pq == nil`), so
		// `verifyPQHalfUnbound` is a no-op here — kept for call-site symmetry
		// with every other PQ-half join.
		let ownAppBinding = try AppBinding.read(fromExtensionsOf: groupA.classical.context)
		try verifyAppBinding(groupB.classical, expected: ownAppBinding)
		try verifyPQHalfUnbound(groupB.pq)
		let creatorLeaf = try Self.joinedCreatorLeaf(of: groupB.classical)
		if ownAppBinding != nil {
			try ensureAppBindingCreatorLeafAdvert(creatorLeaf)
		}

		// Slice 11, §C.2: admit the joined creator into `auth.theirs` when
		// it's new — the born-dedicated adoption. A `.bare`-mode join can
		// only ever reach this point already equal to `auth.theirs.current`
		// (a mismatch there throws inside `joinClassicalOnly` instead), so
		// this only ever fires for an `.approved` join.
		let creatorID = try basicIdentifier(creatorLeaf.credential)
		var newSender: Data?
		if creatorID != auth.theirs.current {
			try auth.theirs.commit(creatorID)
			newSender = creatorID
		}

		// Value semantics: every throwing call above ran on locals, so a failed
		// join leaves `self`'s Group_A exporter leaf unspent (the whole C-3 fix).
		sendGroup = groupA
		sendCrossPSKLedger = ledger
		sendAttachmentLedger = attachmentLedger
		recvGroup = groupB
		recvAttachmentLedger = recvAttachmentLedgerLocal
		joinedWelcomeDigest = digest
		// This was the initiator's own classical init secret's one use
		// (`initiate` deferred clearing it exactly for this join) — clear it
		// now so it can never be archived once spent.
		identity = identity.clearingInitSecrets(classical: true, pq: false)
		// The initiator has nothing left to establish past this point —
		// `pendingOutbound()` (PR3b) has no more envelope to re-seal.
		initialTheirKP = nil
		return newSender
	}
}
