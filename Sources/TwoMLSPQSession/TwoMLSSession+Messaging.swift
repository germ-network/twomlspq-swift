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
		let (didCommit, committedRemoteClientID) = try committingRound()
		rewrapSideBand()

		guard var recv = recvGroup else { throw TwoMLSError.notEstablished }

		let message: MLS.RFC9420.Message
		let proposing: Data
		var mintedCandidate: RotationCandidate?

		if let rotating {
			guard !rotating.isEmpty else { throw TwoMLSError.credentialUnknown }
			// CODE FIX 2: rotating "to" the id already occupying my own
			// recv-leaf can never converge — `PartySequence.commit(current)`
			// early-returns as a no-op, so the offer would sit `.pending`
			// forever with no fold ever able to canonicalize it.
			let myCurrentID = try basicIdentifier(
				Self.ownLeaf(of: recv.classical).credential)
			guard rotating != myCurrentID else { throw TwoMLSError.credentialUnknown }

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
					guard !auth.mine.history.contains(existing.clientID),
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

			// MF5/the ring: `.framedContent` stays on the recv-leaf's CURRENT
			// key (still OLD — recv-classical has not canonicalized yet), so
			// the peer's `verifying(proposal:)` checks it against the
			// pre-commit sender leaf; `.leafNode` routes to the candidate's
			// NEW key, which is what the peer's AS validates as a successor.
			let (rotatingMessage, _) = try recv.classical.proposeUpdate(
				classicalProvider,
				sign: MLS.RFC9420.signingClosure(
					classicalProvider, current: try recvClassicalSigningKey(),
					new: candidate.signingKey),
				framing: .publicMessage,
				newIdentity: MLS.RFC9420.NewSigningIdentity(
					credential: .basic(identity: candidate.clientID),
					signatureKey: candidate.signatureKey))
			message = rotatingMessage
			proposing = candidate.clientID
			mintedCandidate = candidate
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
		return PrepareResult(
			proposalMessage: proposalBytes, proposalHash: proposalHash,
			didCommit: didCommit, committedRemoteClientID: committedRemoteClientID
		)
	}

	/// Seal `app` on the send group with the pending proposal's hash as its
	/// carried `authenticated_data`, and frame it alongside that proposal and
	/// the current staple. The AEAD binds the hash to *this* app message, not
	/// to the frame's separate proposal section — proposal integrity is its own
	/// MLS leaf signature, checked when folded (`queueProposal`/
	/// `committingRound`/`applyFoldCommit`, slice 5) (M1).
	public mutating func encrypt(_ app: Data) throws -> Data {
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

		// §A.4 self-drive: both best-effort (never throw out of `encrypt`) —
		// `rewrapSideBand` re-mints a stale parked leg at the epoch this send
		// just moved to; `maybeStageNextRound` then stages the next EK if it's
		// my turn and nothing else is outstanding.
		rewrapSideBand()
		maybeStageNextRound()
		return frame
	}

	/// Decode a frame, apply its staple (join Group_B, a `0x00` fold, or a
	/// `0x05` bind — idempotently, when the staple merely re-rides a commit
	/// already applied off an earlier frame), decrypt the app section against
	/// the receive group, and surface the peer's staged proposal uninterpreted
	/// (`queueProposal` is the approval step that folds it).
	public mutating func processIncoming(_ frame: Data) throws -> DecryptResult {
		let (staple, proposalSection, appSection) = try Frames.decodeMessageFrame(frame)
		let appMessage = try MLS.RFC9420.Message(mlsEncoded: appSection)
		guard case .privateMessage(let appPM) = appMessage else {
			throw TwoMLSError.appSectionNotPrivateMessage
		}

		let stapleResult = try handleStaple(staple)

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

		return DecryptResult(
			applicationMessage: data, sender: unprotected.sender,
			epoch: unprotected.epoch,
			authenticatedData: unprotected.authenticatedData,
			didApplyRemoteCommit: stapleResult.applied,
			newSender: stapleResult.newSender,
			ownCredentialCanonicalized: stapleResult.ownCredentialCanonicalized,
			queuedProposal: QueuedProposal(digest: digest, proposing: proposing))
	}

	/// `0x01` welcome → join Group_B if this staple hasn't been joined yet
	/// (idempotent otherwise, matching the reference's welcome dedup); `0x00`
	/// mlsMessage → the fold-only commit apply arm (§11 checkpoint 3); `0x05`
	/// apqPrivateMessage → `applyBind`. Returns whether a remote commit was
	/// actually applied (`false` for a welcome, or an idempotent skip of a
	/// commit already applied off an earlier frame).
	@discardableResult
	private mutating func handleStaple(_ staple: Data) throws -> StapleApplyResult {
		guard let tag = staple.first else { throw TwoMLSError.truncatedSection }
		switch Frames.stapleKind(tag) {
		case .welcome:
			try joinGroupBIfNeeded(fromStaple: staple)
			return .notApplied
		case .mlsMessage:
			let commitBytes = try Frames.decodeMlsMessageStaple(staple)
			return try applyFoldCommit(commitBytes)
		case .apqPrivateMessage:
			return try applyBind(staple)
		case .unsupported(let tag):
			throw TwoMLSError.unsupportedStapleTag(tag)
		}
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

	private mutating func joinGroupBIfNeeded(fromStaple staple: Data) throws {
		// `sha256` for the deployed classical suite, matching the book's fixed
		// sha256 for the welcome digest.
		let digest = try classicalProvider.hash(staple)
		if let joined = joinedWelcomeDigest, joined != digest {
			throw TwoMLSError.unexpectedWelcome
		}
		guard joinedWelcomeDigest != digest else { return }

		let (tBytes, pqBytes) = try Frames.decodeAPQWelcome(staple)
		guard pqBytes.isEmpty else { throw TwoMLSError.fullEstablishmentStapleUnsupported }

		// Derive my own copy of the cross-party PSK off MY Group_A (the session's
		// send group here — I am the initiator joining Group_B) rather than
		// trusting any wire-carried value (m6).
		guard var groupA = sendGroup else { throw TwoMLSError.notEstablished }
		let crossPSK = try MLS.Combiner.ExportedPsk.export(
			from: &groupA.classical, classicalProvider,
			componentID: Self.crossPartyComponentID)
		sendGroup = groupA
		// §11 MF4: this consumes `sendGroup.classical`'s (Group_A's) epoch-1
		// `0xFF02` leaf — the exact `(group, epoch, component)` the send-side
		// ledger otherwise "remembers" lazily on first commit. Seed it with
		// this already-derived value so `committingRound`'s first `0x00`/
		// `0x05` round doesn't attempt a second, failing export of the same
		// leaf.
		sendCrossPSKLedger[groupA.classical.context.epoch] = crossPSK

		let welcome = try MLS.RFC9420.Welcome(mlsEncoded: tBytes)
		let groupB = try APQGroup.joinClassicalOnly(
			welcome: welcome, credentials: identity.classicalJoinCredentials,
			crossPSK: crossPSK, provider: classicalProvider, codepoints: codepoints)
		try TwoPartyRules.ensureTwoParty(groupB.classical)

		recvGroup = groupB
		joinedWelcomeDigest = digest
	}
}
