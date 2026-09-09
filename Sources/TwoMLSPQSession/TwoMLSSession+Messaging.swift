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
	/// First runs a `committingRound` (§4b/§5) — folding an approved peer
	/// Update and/or discharging an owed bind if one is licensed — into a FULL
	/// commit on `sendGroup.classical`, stapling either a bare `0x00` fold or
	/// the `0x05` bind pair, so `encrypt` then protects the app on the
	/// newly-advanced epoch. `didCommit` reports whether that happened;
	/// `committedRemoteClientID` is set only when a fold rode.
	public mutating func prepareToEncrypt() throws -> PrepareResult {
		guard recvGroup != nil, sendGroup != nil else {
			throw TwoMLSError.notEstablished
		}
		let (didCommit, committedRemoteClientID) = try committingRound()
		rewrapSideBand()

		guard var recv = recvGroup else { throw TwoMLSError.notEstablished }
		let (message, _) = try recv.classical.proposeUpdate(
			classicalProvider, signingKey: identity.signingKey, framing: .publicMessage)
		recvGroup = recv

		let proposalBytes = try message.mlsEncoded()
		// `sha256` for the deployed classical suite (curve25519ChaCha), matching
		// the book's fixed sha256 for `proposal_hash`.
		let proposalHash = try classicalProvider.hash(proposalBytes)
		pendingProposal = (
			proposing: identity.clientID, message: proposalBytes, hash: proposalHash
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
			signingKey: identity.signingKey)
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

		let didApplyRemoteCommit = try handleStaple(staple)

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
			didApplyRemoteCommit: didApplyRemoteCommit,
			queuedProposal: QueuedProposal(digest: digest, proposing: proposing))
	}

	/// `0x01` welcome → join Group_B if this staple hasn't been joined yet
	/// (idempotent otherwise, matching the reference's welcome dedup); `0x00`
	/// mlsMessage → the fold-only commit apply arm (§11 checkpoint 3); `0x05`
	/// apqPrivateMessage → `applyBind`. Returns whether a remote commit was
	/// actually applied (`false` for a welcome, or an idempotent skip of a
	/// commit already applied off an earlier frame).
	@discardableResult
	private mutating func handleStaple(_ staple: Data) throws -> Bool {
		guard let tag = staple.first else { throw TwoMLSError.truncatedSection }
		switch Frames.stapleKind(tag) {
		case .welcome:
			try joinGroupBIfNeeded(fromStaple: staple)
			return false
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
		withDeployedWireWidth {
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
