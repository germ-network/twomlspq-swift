import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes
import Testing
import TwoMLSPQCrypto

@testable import TwoMLSPQSession

/// `canonicalize` (`TwoMLSSession+ClassicalCommit.swift`) now calls
/// `PartySequence.commit` only for a credential genuinely NEW to the
/// sequence — one absent from both `history` and `pinned` — rather than for
/// every `.credentialReplaced` effect unconditionally. `PartySequence.
/// commit` stays strict (a known-but-not-current id is still a rollback
/// candidate from ITS OWN point of view), so a leaf landing on an id the
/// sequence already knows (a legitimate catch-up — a same-id key refresh
/// while the party's canonical head has moved on elsewhere, or a
/// fast-forward to a non-head history element) must never reach `commit`
/// at all, or it would incorrectly throw `.credentialRollback`.
@Suite struct CanonicalizeKnownCredentialTests {
	/// Hand-builds a SOLO `includePath: true` commit on `committer`'s OWN
	/// `sendGroup.classical` moving the committer's own leaf's presentation
	/// to `(newID, newKey)` — no proposals, no license needed (unlike the
	/// real `committingRound`'s own-leaf catch-up, this bypasses its
	/// evidence-gating entirely, standing in for whatever REAL sequence of
	/// events could otherwise produce this exact commit shape). Applies the
	/// commit to the committer's OWN group (so its later frames stay
	/// consistent) and returns the wire bytes.
	@available(iOS 26, macOS 26, *)
	private func handBuildSoloClassicalMove(
		committer: inout TwoMLSSession, newID: Data,
		newKey: (signingKey: MLS.SignatureSecretKey, signatureKey: MLS.SignaturePublicKey)
	) throws -> Data {
		let provider = SessionTestSupport.classicalProvider
		guard var send = committer.sendGroup else {
			throw TwoMLSError.notEstablished
		}
		let currentKey = try committer.sendClassicalSigningKey()
		let sign = MLS.RFC9420.signingClosure(
			provider, current: currentKey, new: newKey.signingKey)
		let newIdentity = MLS.RFC9420.NewSigningIdentity(
			credential: .basic(identity: newID), signatureKey: newKey.signatureKey)
		let transition = try send.classical.committing(
			provider, proposals: [], sign: sign, randomness: try .generate(provider),
			includePath: true, framing: .publicMessage, newIdentity: newIdentity)
		return try withTransitionHandoff(transition) { adopted, sent in
			let commitBytes = try sent.message.mlsEncoded()
			let advanced = try sent.takePending().apply(onto: adopted)
			send.classical = advanced.group
			committer.sendGroup = send
			try committer.leafKeys.sendClassical.stage(
				LeafKey(
					signingKey: newKey.signingKey,
					signatureKey: newKey.signatureKey),
				for: newID)
			try committer.leafKeys.sendClassical.promoted(
				presenting: newKey.signatureKey, id: newID)
			return commitBytes
		}
	}

	/// Delivers `commitBytes` (a bare `0x00` mlsMessage staple) directly to
	/// `alice`'s fold-only apply arm — the exact internal entry point a
	/// real `0x00` message frame's staple dispatches to
	/// (`TwoMLSSession+Messaging.swift`'s `handleStaple`), skipping the
	/// surrounding frame/app-section machinery this test has no need to
	/// forge. This is what exercises `canonicalize`.
	@available(iOS 26, macOS 26, *)
	private func deliver(_ commitBytes: Data, to alice: inout TwoMLSSession) throws
		-> StapleApplyResult
	{
		try alice.applyFoldCommit(commitBytes)
	}

	/// The shared fixture: alice/bob established, bob's classical history
	/// seeded (directly, mirroring `ReciprocalCatchUpConformanceTests`' own
	/// technique) to `[id0, s1, s2]` with `s2` current — WITHOUT touching
	/// bob's actual classical leaf (still presenting `id0` for real), so a
	/// hand-built move off `id0` is a genuine fast-forward/refresh over
	/// real, book-shaped history.
	@available(iOS 26, macOS 26, *)
	private func seededFixture() throws -> (
		alice: TwoMLSSession, bob: TwoMLSSession, id0: Data, s1: Data, s2: Data
	) {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged(
			alice: "canon-alice-\(UUID())", bob: "canon-bob-\(UUID())")
		let id0 = bob.identity.clientID
		let s1 = Data("canon-s1-\(UUID())".utf8)
		let s2 = Data("canon-s2-\(UUID())".utf8)
		try alice.auth.theirs.commit(s1)
		try alice.auth.theirs.commit(s2)
		try bob.auth.mine.commit(s1)
		try bob.auth.mine.commit(s2)
		return (alice, bob, id0, s1, s2)
	}

	/// (a) A same-id (`id0`) fresh-key refresh, while `theirs.current` has
	/// moved on to `s2` elsewhere: accepted, canonicalizes nothing (`id0`
	/// stays out of the caller's view — `history`/`current` unchanged).
	/// Mutation: reverting the guard (calling `commit` unconditionally)
	/// makes this throw `.credentialRollback` instead.
	@available(iOS 26, macOS 26, *)
	@Test func sameIDKeyRefreshWhileCurrentIsAheadIsAcceptedAndCanonicalizesNothing() throws {
		var fixture = try seededFixture()
		let (freshSigningKey, freshSignatureKey) = try TwoMLSIdentity.mintSignatureKeypair()
		let commitBytes = try handBuildSoloClassicalMove(
			committer: &fixture.bob, newID: fixture.id0,
			newKey: (freshSigningKey, freshSignatureKey))

		let historyBefore = fixture.alice.auth.theirs.history
		let result = try deliver(commitBytes, to: &fixture.alice)
		#expect(result.applied)
		// D3: a same-id move (a key refresh only) surfaces no `newSender` —
		// only an id change does.
		#expect(result.newSender == nil)
		#expect(
			fixture.alice.auth.theirs.history == historyBefore,
			"nothing new was canonicalized")
		#expect(fixture.alice.auth.theirs.current == fixture.s2)
	}

	/// (b) A fast-forward from `id0` straight to `s1` — an already-
	/// canonical, non-head history id: accepted, canonicalizes nothing (the
	/// caller's `history`/`current` stay exactly as they were; only the
	/// LEAF that moved is now presenting `s1`). Mutation: reverting the
	/// guard makes this throw `.credentialRollback` too (the pre-fix bug:
	/// `commit` sees `s1 ∈ history`, `s1 != current`, and treats a
	/// legitimate partial catch-up as a rollback).
	@available(iOS 26, macOS 26, *)
	@Test func fastForwardToANonHeadHistoryIDIsAcceptedAndCanonicalizesNothing() throws {
		var fixture = try seededFixture()
		let (freshSigningKey, freshSignatureKey) = try TwoMLSIdentity.mintSignatureKeypair()
		let commitBytes = try handBuildSoloClassicalMove(
			committer: &fixture.bob, newID: fixture.s1,
			newKey: (freshSigningKey, freshSignatureKey))

		let historyBefore = fixture.alice.auth.theirs.history
		let result = try deliver(commitBytes, to: &fixture.alice)
		#expect(result.applied)
		#expect(result.newSender == fixture.s1)
		#expect(
			fixture.alice.auth.theirs.history == historyBefore,
			"nothing new was canonicalized")
		#expect(fixture.alice.auth.theirs.current == fixture.s2)
	}

	/// Negative control: a move to an id `theirs` has NEVER heard of (not
	/// in `history`, `pinned`, or `authorizedNext`) is still rejected —
	/// `adjudicate`'s own successor check runs BEFORE `canonicalize` ever
	/// gets a chance to skip anything, so the guard added here never masks
	/// a genuine rollback/forgery. Proves the guard is exactly "already
	/// known," not "anything goes."
	@available(iOS 26, macOS 26, *)
	@Test func moveToAnUnknownIDIsStillRejected() throws {
		var fixture = try seededFixture()
		let (freshSigningKey, freshSignatureKey) = try TwoMLSIdentity.mintSignatureKeypair()
		let unknownID = Data("canon-never-authorized-\(UUID())".utf8)
		let commitBytes = try handBuildSoloClassicalMove(
			committer: &fixture.bob, newID: unknownID,
			newKey: (freshSigningKey, freshSignatureKey))

		#expect(throws: TwoMLSError.invalidSuccession) {
			try deliver(commitBytes, to: &fixture.alice)
		}
		#expect(!fixture.alice.auth.theirs.history.contains(unknownID))
	}

	// MARK: - (c) A pinned, history-evicted id

	/// (c) A same-id refresh on a credential a live PQ leaf still presents,
	/// evicted from `theirs.history` (rule 4's pin): 8 seeded commits (not
	/// `seededFixture`'s 2) push id0 out of the window, then
	/// `alice.prepareToEncrypt()` — a routine round, nothing about alice's
	/// own leaf changes — recomputes `pinned` at the choke point from
	/// what bob's live PQ leaves still actually present (id0, untouched).
	/// Accepted, canonicalizes nothing. Mutation: dropping the `pinned`
	/// clause of the `theirs` guard makes this throw `.credentialRollback`
	/// (id0 absent from `history`, and the guard would then see only that).
	@available(iOS 26, macOS 26, *)
	@Test func sameIDKeyRefreshOnAPinnedEvictedIDIsAcceptedAndCanonicalizesNothing() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged(
			alice: "canon-pin-alice-\(UUID())", bob: "canon-pin-bob-\(UUID())")
		let id0 = bob.identity.clientID
		for step in 1...8 {
			let stepID = Data("canon-pin-step\(step)-\(UUID())".utf8)
			try alice.auth.theirs.commit(stepID)
			try bob.auth.mine.commit(stepID)
		}
		#expect(!alice.auth.theirs.history.contains(id0))
		_ = try alice.prepareToEncrypt()
		#expect(
			alice.auth.theirs.pinned.contains(id0),
			"bob's live PQ leaves still present id0, untouched")

		let (freshSigningKey, freshSignatureKey) = try TwoMLSIdentity.mintSignatureKeypair()
		let commitBytes = try handBuildSoloClassicalMove(
			committer: &bob, newID: id0, newKey: (freshSigningKey, freshSignatureKey))

		let historyBefore = alice.auth.theirs.history
		let result = try deliver(commitBytes, to: &alice)
		#expect(result.applied)
		// D3: a same-id move surfaces no `newSender`.
		#expect(result.newSender == nil)
		#expect(
			alice.auth.theirs.history == historyBefore, "nothing new was canonicalized")
	}

	/// Hand-builds a validly-framed Update proposal for `mover`'s own leaf
	/// within `committer`'s send-classical group — the leaf `mover` does
	/// not control commits for — signed under `mover`'s CURRENT key for
	/// the enclosing proposal's framing and the NEW key for the leaf's own
	/// RFC 9420 section 7.3 signature (mirrors
	/// `UpdateApprovalLeafValidationTests.forgedUpdate`'s technique, but
	/// legitimately — no mutation — and folded straight into a real commit
	/// rather than left as a bare proposal). Applies the resulting commit
	/// to the committer's OWN group and returns the wire bytes. Also
	/// stages the raw proposal onto `mover.stagedUpdates` — the local
	/// record `rebuildStagedProposalStore` re-derives from when `mover`
	/// later applies the fold that references it by hash, exactly as a
	/// real `prepareToEncrypt(rotating:)` offer would have left behind.
	/// Standing in for whatever real approval/fold sequence could
	/// otherwise produce this exact commit shape — same rationale as
	/// `handBuildSoloClassicalMove` above.
	@available(iOS 26, macOS 26, *)
	private func handBuildFoldedOwnLeafMove(
		committer: inout TwoMLSSession, mover: inout TwoMLSSession, newID: Data,
		newKey: (signingKey: MLS.SignatureSecretKey, signatureKey: MLS.SignaturePublicKey)
	) throws -> Data {
		let provider = SessionTestSupport.classicalProvider
		guard var send = committer.sendGroup else {
			throw TwoMLSError.notEstablished
		}
		guard var moverRecv = mover.recvGroup else {
			throw TwoMLSError.notEstablished
		}
		// The real `Group.proposeUpdate` API, not a hand-crafted
		// `FramedContent`: it mints its own fresh HPKE leaf key pair and
		// records the secret half on `moverRecv.classical`'s own pending-
		// update bookkeeping (`memberships[_].pendingUpdate`) — the exact
		// mechanism `apply(onto:)` later reads to decrypt the committer's
		// path once this same Update is folded and delivered back. Hand-
		// building the `LeafNode`/`FramedContent` directly (as
		// `handBuildSoloClassicalMove` does for a SELF path move) would
		// leave that secret nowhere `mover`'s own session could ever
		// recover it.
		let sign = MLS.RFC9420.signingClosure(
			provider, current: try mover.recvClassicalSigningKey(),
			new: newKey.signingKey)
		let newIdentity = MLS.RFC9420.NewSigningIdentity(
			credential: .basic(identity: newID), signatureKey: newKey.signatureKey)
		let (proposalMessage, _) = try moverRecv.classical.proposeUpdate(
			provider, sign: sign, framing: .publicMessage, newIdentity: newIdentity)
		mover.recvGroup = moverRecv
		// This session's OWN parallel key bookkeeping (`LeafKeys.swift`,
		// separate from swift-mls's own `pendingUpdate`) also needs the
		// fresh key staged, so `applyFoldCommit`'s `updateRecvClassicalKeys`
		// can promote it once this credential lands — mirrors
		// `handBuildSoloClassicalMove`'s `stage`/`promoted` pair on the
		// SEND side above.
		try mover.leafKeys.recvClassical.stage(
			LeafKey(signingKey: newKey.signingKey, signatureKey: newKey.signatureKey),
			for: newID)
		guard case .publicMessage(let proposalPub) = proposalMessage else {
			throw TwoMLSError.malformedSideBandMessage
		}
		let verified = try send.classical.verifying(provider, proposal: proposalPub)
		var proposalStore = MLS.RFC9420.ProposalStore()
		let ref = try proposalStore.insert(verified, provider)
		mover.stagedUpdates.append(
			(digest: provider.randomBytes(8), message: try proposalMessage.mlsEncoded())
		)

		let currentKey = try committer.sendClassicalSigningKey()
		let transition = try send.classical.committing(
			provider, proposals: [.reference(ref)], proposalStore: proposalStore,
			signingKey: currentKey, randomness: try .generate(provider),
			includePath: true, framing: .publicMessage)
		return try withTransitionHandoff(transition) { adopted, sent in
			let commitBytes = try sent.message.mlsEncoded()
			let advanced = try sent.takePending().apply(onto: adopted)
			send.classical = advanced.group
			committer.sendGroup = send
			return commitBytes
		}
	}

	/// The `mine`-arm mirror of the test above: ALICE's own leaf, in her
	/// recv-classical group (bob commits it), moves to a same,
	/// already-known id — pinned, evicted from her OWN history — via a
	/// commit bob folds and she then applies. Accepted, canonicalizes
	/// nothing. Mutation: dropping the `pinned` clause of the `mine` guard
	/// makes this throw `.credentialRollback`.
	@available(iOS 26, macOS 26, *)
	@Test func ownSameIDKeyRefreshOnAPinnedEvictedIDIsAcceptedAndCanonicalizesNothing() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged(
			alice: "canon-pin-mine-alice-\(UUID())", bob: "canon-pin-mine-bob-\(UUID())"
		)
		let id0 = alice.identity.clientID
		for step in 1...8 {
			let stepID = Data("canon-pin-mine-step\(step)-\(UUID())".utf8)
			try alice.auth.mine.commit(stepID)
			try bob.auth.theirs.commit(stepID)
		}
		#expect(!alice.auth.mine.history.contains(id0))
		// Pin directly rather than through a routine `prepareToEncrypt()`
		// round (as the `theirs` mirror above does): alice's own recv-
		// classical leaf still genuinely presents id0 while
		// `auth.mine.current` has moved on to the seeded step8, so a
		// routine round would itself trigger the (unrelated) implicit
		// recv-leaf catch-up arm — the auto-recompute machinery itself is
		// already proven by the `theirs` case above and by
		// `ReciprocalCatchUpConformanceTests.testRule4Pin`; this test's
		// job is only the guard.
		alice.auth.mine.pin(id0)
		#expect(alice.auth.mine.pinned.contains(id0))

		let (freshSigningKey, freshSignatureKey) = try TwoMLSIdentity.mintSignatureKeypair()
		let commitBytes = try handBuildFoldedOwnLeafMove(
			committer: &bob, mover: &alice, newID: id0,
			newKey: (freshSigningKey, freshSignatureKey))

		let historyBefore = alice.auth.mine.history
		let result = try alice.applyFoldCommit(commitBytes)
		#expect(result.applied)
		// D3: a same-id move surfaces no `ownCredentialCanonicalized`.
		#expect(!result.ownCredentialCanonicalized)
		#expect(
			alice.auth.mine.history == historyBefore, "nothing new was canonicalized")
	}
}
