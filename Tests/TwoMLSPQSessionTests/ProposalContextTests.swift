import Crypto
import Foundation
import Testing

@testable import TwoMLSPQSession

/// `TwoMLSSession.proposalContext()` / `QueuedProposal.context` — the
/// proposal-context digests a host binds proposals to, mirroring the
/// reference implementation's `proposal_context()`. The oracle below
/// (`sha256`, called directly via `Crypto` rather than through
/// `classicalProvider.hash`) pins WHICH group each accessor actually
/// hashes — `proposalContext()` the recv group, `QueuedProposal.context`
/// the send group — and that the digest is the raw 32-byte SHA-256 output
/// over the group id alone, with no added type/tag byte.
@Suite struct ProposalContextTests {
	private func sha256(_ data: Data) -> Data {
		Data(SHA256.hash(data: data))
	}

	// MARK: - Established pair, first exchange

	/// The initiator's `proposalContext()` is `nil` before it has joined the
	/// acceptor's group and non-nil after; the acceptor's is non-nil at
	/// birth. In both directions, the sender's `proposalContext()` equals
	/// the receiver's `queuedProposal.context` for that frame, and both
	/// equal the independent SHA-256 oracle over the SENDER's own recv-group
	/// classical group id.
	@available(iOS 26, macOS 26, *)
	@Test func proposalContextEqualitiesBothDirections() throws {
		var (alice, bob, _, _, _, _) = try SessionTestSupport.established()

		#expect(alice.proposalContext() == nil)
		let bobContextAtBirth = try #require(bob.proposalContext())

		// The guard the oracle below relies on: Group_A and Group_B are
		// genuinely different classical group ids, so a send/recv swap on
		// either accessor would actually change the digest, not coincide.
		let groupAID = try #require(bob.recvGroup?.classical.context.groupID)
		let groupBID = try #require(bob.sendGroup?.classical.context.groupID)
		#expect(groupAID != groupBID)
		#expect(bobContextAtBirth == sha256(groupAID))

		// bob -> alice: bob's context (Group_A, his recv group) is what
		// alice's queued proposal carries once she decrypts it — the same
		// frame that joins her.
		_ = try bob.prepareToEncrypt()
		let bobFrame = try bob.encrypt(Data("bob-hello".utf8)).frame
		let bobDecrypted = try alice.processIncomingDecrypted(bobFrame)

		#expect(alice.proposalContext() != nil)
		#expect(bobContextAtBirth == bobDecrypted.queuedProposal.context)
		#expect(bobDecrypted.queuedProposal.context.count == 32)
		#expect(
			bobDecrypted.queuedProposal.context != bobDecrypted.queuedProposal.digest)

		// alice -> bob: alice's context (Group_B, her recv group once
		// joined) is what bob's queued proposal carries once he decrypts it.
		_ = try alice.prepareToEncrypt()
		let aliceFrame = try alice.encrypt(Data("alice-hello".utf8)).frame
		let aliceDecrypted = try bob.processIncomingDecrypted(aliceFrame)

		let aliceContext = try #require(alice.proposalContext())
		#expect(aliceContext == aliceDecrypted.queuedProposal.context)
		// The independent oracle, sender side, in the OTHER direction —
		// pins alice's own accessor against Group_B specifically, not just
		// against bob's already-pinned Group_A.
		#expect(aliceContext == sha256(groupBID))
		#expect(
			aliceDecrypted.queuedProposal.context
				!= aliceDecrypted.queuedProposal.digest)
	}

	/// Stable across a routine classical fold (an epoch change) and across
	/// `restore` — group ids never move once minted, so neither accessor
	/// should either.
	@available(iOS 26, macOS 26, *)
	@Test func proposalContextStableAcrossFoldAndRestore() throws {
		var (alice, bob, _, _, _, _) = try SessionTestSupport.established()
		_ = try bob.prepareToEncrypt()
		let bobHello = try bob.encrypt(Data("bob-hello".utf8)).frame
		_ = try alice.processIncomingDecrypted(bobHello)

		let aliceContextBefore = try #require(alice.proposalContext())
		let bobContextBefore = try #require(bob.proposalContext())
		let epochBefore = alice.sendGroup?.classical.context.epoch

		// A routine classical fold: bob offers, alice approves and folds it
		// into her next commit.
		_ = try bob.prepareToEncrypt()
		let offerFrame = try bob.encrypt(Data("offer".utf8)).frame
		let offerDecrypted = try alice.processIncomingDecrypted(offerFrame)
		_ = try alice.queueProposal(digest: offerDecrypted.queuedProposal.digest)

		let prepared = try alice.prepareToEncrypt()
		#expect(prepared.didCommit)
		let foldFrame = try alice.encrypt(Data("folded".utf8)).frame
		_ = try bob.processIncomingDecrypted(foldFrame)

		#expect(alice.sendGroup?.classical.context.epoch != epochBefore)
		#expect(alice.proposalContext() == aliceContextBefore)
		#expect(bob.proposalContext() == bobContextBefore)

		let checkpoint = try alice.makeSessionArchive(kind: .checkpoint)
		let restoredAlice = try TwoMLSSession.restore(
			core: nil, checkpoint: checkpoint,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		#expect(restoredAlice.proposalContext() == aliceContextBefore)
	}

	// MARK: - Born-dedicated

	/// The acceptor's recv group is Group_A, joined under the INVITATION
	/// identity (not the dedicated principal D's own Group_B) — its
	/// `proposalContext()` must name Group_A specifically.
	@available(iOS 26, macOS 26, *)
	@Test func bornDedicatedAcceptorProposalContextIsGroupANotGroupB() throws {
		let (_, bob, _, _, _) = try SessionTestSupport.establishedDedicated()

		let groupAID = try #require(bob.recvGroup?.classical.context.groupID)
		let groupBID = try #require(bob.sendGroup?.classical.context.groupID)
		#expect(groupAID != groupBID)

		let bobContext = try #require(bob.proposalContext())
		#expect(bobContext == sha256(groupAID))
		#expect(bobContext != sha256(groupBID))
	}

	/// The born-dedicated initiator's `proposalContext()` stays `nil` not
	/// only at birth but also across an un-approved `0x0B` pause — only the
	/// APPROVED re-feed actually joins Group_B and gives it a recv group.
	@available(iOS 26, macOS 26, *)
	@Test func bornDedicatedInitiatorProposalContextNilUntilApprovedJoin() throws {
		var (alice, bob, _, _, dedicatedClientID) =
			try SessionTestSupport.establishedDedicated()
		#expect(alice.proposalContext() == nil)

		let envelope = Data("fake-signed-handoff".utf8)
		_ = try bob.installEstablishmentEnvelope(envelope)
		let standaloneRaw = try bob.standaloneWelcome()
		let standalone = try #require(standaloneRaw)
		let openedRaw = try alice.openIncoming(standalone)
		let opened = try #require(openedRaw)

		guard case .pendingEstablishment = try alice.processIncoming(opened.frame) else {
			Issue.record("expected a pause on the un-approved 0x0B")
			return
		}
		#expect(alice.proposalContext() == nil)

		let (envelopeBytes, welcomeBytes) = try Frames.decodeEstablishmentHandoff(
			bob.currentStaple)
		let envelopeDigest = try SessionTestSupport.classicalProvider.hash(envelopeBytes)
		let welcomeDigest = try SessionTestSupport.classicalProvider.hash(welcomeBytes)
		guard
			case .joined = try alice.processIncomingApproved(
				opened.frame, approvedEnvelopeDigest: envelopeDigest,
				approvedWelcomeDigest: welcomeDigest,
				expectedCreator: dedicatedClientID)
		else {
			Issue.record("expected .joined on the approved re-feed")
			return
		}
		#expect(alice.proposalContext() != nil)
	}
}
