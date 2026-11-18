import Foundation
import MLSCodec
import MLSCrypto
import MLSProfileRFC9420
import Testing
import TwoMLSPQCrypto

@testable import TwoMLSPQSession

/// RFC 9420 §7.3: a sender checks every KeyPackage it adds against the
/// host-supplied current time, and only creation commits add one.
@Suite struct KeyPackageLifetimeTests {
	@available(iOS 26, macOS 26, *)
	private static var nowSeconds: UInt64 {
		UInt64(SessionTestSupport.now.timeIntervalSince1970)
	}

	@available(iOS 26, macOS 26, *)
	private static func principals() throws -> (alice: Principal, bob: Principal) {
		(try SessionTestSupport.principal("alice"), try SessionTestSupport.principal("bob"))
	}

	/// `proposal` framed and verified from `session`'s own classical receive
	/// leaf, and stored: the by-reference shape a commit consumes.
	@available(iOS 26, macOS 26, *)
	private static func storedProposal(
		_ proposal: MLS.RFC9420.Proposal, from session: TwoMLSSession
	) throws -> (ref: MLS.HashReference, store: MLS.RFC9420.ProposalStore) {
		let provider = SessionTestSupport.classicalProvider
		let group = try #require(session.recvGroup).classical
		let content = MLS.RFC9420.FramedContent(
			groupID: group.context.groupID, epoch: group.context.epoch,
			sender: .member(group.myLeafIndex), authenticatedData: Data(),
			content: .proposal(proposal))
		let framed = try MLS.RFC9420.protectPublic(
			provider, content: content, groupContext: group.context,
			confirmationTag: nil, signingKey: try session.recvClassicalSigningKey(),
			membershipKey: group.epoch.membershipKey)
		var store = MLS.RFC9420.ProposalStore()
		let ref = try store.insert(
			try group.verifying(provider, proposal: framed), provider)
		return (ref, store)
	}

	enum Half { case classical, pq, both }

	/// The invitation's KeyPackages with the lifetime of `halves` replaced.
	@available(iOS 26, macOS 26, *)
	private static func invitationKeyPackage(
		_ invitation: Invitation, halves: Half = .both, notBefore: UInt64,
		notAfter: UInt64
	) throws -> CombinerKeyPackage {
		let identity = try #require(invitation.identity)
		var result = identity.keyPackage
		if halves != .pq {
			result.classical = try SessionTestSupport.keyPackage(
				identity.keyPackage.classical, notBefore: notBefore,
				notAfter: notAfter, signingKey: identity.signingKey,
				provider: SessionTestSupport.classicalProvider)
		}
		if halves != .classical {
			result.pq = try SessionTestSupport.keyPackage(
				identity.keyPackage.pq, notBefore: notBefore, notAfter: notAfter,
				signingKey: identity.pqSigningKey,
				provider: SessionTestSupport.pqProvider)
		}
		return result
	}

	/// A peer KeyPackage whose `notAfter` is before `now` cannot found a session.
	@available(iOS 26, macOS 26, *)
	@Test(arguments: [Half.classical, .pq])
	func initiateRejectsPeerKeyPackagePastNotAfter(half: Half) throws {
		let now = Self.nowSeconds
		let (alice, bob) = try Self.principals()
		let (invitation, _) = try bob.generateInvitation(lastResort: true)
		let their = try Self.invitationKeyPackage(
			invitation, halves: half, notBefore: 0, notAfter: now - 1)

		#expect(throws: MLS.RFC9420.GroupError.leafNodeLifetimeOutOfRange) {
			try TwoMLSSession.initiate(
				principal: alice, their: their, now: SessionTestSupport.now)
		}
	}

	/// A peer KeyPackage whose `notBefore` is after `now` cannot found a session.
	@available(iOS 26, macOS 26, *)
	@Test(arguments: [Half.classical, .pq])
	func initiateRejectsPeerKeyPackageBeforeNotBefore(half: Half) throws {
		let now = Self.nowSeconds
		let (alice, bob) = try Self.principals()
		let (invitation, _) = try bob.generateInvitation(lastResort: true)
		let their = try Self.invitationKeyPackage(
			invitation, halves: half, notBefore: now + 1, notAfter: .max)

		#expect(throws: MLS.RFC9420.GroupError.leafNodeLifetimeOutOfRange) {
			try TwoMLSSession.initiate(
				principal: alice, their: their, now: SessionTestSupport.now)
		}
	}

	/// The lifetime bounds are inclusive at whole-second resolution: `now` at
	/// `notAfter` plus a fraction of a second still founds a session.
	@available(iOS 26, macOS 26, *)
	@Test func initiateAcceptsPeerKeyPackageWithinNotAfterSecond() throws {
		let now = Self.nowSeconds
		let (alice, bob) = try Self.principals()
		let (invitation, _) = try bob.generateInvitation(lastResort: true)
		let their = try Self.invitationKeyPackage(
			invitation, notBefore: now, notAfter: now)

		_ = try TwoMLSSession.initiate(
			principal: alice, their: their,
			now: SessionTestSupport.now.addingTimeInterval(0.9))
		#expect(throws: MLS.RFC9420.GroupError.leafNodeLifetimeOutOfRange) {
			try TwoMLSSession.initiate(
				principal: alice, their: their,
				now: SessionTestSupport.now.addingTimeInterval(1))
		}
	}

	/// An expired return KeyPackage is rejected and claims nothing, so the same
	/// invitation still accepts a valid one afterwards.
	@available(iOS 26, macOS 26, *)
	@Test func invitationReceiveRejectsExpiredKeyPackageAndStaysUnclaimed() throws {
		let now = Self.nowSeconds
		let (alice, bob) = try Self.principals()
		var (invitation, _) = try bob.generateInvitation(lastResort: false)
		let stateSeq = invitation.stateSeq
		let initiated = try TwoMLSSession.initiate(
			principal: alice, their: try #require(invitation.combinerKeyPackage),
			now: SessionTestSupport.now)
		let commitment = try initiated.session.bootstrapKPCommitment()
		let aliceKeyPackage = initiated.session.identity.keyPackage.classical
		let expired = try SessionTestSupport.keyPackage(
			aliceKeyPackage, notBefore: 0, notAfter: now - 1,
			signingKey: initiated.session.identity.signingKey,
			provider: SessionTestSupport.classicalProvider)
		let spawnToken = SessionTestSupport.classicalProvider.randomBytes(16)

		#expect(throws: MLS.RFC9420.GroupError.leafNodeLifetimeOutOfRange) {
			try invitation.receive(
				welcome: initiated.welcome, theirClassicalKeyPackage: expired,
				bootstrapKPCommitment: commitment, spawnToken: spawnToken,
				now: SessionTestSupport.now)
		}
		#expect(invitation.combinerKeyPackage != nil)
		#expect(invitation.stateSeq == stateSeq)

		let received = try invitation.receive(
			welcome: initiated.welcome, theirClassicalKeyPackage: aliceKeyPackage,
			bootstrapKPCommitment: commitment, spawnToken: spawnToken,
			now: SessionTestSupport.now)
		#expect(received.session.isEstablished)
	}

	/// An expired bootstrap KeyPackage (KP′) founds no PQ half and leaves the
	/// session's state unchanged.
	@available(iOS 26, macOS 26, *)
	@Test func pqBootstrapRespondRejectsExpiredBootstrapKeyPackage() throws {
		let now = Self.nowSeconds
		let (alice, bob) = try Self.principals()
		var (invitation, _) = try bob.generateInvitation(lastResort: true)
		let initiated = try TwoMLSSession.initiate(
			principal: alice, their: try #require(invitation.combinerKeyPackage),
			now: SessionTestSupport.now)
		let expired = try SessionTestSupport.keyPackage(
			initiated.session.identity.keyPackage.pq, notBefore: 0, notAfter: now - 1,
			signingKey: initiated.session.identity.pqSigningKey,
			provider: SessionTestSupport.pqProvider)
		let wire = try MLS.RFC9420.Message.keyPackage(expired).mlsEncoded()
		var responder = try invitation.receive(
			welcome: initiated.welcome,
			theirClassicalKeyPackage: initiated.session.identity.keyPackage.classical,
			bootstrapKPCommitment: try SessionTestSupport.classicalProvider.hash(wire),
			spawnToken: SessionTestSupport.classicalProvider.randomBytes(16),
			now: SessionTestSupport.now
		).session
		let stateSeq = responder.stateSeq
		#expect(responder.pqInflight == nil)

		#expect(throws: MLS.RFC9420.GroupError.leafNodeLifetimeOutOfRange) {
			try responder.pqBootstrapRespond(
				Frames.encodePQBootstrapKP(wire), now: SessionTestSupport.now)
		}
		#expect(responder.stateSeq == stateSeq)
		#expect(responder.pqInflight == nil)
		#expect(responder.sendGroup?.pq == nil)

		_ = try responder.pqBootstrapRespond(
			Frames.encodePQBootstrapKP(wire),
			now: SessionTestSupport.now.addingTimeInterval(-1))
		#expect(responder.sendGroup?.pq != nil)
	}

	/// `now` maps to whole Unix seconds rounded down; times before 1970 map to
	/// 0, times beyond `UInt64.max` seconds clamp to it, and NaN and ±infinity
	/// clamp the same way instead of trapping.
	@available(iOS 26, macOS 26, *)
	@Test func lifetimeCheckFromDateFloorsAndClamps() throws {
		func seconds(_ interval: TimeInterval) -> MLS.RFC9420.LifetimeCheck {
			.at(Date(timeIntervalSince1970: interval))
		}
		#expect(seconds(1_800_000_000.999) == .at(unixSeconds: 1_800_000_000))
		#expect(seconds(1_800_000_000) == .at(unixSeconds: 1_800_000_000))
		#expect(seconds(0.5) == .at(unixSeconds: 0))
		#expect(seconds(-1) == .at(unixSeconds: 0))
		#expect(seconds(-.infinity) == .at(unixSeconds: 0))
		#expect(seconds(.nan) == .at(unixSeconds: 0))
		#expect(seconds(0x1p63) == .at(unixSeconds: 1 << 63))
		#expect(seconds(0x1p64) == .at(unixSeconds: .max))
		#expect(seconds(.infinity) == .at(unixSeconds: .max))
	}

	/// A non-creation commit skips the lifetime check only while it adds no
	/// KeyPackage: an inline Add is refused.
	@available(iOS 26, macOS 26, *)
	@Test func lifetimeCheckWithoutAddsRefusesInlineAdd() throws {
		let (_, bob) = try SessionTestSupport.establishedAndExchanged()
		let add = MLS.RFC9420.Proposal.add(bob.identity.keyPackage.classical)

		#expect(throws: TwoMLSError.unexpectedProposal) {
			try TwoPartyRules.lifetimeCheckWithoutAdds([.proposal(add)])
		}
		#expect(throws: TwoMLSError.unexpectedProposal) {
			try TwoPartyRules.lifetimeCheckWithoutAdds([
				.proposal(.remove(MLS.LeafIndex(value: 0))), .proposal(add),
			])
		}
		#expect(throws: TwoMLSError.unexpectedProposal) {
			try TwoPartyRules.lifetimeCheckWithoutAdds([
				.proposal(add), .proposal(.remove(MLS.LeafIndex(value: 0))),
			])
		}
	}

	/// The same holds for an Add the commit references from the proposal store.
	@available(iOS 26, macOS 26, *)
	@Test func lifetimeCheckWithoutAddsRefusesAddByReference() throws {
		let (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let add = MLS.RFC9420.Proposal.add(bob.identity.keyPackage.classical)
		let (ref, store) = try Self.storedProposal(add, from: alice)

		#expect(throws: TwoMLSError.unexpectedProposal) {
			try TwoPartyRules.lifetimeCheckWithoutAdds(
				[.reference(ref)], proposalStore: store)
		}
	}

	/// Commits with no Add skip the check, which is vacuous for them.
	@available(iOS 26, macOS 26, *)
	@Test func lifetimeCheckWithoutAddsAllowsCommitsWithoutAdds() throws {
		let (alice, _) = try SessionTestSupport.establishedAndExchanged()
		let remove = MLS.RFC9420.Proposal.remove(MLS.LeafIndex(value: 0))
		let (ref, store) = try Self.storedProposal(remove, from: alice)

		#expect(try TwoPartyRules.lifetimeCheckWithoutAdds([]) == .unchecked)
		#expect(
			try TwoPartyRules.lifetimeCheckWithoutAdds(
				[.proposal(remove), .reference(ref)], proposalStore: store)
				== .unchecked)
	}
}
