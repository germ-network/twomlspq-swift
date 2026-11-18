import Foundation
import MLSCodec
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes
import Testing
import TwoMLSPQCrypto

@testable import TwoMLSPQSession

/// Raw groups for the helper-level checks.
@available(iOS 26, macOS 26, *)
enum RestoreInvariantFixtures {
	static let binding = Data("relationship-digest".utf8)

	static func classical(
		_ founder: TwoMLSIdentity, adding others: [TwoMLSIdentity],
		extensions: [MLS.RFC9420.Extension] = []
	) throws -> MLS.RFC9420.Group {
		let provider = SessionTestSupport.classicalProvider
		return try group(
			provider, founderLeaf: founder.keyPackage.classical.leafNode,
			founderSecret: founder.classicalLeafSecretKey,
			signingKey: founder.signingKey,
			adding: others.map { $0.keyPackage.classical }, extensions: extensions)
	}

	static func pq(
		_ founder: TwoMLSIdentity, adding others: [TwoMLSIdentity],
		extensions: [MLS.RFC9420.Extension] = []
	) throws -> MLS.RFC9420.Group {
		let provider = SessionTestSupport.pqProvider
		return try group(
			provider, founderLeaf: founder.keyPackage.pq.leafNode,
			founderSecret: founder.pqLeafSecretKey, signingKey: founder.pqSigningKey,
			adding: others.map { $0.keyPackage.pq }, extensions: extensions)
	}

	private static func group(
		_ provider: any MLS.CipherSuiteProvider, founderLeaf: MLS.RFC9420.LeafNode,
		founderSecret: MLS.HpkeSecretKey, signingKey: MLS.SignatureSecretKey,
		adding others: [MLS.RFC9420.KeyPackage], extensions: [MLS.RFC9420.Extension]
	) throws -> MLS.RFC9420.Group {
		let epoch0 = try MLS.RFC9420.Group.create(
			provider, groupID: provider.randomBytes(provider.hashSize),
			leafNode: founderLeaf, leafSecretKey: founderSecret, extensions: extensions,
			epochSecret: SecretBytes(randomByteCount: provider.hashSize))
		let transition = try epoch0.committing(
			provider, proposals: others.map { .proposal(.add($0)) },
			signingKey: signingKey, randomness: try .generate(provider))
		let adopted = transition.group
		return try transition.takeOutput().takePending().apply(onto: adopted).group
	}

	static func bindingExtension(_ data: Data = binding) throws -> MLS.RFC9420.Extension {
		try AppBinding(data: data).asExtension()
	}

	/// An acceptor session over the two identities, bound to `binding`.
	static func boundAcceptor(
		alice: TwoMLSIdentity, bob: TwoMLSIdentity, binding: Data?
	) throws -> TwoMLSSession {
		let initiated = try TwoMLSSession.initiate(
			identity: alice, their: bob.keyPackage,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider, appBinding: binding)
		return try TwoMLSSession.receive(
			identity: bob, welcome: initiated.welcome,
			theirClassicalKeyPackage: alice.keyPackage.classical,
			bootstrapKPCommitment: try initiated.session.bootstrapKPCommitment(),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider, expectedAppBinding: binding
		).session
	}
}

/// Restore and migration mint refuse state no live path writes, and rebuild
/// what they can re-derive instead of trusting it.
@Suite struct RestoredGroupInvariantTests {
	@available(iOS 26, macOS 26, *)
	private typealias Fixtures = RestoreInvariantFixtures

	@available(iOS 26, macOS 26, *)
	private func check(
		sendClassical: MLS.RFC9420.Group, sendPQ: MLS.RFC9420.Group? = nil,
		recvClassical: MLS.RFC9420.Group? = nil, recvPQ: MLS.RFC9420.Group? = nil
	) throws {
		try TwoMLSSession.validateRestoredGroups(
			sendClassical: sendClassical, sendPQ: sendPQ, recvClassical: recvClassical,
			recvPQ: recvPQ)
	}

	@available(iOS 26, macOS 26, *)
	private func identities() throws -> (TwoMLSIdentity, TwoMLSIdentity) {
		(
			try SessionTestSupport.identity("grp-alice"),
			try SessionTestSupport.identity("grp-bob")
		)
	}

	/// A tree with a third member is refused, as every live ingress refuses it.
	@available(iOS 26, macOS 26, *)
	@Test func rejectsTreeWithThirdMember() throws {
		let (alice, bob) = try identities()
		let carol = try SessionTestSupport.identity("grp-carol")
		let pair = try Fixtures.classical(alice, adding: [bob])
		#expect(throws: Never.self) { try check(sendClassical: pair) }

		let trio = try Fixtures.classical(alice, adding: [bob, carol])
		#expect(throws: TwoMLSError.archiveInvalid) { try check(sendClassical: trio) }
		#expect(throws: TwoMLSError.archiveInvalid) {
			try check(sendClassical: pair, recvClassical: trio)
		}
		let pqTrio = try Fixtures.pq(alice, adding: [bob, carol])
		#expect(throws: TwoMLSError.archiveInvalid) {
			try check(sendClassical: pair, sendPQ: pqTrio)
		}
		#expect(throws: TwoMLSError.archiveInvalid) {
			try check(sendClassical: pair, recvClassical: pair, recvPQ: pqTrio)
		}
	}

	/// A PQ half that carries an AppBinding is refused.
	@available(iOS 26, macOS 26, *)
	@Test func rejectsBoundPQHalf() throws {
		let (alice, bob) = try identities()
		let pair = try Fixtures.classical(alice, adding: [bob])
		let bound = try Fixtures.pq(
			alice, adding: [bob], extensions: [try Fixtures.bindingExtension()])
		#expect(throws: TwoMLSError.archiveInvalid) {
			try check(sendClassical: pair, sendPQ: bound)
		}
		#expect(throws: TwoMLSError.archiveInvalid) {
			try check(sendClassical: pair, recvClassical: pair, recvPQ: bound)
		}
		let clean = try Fixtures.pq(alice, adding: [bob])
		#expect(throws: Never.self) {
			try check(
				sendClassical: pair, sendPQ: clean, recvClassical: pair,
				recvPQ: clean)
		}
	}

	/// A PQ half that records a profile is refused.
	@available(iOS 26, macOS 26, *)
	@Test func rejectsPQHalfWithRecordedProfile() throws {
		let (alice, bob) = try identities()
		let pair = try Fixtures.classical(alice, adding: [bob])
		let profiled = try Fixtures.pq(
			alice, adding: [bob], extensions: SessionProfile.correct.recordExtensions)
		#expect(throws: TwoMLSError.archiveInvalid) {
			try check(sendClassical: pair, sendPQ: profiled)
		}
		#expect(throws: TwoMLSError.archiveInvalid) {
			try check(sendClassical: pair, recvClassical: pair, recvPQ: profiled)
		}
	}

	/// Classical halves that disagree on the AppBinding are refused.
	@available(iOS 26, macOS 26, *)
	@Test func rejectsClassicalHalvesWithDifferentAppBindings() throws {
		let (alice, bob) = try identities()
		let bound = try Fixtures.classical(
			alice, adding: [bob], extensions: [try Fixtures.bindingExtension()])
		let boundAgain = try Fixtures.classical(
			alice, adding: [bob], extensions: [try Fixtures.bindingExtension()])
		let other = try Fixtures.classical(
			alice, adding: [bob],
			extensions: [try Fixtures.bindingExtension(Data("other".utf8))])
		let unbound = try Fixtures.classical(alice, adding: [bob])
		#expect(throws: Never.self) {
			try check(sendClassical: bound, recvClassical: boundAgain)
		}
		#expect(throws: Never.self) {
			try check(sendClassical: unbound, recvClassical: unbound)
		}
		#expect(throws: TwoMLSError.archiveInvalid) {
			try check(sendClassical: bound, recvClassical: other)
		}
		#expect(throws: TwoMLSError.archiveInvalid) {
			try check(sendClassical: bound, recvClassical: unbound)
		}
		#expect(throws: TwoMLSError.archiveInvalid) {
			try check(sendClassical: unbound, recvClassical: bound)
		}
	}

	/// A classical half whose AppBinding is malformed is refused.
	@available(iOS 26, macOS 26, *)
	@Test func rejectsMalformedAppBinding() throws {
		let (alice, bob) = try identities()
		let malformed = MLS.RFC9420.Extension(
			type: AppBinding.extensionType, data: Data([0xFF]))
		let broken = try Fixtures.classical(alice, adding: [bob], extensions: [malformed])
		#expect(throws: TwoMLSError.archiveInvalid) { try check(sendClassical: broken) }
		let pair = try Fixtures.classical(alice, adding: [bob])
		#expect(throws: TwoMLSError.archiveInvalid) {
			try check(sendClassical: pair, recvClassical: broken)
		}
	}

	/// Classical halves that disagree on the recorded profile are refused.
	@available(iOS 26, macOS 26, *)
	@Test func rejectsClassicalHalvesWithDifferentProfiles() throws {
		let (alice, bob) = try identities()
		let profiled = try Fixtures.classical(
			alice, adding: [bob], extensions: SessionProfile.correct.recordExtensions)
		let plain = try Fixtures.classical(alice, adding: [bob])
		#expect(throws: Never.self) {
			try check(sendClassical: profiled, recvClassical: profiled)
		}
		#expect(throws: TwoMLSError.archiveInvalid) {
			try check(sendClassical: profiled, recvClassical: plain)
		}
		#expect(throws: TwoMLSError.archiveInvalid) {
			try check(sendClassical: plain, recvClassical: profiled)
		}
		let type = try #require(SessionProfile.correct.extensionType)
		let malformed = try Fixtures.classical(
			alice, adding: [bob],
			extensions: [MLS.RFC9420.Extension(type: type, data: Data([1]))])
		#expect(throws: TwoMLSError.archiveInvalid) { try check(sendClassical: malformed) }
		#expect(throws: TwoMLSError.archiveInvalid) {
			try check(sendClassical: plain, recvClassical: malformed)
		}
	}

	@available(iOS 26, macOS 26, *)
	private func swappedRecv(
		binding: Data, from other: Data
	) throws -> (body: SessionArchive, sourceBody: SessionArchive) {
		let alice = try SessionTestSupport.identity("swap-alice")
		let bob = try SessionTestSupport.identity("swap-bob")
		let target = try Fixtures.boundAcceptor(alice: alice, bob: bob, binding: binding)
		let source = try Fixtures.boundAcceptor(alice: alice, bob: bob, binding: other)
		return (
			try target.makeSessionArchive(kind: .checkpoint).decode(
				SessionArchive.self),
			try source.makeSessionArchive(kind: .checkpoint).decode(SessionArchive.self)
		)
	}

	@available(iOS 26, macOS 26, *)
	private func restore(_ body: SessionArchive) throws -> TwoMLSSession {
		try TwoMLSSession.restore(
			core: nil, checkpoint: try SecretArchive(encoding: body),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
	}

	/// Restore runs the group checks: an archive whose recv half is swapped
	/// for an equally bound one restores, and for a differently bound one is
	/// refused.
	@available(iOS 26, macOS 26, *)
	@Test func restoreRejectsMismatchedAppBindings() throws {
		for (other, accepted) in [(Fixtures.binding, true), (Data("other".utf8), false)] {
			var (body, source) = try swappedRecv(binding: Fixtures.binding, from: other)
			body.recvGroup = source.recvGroup
			body.recvClassicalGroupID = source.recvClassicalGroupID
			body.recvPQEpoch = source.recvPQEpoch
			if accepted {
				#expect(throws: Never.self) { try restore(body) }
			} else {
				#expect(throws: TwoMLSError.archiveInvalid) { try restore(body) }
			}
		}
	}

	/// A core-kind mint runs the group checks too, since it gets no trial
	/// restore; the equally bound swap still mints.
	@available(iOS 26, macOS 26, *)
	@Test func coreMintRejectsMismatchedAppBindings() throws {
		let alice = try SessionTestSupport.identity("swap-alice")
		let bob = try SessionTestSupport.identity("swap-bob")
		let migration = SessionMigrationTests()
		let target = try migration.migratedParts(
			try Fixtures.boundAcceptor(
				alice: alice, bob: bob, binding: Fixtures.binding),
			suppliedLeafKeys: true)
		for (other, accepted) in [(Fixtures.binding, true), (Data("other".utf8), false)] {
			var parts = target
			parts.recvGroup = try migration.migratedParts(
				try Fixtures.boundAcceptor(alice: alice, bob: bob, binding: other),
				suppliedLeafKeys: true
			).recvGroup
			let mint = {
				try SessionMigration.mintArchive(
					kind: .core, parts: parts,
					classicalProvider: SessionTestSupport.classicalProvider,
					pqProvider: SessionTestSupport.pqProvider)
			}
			if accepted {
				#expect(throws: Never.self) { try mint() }
			} else {
				#expect(throws: TwoMLSError.archiveInvalid) { try mint() }
			}
		}
	}

	/// Leaf capabilities are not a restore check, because a peer's commit path
	/// leaf is never capability-checked live: a group with a capability-less
	/// leaf passes the restore group check and fails the mint advert check.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func capabilityLessLeafPassesRestoreCheckButNotMint() throws {}
}

@Suite struct MigratedLeafAdvertTests {
	/// A migrated leaf missing the APQ capabilities is refused.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func mintRejectsLeafWithoutAPQCapabilities() throws {}

	/// A migrated leaf of a bound classical half that does not advertise the
	/// AppBinding is refused.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func mintRejectsBoundLeafWithoutBindingAdvert() throws {}
}

@Suite struct RestoredAuthShapeTests {
	/// An empty history is refused.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func rejectsEmptyHistory() throws {}

	/// A history longer than the credential history window is refused.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func rejectsHistoryLongerThanWindow() throws {}

	/// A history that repeats an id is refused.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func rejectsDuplicateHistoryEntry() throws {}

	/// An id in both parties' history or authorizations is refused.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func rejectsIDKnownToBothParties() throws {}

	/// An own authorization of a retired own id, which the public API can
	/// write, still restores.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func restoresAuthorizationOfRetiredOwnID() throws {}

	/// A peer PQ leaf presenting my own id pins it on both sides; the
	/// archive still restores.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func restoresWhenPeerPQLeafPresentsMyID() throws {}

	/// Restore runs the auth shape check.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func restoreRejectsDuplicateHistoryEntry() throws {}

	/// A core-kind mint runs the auth shape check.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func coreMintRejectsDuplicateHistoryEntry() throws {}
}

@Suite struct MigratedPeerApprovalTests {
	/// A migrated peer authorization is dropped at mint, so it cannot admit
	/// an unapproved peer rotation after restore.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func mintDropsTheirAuthorization() throws {}

	/// A migrated queued proposal is dropped at mint, so the next fold cannot
	/// canonicalize a peer rotation the app never approved.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func mintDropsQueuedProposal() throws {}

	/// After a migrated approval is dropped, the next fold canonicalizes no
	/// peer rotation: the peer stays in sync on its old id.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func droppedApprovalLeavesPeerOnOldID() throws {}

	/// A dropped peer rotation converges once the peer re-requests it and the
	/// app approves it again.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func droppedPeerRotationConvergesAfterReapproval() throws {}

	/// My own migrated authorizations survive the mint unchanged.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func mintKeepsMyAuthorizations() throws {}
}

@Suite struct EstablishmentOwedInvariantTests {
	/// An initiator that claims to owe the envelope is refused.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func rejectsOwedOnInitiator() throws {}

	/// An owed envelope with a staple other than the `0x01` welcome is refused.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func rejectsOwedWithMovedStaple() throws {}

	/// A non-dedicated acceptor on its welcome staple that claims to owe the
	/// envelope is refused.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func rejectsOwedOnNonDedicatedAcceptor() throws {}

	/// A dedicated acceptor still on its welcome staple that claims not to owe
	/// the envelope is refused, so the signed-handoff gate cannot be skipped.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func rejectsUnowedDedicatedAcceptorBeforeInstall() throws {}

	/// The migration path refuses the same unowed dedicated acceptor.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func mintRejectsUnowedDedicatedAcceptorBeforeInstall() throws {}

	/// A non-dedicated acceptor whose recv leaf rotated ahead of its send leaf
	/// on the welcome staple still restores.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func restoresNonDedicatedAcceptorAfterPeerFoldedRotation()
		throws
	{}
}

@Suite struct WindowEpochInvariantTests {
	/// A rendezvous entry keyed above the send-classical epoch is refused.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func rejectsRendezvousEntryAboveCurrentEpoch() throws {}

	/// A header-key entry keyed above the send-classical epoch is refused.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func rejectsHeaderKeyEntryAboveCurrentEpoch() throws {}

	/// A PQ header-key entry keyed above the send-PQ epoch is refused.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func rejectsPQHeaderKeyEntryAboveCurrentEpoch() throws {}

	/// PQ header keys with no send PQ group are refused.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func rejectsPQHeaderKeysWithoutSendPQ() throws {}

	/// A core-kind mint refuses a future-keyed window entry.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func coreMintRejectsHeaderKeyEntryAboveCurrentEpoch() throws {}
}

@Suite struct WindowRederivationTests {
	/// A tampered current-epoch rendezvous entry is replaced by the derived value.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func restoreReplacesTamperedCurrentRendezvous() throws {}

	/// A tampered current-epoch header key is replaced by the derived value.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func restoreReplacesTamperedCurrentHeaderKey() throws {}

	/// A tampered current-epoch PQ header key is replaced by the derived value.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func restoreReplacesTamperedCurrentPQHeaderKey() throws {}
}
