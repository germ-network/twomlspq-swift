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

	/// A PQ two-party group whose second leaf carries `capabilities`.
	static func pq(
		_ founder: TwoMLSIdentity, addingLeafWith capabilities: MLS.RFC9420.Capabilities
	) throws -> MLS.RFC9420.Group {
		let provider = SessionTestSupport.pqProvider
		let rogue = try SessionMigrationTests().rogueKeyPackage(
			named: "rogue-peer", capabilities: capabilities, provider: provider)
		return try group(
			provider, founderLeaf: founder.keyPackage.pq.leafNode,
			founderSecret: founder.pqLeafSecretKey, signingKey: founder.pqSigningKey,
			adding: [rogue], extensions: [])
	}

	/// A classical two-party group whose second leaf carries `capabilities`.
	/// The group is built by plain Add, which does not check the leaf against
	/// the group's extensions.
	static func classical(
		_ founder: TwoMLSIdentity, addingLeafWith capabilities: MLS.RFC9420.Capabilities,
		extensions: [MLS.RFC9420.Extension] = []
	) throws -> MLS.RFC9420.Group {
		let provider = SessionTestSupport.classicalProvider
		let rogue = try SessionMigrationTests().rogueKeyPackage(
			named: "rogue-peer", capabilities: capabilities)
		return try group(
			provider, founderLeaf: founder.keyPackage.classical.leafNode,
			founderSecret: founder.classicalLeafSecretKey,
			signingKey: founder.signingKey,
			adding: [rogue], extensions: extensions)
	}

	static func checkpointBody(_ session: TwoMLSSession) throws -> SessionArchive {
		try session.makeSessionArchive(kind: .checkpoint).decode(SessionArchive.self)
	}

	static func restore(_ body: SessionArchive) throws -> TwoMLSSession {
		try SessionTestSupport.restore(checkpoint: try SecretArchive(encoding: body))
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
		return (try Fixtures.checkpointBody(target), try Fixtures.checkpointBody(source))
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
				#expect(throws: Never.self) { try Fixtures.restore(body) }
			} else {
				#expect(throws: TwoMLSError.archiveInvalid) {
					try Fixtures.restore(body)
				}
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
	@Test func capabilityLessLeafPassesRestoreCheckButNotMint() throws {
		let alice = try SessionTestSupport.identity("cap-alice")
		let group = try Fixtures.classical(
			alice, addingLeafWith: SessionMigrationTests.rogueCapabilities)
		#expect(throws: Never.self) { try check(sendClassical: group) }
		#expect(throws: TwoMLSError.archiveInvalid) {
			try SessionMigration.validateMigratedLeafAdverts(
				sendClassical: group, sendPQ: nil, recvClassical: nil, recvPQ: nil)
		}
	}
}

@Suite struct MigratedLeafAdvertTests {
	@available(iOS 26, macOS 26, *)
	private typealias Fixtures = RestoreInvariantFixtures

	@available(iOS 26, macOS 26, *)
	private func adverts(
		sendClassical: MLS.RFC9420.Group, recvClassical: MLS.RFC9420.Group? = nil
	) throws {
		try SessionMigration.validateMigratedLeafAdverts(
			sendClassical: sendClassical, sendPQ: nil, recvClassical: recvClassical,
			recvPQ: nil)
	}

	/// A migrated leaf missing the APQ capabilities is refused.
	@available(iOS 26, macOS 26, *)
	@Test func mintRejectsLeafWithoutAPQCapabilities() throws {
		let alice = try SessionTestSupport.identity("adv-alice")
		let bob = try SessionTestSupport.identity("adv-bob")
		let honest = try Fixtures.classical(alice, adding: [bob])
		let rogue = try Fixtures.classical(
			alice, addingLeafWith: SessionMigrationTests.rogueCapabilities)
		#expect(throws: Never.self) { try adverts(sendClassical: honest) }
		#expect(throws: TwoMLSError.archiveInvalid) { try adverts(sendClassical: rogue) }
		#expect(throws: TwoMLSError.archiveInvalid) {
			try adverts(sendClassical: honest, recvClassical: rogue)
		}
		let rogueCaps = SessionMigrationTests.rogueCapabilities
		let rogueSendPQ = try Fixtures.pq(alice, addingLeafWith: rogueCaps)
		let honestPQ = try Fixtures.pq(alice, adding: [bob])
		#expect(throws: TwoMLSError.archiveInvalid) {
			try SessionMigration.validateMigratedLeafAdverts(
				sendClassical: honest, sendPQ: rogueSendPQ, recvClassical: nil,
				recvPQ: nil)
		}
		#expect(throws: TwoMLSError.archiveInvalid) {
			try SessionMigration.validateMigratedLeafAdverts(
				sendClassical: honest, sendPQ: honestPQ, recvClassical: honest,
				recvPQ: rogueSendPQ)
		}
	}

	/// A migrated leaf of a bound classical half that does not advertise the
	/// AppBinding is refused.
	@available(iOS 26, macOS 26, *)
	@Test func mintRejectsBoundLeafWithoutBindingAdvert() throws {
		let alice = try SessionTestSupport.identity("adv-bound-alice")
		let bob = try SessionTestSupport.identity("adv-bound-bob")
		let apqOnly = MLS.RFC9420.Capabilities(
			versions: [.mls10], cipherSuites: [TwoMLSSuite.classical, TwoMLSSuite.pq],
			extensions: [MLS.Combiner.Codepoints.deployed.apqInfoExtensionType],
			proposals: [MLS.RFC9420.ProposalType(.appDataUpdate)],
			credentials: [MLS.RFC9420.CredentialType(.basic)])
		let binding = [try Fixtures.bindingExtension()]
		let bound = try Fixtures.classical(alice, adding: [bob], extensions: binding)
		let boundWithoutAdvert = try Fixtures.classical(
			alice, addingLeafWith: apqOnly, extensions: binding)
		let unboundWithoutAdvert = try Fixtures.classical(alice, addingLeafWith: apqOnly)
		#expect(throws: Never.self) { try adverts(sendClassical: bound) }
		#expect(throws: Never.self) { try adverts(sendClassical: unboundWithoutAdvert) }
		#expect(throws: TwoMLSError.archiveInvalid) {
			try adverts(sendClassical: boundWithoutAdvert)
		}
		#expect(throws: TwoMLSError.archiveInvalid) {
			try adverts(sendClassical: bound, recvClassical: boundWithoutAdvert)
		}
	}
}

@Suite struct RestoredAuthShapeTests {
	@available(iOS 26, macOS 26, *)
	private typealias Fixtures = RestoreInvariantFixtures

	private func ids(_ names: String...) -> [Data] { names.map { Data($0.utf8) } }

	private func auth(
		mine: [Data], theirs: [Data], mineNext: [Data] = [], theirsNext: [Data] = []
	) -> AuthCore {
		AuthCore(
			mine: PartySequence(history: mine, authorizedNext: mineNext),
			theirs: PartySequence(history: theirs, authorizedNext: theirsNext))
	}

	@available(iOS 26, macOS 26, *)
	private func shape(_ auth: AuthCore) throws {
		try TwoMLSSession.validateAuthShape(auth)
	}

	/// An empty history is refused.
	@available(iOS 26, macOS 26, *)
	@Test func rejectsEmptyHistory() throws {
		#expect(throws: Never.self) { try shape(auth(mine: ids("a"), theirs: ids("b"))) }
		#expect(throws: TwoMLSError.archiveInvalid) {
			try shape(auth(mine: [], theirs: ids("b")))
		}
		#expect(throws: TwoMLSError.archiveInvalid) {
			try shape(auth(mine: ids("a"), theirs: []))
		}
	}

	/// A history longer than the credential history window is refused.
	@available(iOS 26, macOS 26, *)
	@Test func rejectsHistoryLongerThanWindow() throws {
		let window = PartySequence.credentialHistoryWindow
		let full = (0..<window).map { Data("m\($0)".utf8) }
		#expect(throws: Never.self) { try shape(auth(mine: full, theirs: ids("b"))) }
		let over = full + [Data("extra".utf8)]
		#expect(throws: TwoMLSError.archiveInvalid) {
			try shape(auth(mine: over, theirs: ids("b")))
		}
		#expect(throws: TwoMLSError.archiveInvalid) {
			try shape(auth(mine: ids("a"), theirs: over.map { $0 + Data("t".utf8) }))
		}
	}

	/// A history that repeats an id is refused.
	@available(iOS 26, macOS 26, *)
	@Test func rejectsDuplicateHistoryEntry() throws {
		#expect(throws: TwoMLSError.archiveInvalid) {
			try shape(auth(mine: ids("a", "a"), theirs: ids("b")))
		}
		#expect(throws: TwoMLSError.archiveInvalid) {
			try shape(auth(mine: ids("a"), theirs: ids("b", "c", "b")))
		}
	}

	/// An id in both parties' history or authorizations is refused.
	@available(iOS 26, macOS 26, *)
	@Test func rejectsIDKnownToBothParties() throws {
		#expect(throws: Never.self) {
			try shape(
				auth(
					mine: ids("a"), theirs: ids("b"), mineNext: ids("c"),
					theirsNext: ids("d")))
		}
		let crossed: [AuthCore] = [
			auth(mine: ids("a"), theirs: ids("a")),
			auth(mine: ids("a"), theirs: ids("b"), theirsNext: ids("a")),
			auth(mine: ids("a"), theirs: ids("b"), mineNext: ids("b")),
			auth(
				mine: ids("a"), theirs: ids("b"), mineNext: ids("c"),
				theirsNext: ids("c")),
		]
		for candidate in crossed {
			#expect(throws: TwoMLSError.archiveInvalid) { try shape(candidate) }
		}
	}

	/// An own authorization of a retired own id, which the public API can
	/// write, still restores.
	@available(iOS 26, macOS 26, *)
	@Test func restoresAuthorizationOfRetiredOwnID() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let oldID = alice.identity.clientID
		_ = try alice.prepareToEncrypt(rotating: Data("alice-rotated".utf8))
		let first = try alice.encrypt(Data("x".utf8)).frame
		let received = try bob.processIncomingDecrypted(first)
		_ = try bob.queueProposal(digest: received.queuedProposal.digest)
		_ = try bob.prepareToEncrypt()
		let reply = try bob.encrypt(Data("y".utf8)).frame
		#expect(try alice.processIncomingDecrypted(reply).ownCredentialCanonicalized)
		_ = try alice.prepareToEncrypt(rotating: oldID)
		_ = try alice.encrypt(Data("z".utf8))

		let archive = try alice.stateUpdate(kind: .checkpoint).archive
		let body = try archive.decode(SessionArchive.self)
		#expect(body.auth.mine.authorizedNext.contains(oldID))
		#expect(body.auth.mine.history.contains(oldID))
		#expect(throws: Never.self) { try SessionTestSupport.restore(checkpoint: archive) }
	}

	/// A peer PQ leaf presenting my own id pins it on both sides; the
	/// archive still restores.
	@available(iOS 26, macOS 26, *)
	@Test func restoresWhenPeerPQLeafPresentsMyID() throws {
		let aliceIdentity = try SessionTestSupport.identity("shape-alice")
		let bobIdentity = try SessionTestSupport.identity("shape-bob")
		let evil = try SessionTestSupport.identity("shape-bob")
		let rogueKP = try MLS.RFC9420.Message.keyPackage(evil.keyPackage.pq).mlsEncoded()
		let initiated = try TwoMLSSession.initiate(
			identity: aliceIdentity, their: bobIdentity.keyPackage,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		var bob = try TwoMLSSession.receive(
			identity: bobIdentity, welcome: initiated.welcome,
			theirClassicalKeyPackage: aliceIdentity.keyPackage.classical,
			bootstrapKPCommitment: try SessionTestSupport.classicalProvider.hash(
				rogueKP),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider
		).session
		_ = try bob.prepareToEncrypt()
		_ = try bob.encrypt(Data("hello".utf8))
		let response = try bob.pqBootstrapRespond(Frames.encodePQBootstrapKP(rogueKP))

		let body = try response.update.archive.decode(SessionArchive.self)
		let bobID = bobIdentity.clientID
		#expect(body.auth.mine.pinned.contains(bobID))
		#expect(body.auth.theirs.pinned.contains(bobID))
		#expect(throws: Never.self) {
			try SessionTestSupport.restore(checkpoint: response.update.archive)
		}
	}

	/// With a well-shaped history the pin checks are still the ones that
	/// refuse a pinned candidate and a stranded presented id: the PQ leaves
	/// keep presenting the old own id after a classical rotation.
	@available(iOS 26, macOS 26, *)
	@Test func restoreStillRejectsBadPinsOnAWellShapedHistory() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let oldID = alice.identity.clientID
		let newID = Data("alice-rotated".utf8)
		_ = try alice.prepareToEncrypt(rotating: newID)
		let first = try alice.encrypt(Data("x".utf8)).frame
		let received = try bob.processIncomingDecrypted(first)
		_ = try bob.queueProposal(digest: received.queuedProposal.digest)
		_ = try bob.prepareToEncrypt()
		let reply = try bob.encrypt(Data("y".utf8)).frame
		#expect(try alice.processIncomingDecrypted(reply).ownCredentialCanonicalized)

		let control = try Fixtures.checkpointBody(alice)
		#expect(control.auth.mine.history == [oldID, newID])
		var wellShaped = control
		wellShaped.auth.mine.history = [newID]
		wellShaped.auth.mine.pinned = [oldID]
		#expect(throws: Never.self) { try Fixtures.restore(wellShaped) }

		var pinnedCandidate = wellShaped
		pinnedCandidate.auth.mine.authorizedNext = [oldID]
		#expect(throws: TwoMLSError.archiveInvalid) {
			try Fixtures.restore(pinnedCandidate)
		}

		var stranded = wellShaped
		stranded.auth.mine.pinned = []
		#expect(throws: TwoMLSError.archiveInvalid) { try Fixtures.restore(stranded) }
	}

	/// Restore runs the auth shape check.
	@available(iOS 26, macOS 26, *)
	@Test func restoreRejectsDuplicateHistoryEntry() throws {
		let (_, bob) = try SessionTestSupport.establishedAndExchanged()
		let control = try Fixtures.checkpointBody(bob)
		#expect(throws: Never.self) { try Fixtures.restore(control) }
		var body = control
		let current = try #require(body.auth.mine.history.last)
		body.auth.mine.history = [current, current]
		#expect(throws: TwoMLSError.archiveInvalid) { try Fixtures.restore(body) }
	}

	/// A core-kind mint runs the auth shape check.
	@available(iOS 26, macOS 26, *)
	@Test func coreMintRejectsDuplicateHistoryEntry() throws {
		let migration = SessionMigrationTests()
		let (alice, _) = try migration.fullyEstablishedPair()
		var parts = try migration.migratedParts(alice, suppliedLeafKeys: true)
		let mint = {
			try SessionMigration.mintArchive(
				kind: .core, parts: parts,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		}
		#expect(throws: Never.self) { try mint() }
		let current = try #require(parts.auth.mine.history.last)
		parts.auth.mine.history = [current, current]
		#expect(throws: TwoMLSError.archiveInvalid) { try mint() }
	}
}

@Suite struct MigratedPeerApprovalTests {
	/// Alice asks to rotate; Bob has approved the offer but not yet folded it.
	@available(iOS 26, macOS 26, *)
	private func approvedButUnfolded() throws -> (
		alice: TwoMLSSession, bob: TwoMLSSession, oldID: Data, newID: Data
	) {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let oldID = alice.identity.clientID
		let newID = Data("alice-rotated".utf8)
		_ = try alice.prepareToEncrypt(rotating: newID)
		let frame = try alice.encrypt(Data("x".utf8)).frame
		let received = try bob.processIncomingDecrypted(frame)
		_ = try bob.queueProposal(digest: received.queuedProposal.digest)
		return (alice, bob, oldID, newID)
	}

	@available(iOS 26, macOS 26, *)
	private func mint(_ session: TwoMLSSession) throws -> (
		parts: MigratedSession, archive: SecretArchive
	) {
		let parts = try SessionMigrationTests().migratedParts(
			session, suppliedLeafKeys: true)
		return (
			parts,
			try SessionMigration.mintArchive(
				kind: .checkpoint, parts: parts,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		)
	}

	/// A migrated peer authorization is dropped at mint, so it cannot admit
	/// an unapproved peer rotation after restore.
	@available(iOS 26, macOS 26, *)
	@Test func mintDropsTheirAuthorization() throws {
		let (_, bob, _, newID) = try approvedButUnfolded()
		let minted = try mint(bob)
		#expect(minted.parts.auth.theirs.authorizedNext == [newID])
		let body = try minted.archive.decode(SessionArchive.self)
		#expect(body.auth.theirs.authorizedNext.isEmpty)
	}

	/// The dropped authorization never shields a pin: an id the peer's PQ
	/// leaf presents, listed only as a migrated authorization, is pinned by
	/// the minted archive.
	@available(iOS 26, macOS 26, *)
	@Test func mintPinsAPresentedIDListedOnlyAsAuthorization() throws {
		let (_, bob) = try SessionTestSupport.establishedAndExchanged()
		let presented = try #require(bob.auth.theirs.history.last)
		var parts = try SessionMigrationTests().migratedParts(bob, suppliedLeafKeys: true)
		parts.auth.theirs = MigratedPartySequence(
			history: [Data("former-peer-id".utf8)], authorizedNext: [presented],
			pinned: [])
		let archive = try SessionMigration.mintArchive(
			kind: .checkpoint, parts: parts,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		let body = try archive.decode(SessionArchive.self)
		#expect(body.auth.theirs.pinned == [presented])
		#expect(throws: Never.self) { try SessionTestSupport.restore(checkpoint: archive) }
	}

	/// A migrated queued proposal is dropped at mint, so the next fold cannot
	/// canonicalize a peer rotation the app never approved.
	@available(iOS 26, macOS 26, *)
	@Test func mintDropsQueuedProposal() throws {
		let (_, bob, _, _) = try approvedButUnfolded()
		let minted = try mint(bob)
		#expect(minted.parts.queuedProposal != nil)
		let body = try minted.archive.decode(SessionArchive.self)
		#expect(body.queuedProposal == nil)
	}

	/// After a migrated approval is dropped, the next fold canonicalizes no
	/// peer rotation: the peer stays in sync on its old id.
	@available(iOS 26, macOS 26, *)
	@Test func droppedApprovalLeavesPeerOnOldID() throws {
		let (_, bob, oldID, _) = try approvedButUnfolded()
		var restored = try SessionTestSupport.restore(checkpoint: try mint(bob).archive)
		#expect(restored.theirPrincipalState == .sync(oldID))
		let historyBefore = restored.auth.theirs.history
		let prepared = try restored.prepareToEncrypt()
		#expect(!prepared.didCommit)
		#expect(restored.auth.theirs.history == historyBefore)
		#expect(restored.theirPrincipalState == .sync(oldID))
	}

	/// A dropped peer rotation converges once the peer re-requests it and the
	/// app approves it again.
	@available(iOS 26, macOS 26, *)
	@Test func droppedPeerRotationConvergesAfterReapproval() throws {
		var (alice, bob, oldID, newID) = try approvedButUnfolded()
		var restored = try SessionTestSupport.restore(checkpoint: try mint(bob).archive)
		_ = try restored.prepareToEncrypt()
		_ = try alice.processIncomingDecrypted(try restored.encrypt(Data("y".utf8)).frame)
		#expect(alice.myPrincipalState == .pending(old: oldID, new: newID))

		_ = try alice.prepareToEncrypt(rotating: newID)
		let request = try restored.processIncomingDecrypted(
			try alice.encrypt(Data("z".utf8)).frame)
		_ = try restored.queueProposal(digest: request.queuedProposal.digest)
		_ = try restored.prepareToEncrypt()
		let reply = try alice.processIncomingDecrypted(
			try restored.encrypt(Data("w".utf8)).frame)
		#expect(reply.ownCredentialCanonicalized)
		#expect(restored.auth.theirs.history.last == newID)
	}

	/// My own migrated authorizations survive the mint unchanged.
	@available(iOS 26, macOS 26, *)
	@Test func mintKeepsMyAuthorizations() throws {
		let (alice, _, _, newID) = try approvedButUnfolded()
		let minted = try mint(alice)
		#expect(minted.parts.auth.mine.authorizedNext == [newID])
		let body = try minted.archive.decode(SessionArchive.self)
		#expect(body.auth.mine.authorizedNext == [newID])
	}
}

@Suite struct EstablishmentOwedInvariantTests {
	@available(iOS 26, macOS 26, *)
	private typealias Fixtures = RestoreInvariantFixtures

	@available(iOS 26, macOS 26, *)
	private func restoreRefuses(
		_ session: TwoMLSSession, owes: Bool,
		sourceLocation: SourceLocation = #_sourceLocation
	) throws {
		var body = try Fixtures.checkpointBody(session)
		#expect(
			body.owesEstablishmentEnvelope != owes,
			"the patch must change the flag", sourceLocation: sourceLocation)
		#expect(throws: Never.self, sourceLocation: sourceLocation) {
			try Fixtures.restore(try Fixtures.checkpointBody(session))
		}
		body.owesEstablishmentEnvelope = owes
		#expect(throws: TwoMLSError.archiveInvalid, sourceLocation: sourceLocation) {
			try Fixtures.restore(body)
		}
	}

	/// An initiator that claims to owe the envelope is refused.
	@available(iOS 26, macOS 26, *)
	@Test func rejectsOwedOnInitiator() throws {
		let (alice, _, _, _, _, _) = try SessionTestSupport.established()
		try restoreRefuses(alice, owes: true)
	}

	/// An owed envelope with a staple other than the `0x01` welcome is refused.
	@available(iOS 26, macOS 26, *)
	@Test func rejectsOwedWithMovedStaple() throws {
		var (_, bob, _, _, _) = try SessionTestSupport.establishedDedicated()
		_ = try bob.installEstablishmentEnvelope(Data("fake-signed-handoff".utf8))
		#expect(bob.currentStaple.first == Frames.establishmentHandoffTag)
		try restoreRefuses(bob, owes: true)
	}

	/// A non-dedicated acceptor on its welcome staple that claims to owe the
	/// envelope is refused.
	@available(iOS 26, macOS 26, *)
	@Test func rejectsOwedOnNonDedicatedAcceptor() throws {
		let (_, bob, _, _, _, _) = try SessionTestSupport.established()
		#expect(bob.currentStaple.first == Frames.apqWelcomeTag)
		try restoreRefuses(bob, owes: true)
	}

	/// A dedicated acceptor still on its welcome staple that claims not to owe
	/// the envelope is refused, so the signed-handoff gate cannot be skipped.
	@available(iOS 26, macOS 26, *)
	@Test func rejectsUnowedDedicatedAcceptorBeforeInstall() throws {
		let (_, bob, _, _, _) = try SessionTestSupport.establishedDedicated()
		#expect(bob.owesEstablishmentEnvelope)
		try restoreRefuses(bob, owes: false)
	}

	/// A recv leaf whose id has left `mine.history` counts as older than the
	/// send leaf, so the acceptor still owes the envelope.
	@available(iOS 26, macOS 26, *)
	@Test func evictedRecvIDCountsAsOldest() throws {
		let (_, bob, _, invitationID, dedicatedID) =
			try SessionTestSupport.establishedDedicated()
		var body = try Fixtures.checkpointBody(bob)
		#expect(body.auth.mine.history == [invitationID, dedicatedID])
		body.auth.mine.history = [dedicatedID]
		#expect(throws: Never.self) { try Fixtures.restore(body) }
		body.owesEstablishmentEnvelope = false
		#expect(throws: TwoMLSError.archiveInvalid) { try Fixtures.restore(body) }
	}

	/// The migration path refuses the same unowed dedicated acceptor.
	@available(iOS 26, macOS 26, *)
	@Test func mintRejectsUnowedDedicatedAcceptorBeforeInstall() throws {
		let migration = SessionMigrationTests()
		let established = try migration.deployedShapedEstablishedDedicated(bob: "bob-owed")
		let invitation = established.bob.identity
		let custody = MigratedRecvLeafPrincipal(
			clientID: invitation.clientID, signingKey: invitation.signingKey.data,
			signatureKey: invitation.signatureKey.data,
			pqSigningKey: invitation.pqSigningKey.data,
			pqSignatureKey: invitation.pqSignatureKey.data)
		var parts = try migration.migratedParts(
			established.bob, identityOverride: established.dIdentity,
			recvLeafPrincipal: custody)
		let mint = {
			try SessionMigration.mintArchive(
				kind: .core, parts: parts,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		}
		#expect(parts.owesEstablishmentEnvelope)
		#expect(throws: Never.self) { try mint() }
		parts.owesEstablishmentEnvelope = false
		#expect(throws: TwoMLSError.archiveInvalid) { try mint() }
	}

	/// A non-dedicated acceptor whose recv leaf rotated ahead of its send leaf
	/// on the welcome staple still restores.
	@available(iOS 26, macOS 26, *)
	@Test func restoresNonDedicatedAcceptorAfterPeerFoldedRotation()
		throws
	{
		var (alice, bob, _, _, _, _) = try SessionTestSupport.established()
		_ = try bob.prepareToEncrypt(rotating: Data("bob-rotated".utf8))
		let first = try bob.encrypt(Data("x".utf8)).frame
		let received = try alice.processIncomingDecrypted(first)
		_ = try alice.queueProposal(digest: received.queuedProposal.digest)
		_ = try alice.prepareToEncrypt()
		let reply = try alice.encrypt(Data("y".utf8)).frame
		_ = try bob.processIncomingDecrypted(reply)

		let body = try Fixtures.checkpointBody(bob)
		#expect(body.currentStaple.first == Frames.apqWelcomeTag)
		#expect(!body.owesEstablishmentEnvelope)
		#expect(body.auth.mine.history.count == 2)
		#expect(throws: Never.self) { try Fixtures.restore(body) }
	}
}

@Suite struct WindowEpochInvariantTests {
	@available(iOS 26, macOS 26, *)
	private typealias Fixtures = RestoreInvariantFixtures

	private static let entry = Data(repeating: 0x42, count: 32)

	/// The patched window entry is refused, and the unpatched archive is the
	/// control.
	@available(iOS 26, macOS 26, *)
	private func refuses(
		_ session: TwoMLSSession, sourceLocation: SourceLocation = #_sourceLocation,
		patch: (inout SessionArchive) -> Void
	) throws {
		let control = try Fixtures.checkpointBody(session)
		#expect(throws: Never.self, sourceLocation: sourceLocation) {
			try Fixtures.restore(control)
		}
		var body = control
		patch(&body)
		#expect(throws: TwoMLSError.archiveInvalid, sourceLocation: sourceLocation) {
			try Fixtures.restore(body)
		}
	}

	/// A rendezvous entry keyed above the send-classical epoch is refused.
	@available(iOS 26, macOS 26, *)
	@Test func rejectsRendezvousEntryAboveCurrentEpoch() throws {
		let (_, bob) = try SessionTestSupport.establishedAndExchanged()
		let epoch = try #require(bob.sendGroup).classical.context.epoch
		try refuses(bob) { $0.listenRendezvous.entries[epoch + 1] = Self.entry }
	}

	/// A header-key entry keyed above the send-classical epoch is refused.
	@available(iOS 26, macOS 26, *)
	@Test func rejectsHeaderKeyEntryAboveCurrentEpoch() throws {
		let (_, bob) = try SessionTestSupport.establishedAndExchanged()
		let epoch = try #require(bob.sendGroup).classical.context.epoch
		try refuses(bob) { $0.recvHeaderKeys.entries[epoch + 1] = Self.entry }
	}

	/// A PQ header-key entry keyed above the send-PQ epoch is refused.
	@available(iOS 26, macOS 26, *)
	@Test func rejectsPQHeaderKeyEntryAboveCurrentEpoch() throws {
		let bob = try RatchetTests.fullyEstablishedTurnOnBob().bob
		let epoch = try #require(bob.sendGroup?.pq).context.epoch
		try refuses(bob) { $0.recvHeaderKeysPQ.entries[epoch + 1] = Self.entry }
	}

	/// PQ header keys with no send PQ group are refused.
	@available(iOS 26, macOS 26, *)
	@Test func rejectsPQHeaderKeysWithoutSendPQ() throws {
		let (_, bob, _, _, _, _) = try SessionTestSupport.established()
		#expect(bob.sendGroup?.pq == nil)
		try refuses(bob) { $0.recvHeaderKeysPQ.entries[0] = Self.entry }
	}

	/// A core-kind mint refuses a future-keyed window entry.
	@available(iOS 26, macOS 26, *)
	@Test func coreMintRejectsHeaderKeyEntryAboveCurrentEpoch() throws {
		let migration = SessionMigrationTests()
		let (alice, _) = try migration.fullyEstablishedPair()
		let epoch = try #require(alice.sendGroup).classical.context.epoch
		var parts = try migration.migratedParts(alice, suppliedLeafKeys: true)
		let mint = {
			try SessionMigration.mintArchive(
				kind: .core, parts: parts,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		}
		#expect(throws: Never.self) { try mint() }
		let control = parts
		parts.recvHeaderKeys[epoch + 1] = Self.entry
		#expect(throws: TwoMLSError.archiveInvalid) { try mint() }
		parts = control
		parts.listenRendezvous[epoch + 1] = Self.entry
		#expect(throws: TwoMLSError.archiveInvalid) { try mint() }
		parts = control
		let pqEpoch = try #require(alice.sendGroup?.pq).context.epoch
		parts.recvHeaderKeysPQ[pqEpoch + 1] = Self.entry
		#expect(throws: TwoMLSError.archiveInvalid) { try mint() }
	}
}

@Suite struct WindowRederivationTests {
	@available(iOS 26, macOS 26, *)
	private typealias Fixtures = RestoreInvariantFixtures

	private static let tampered = Data(repeating: 0x42, count: 32)

	/// A tampered current-epoch rendezvous entry is replaced by the derived value.
	@available(iOS 26, macOS 26, *)
	@Test func restoreReplacesTamperedCurrentRendezvous() throws {
		let (_, bob) = try SessionTestSupport.establishedAndExchanged()
		let epoch = try #require(bob.sendGroup).classical.context.epoch
		let derived = try #require(bob.listenRendezvous[epoch])
		var body = try Fixtures.checkpointBody(bob)
		body.listenRendezvous.entries[epoch] = Self.tampered
		let restored = try Fixtures.restore(body)
		#expect(restored.listenRendezvous[epoch] == derived)
	}

	/// A tampered current-epoch header key is replaced by the derived value.
	@available(iOS 26, macOS 26, *)
	@Test func restoreReplacesTamperedCurrentHeaderKey() throws {
		let (_, bob) = try SessionTestSupport.establishedAndExchanged()
		let epoch = try #require(bob.sendGroup).classical.context.epoch
		let derived = try #require(bob.recvHeaderKeys[epoch])
		var body = try Fixtures.checkpointBody(bob)
		body.recvHeaderKeys.entries[epoch] = Self.tampered
		let restored = try Fixtures.restore(body)
		#expect(restored.recvHeaderKeys[epoch] == derived)
	}

	/// A tampered current-epoch PQ header key is replaced by the derived value.
	@available(iOS 26, macOS 26, *)
	@Test func restoreReplacesTamperedCurrentPQHeaderKey() throws {
		let bob = try RatchetTests.fullyEstablishedTurnOnBob().bob
		let epoch = try #require(bob.sendGroup?.pq).context.epoch
		let derived = try #require(bob.recvHeaderKeysPQ[epoch])
		var body = try Fixtures.checkpointBody(bob)
		body.recvHeaderKeysPQ.entries[epoch] = Self.tampered
		let restored = try Fixtures.restore(body)
		#expect(restored.recvHeaderKeysPQ[epoch] == derived)
	}
}
