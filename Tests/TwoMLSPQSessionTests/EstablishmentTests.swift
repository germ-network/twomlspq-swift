import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSExtensions
import MLSProfileRFC9420
import SecretBytes
import TwoMLSPQCrypto
import XCTest

@testable import TwoMLSPQSession

@available(iOS 26, macOS 26, *)
final class EstablishmentTests: XCTestCase {
	func testBobEstablishedImmediatelyAliceOnlyAfterFirstFrame() throws {
		let (alice, bob, _, _, _, _) = try SessionTestSupport.established()
		XCTAssertFalse(alice.isEstablished)
		XCTAssertTrue(bob.isEstablished)

		let (aliceAfter, bobAfter) = try SessionTestSupport.establishedAndExchanged()
		XCTAssertTrue(aliceAfter.isEstablished)
		XCTAssertTrue(bobAfter.isEstablished)
	}

	/// Both init secrets are join-only: the responder's are spent joining
	/// Group_A and founding Group_B (both done inside `receive`), and the
	/// initiator's PQ one is spent founding Group_A's PQ half — all three
	/// are gone immediately. The initiator's classical one survives until
	/// she joins Group_B herself (the acceptor's first frame), at which
	/// point it too is cleared. An ESTABLISHED session archive never carries
	/// them; only a pre-establishment initiator archive carries its still-
	/// live classical one (this test restores only established bob).
	func testInitSecretsAreClearedOnceSpentAndNeverSurviveRestore() throws {
		let (alice, bob, _, _, _, _) = try SessionTestSupport.established()
		XCTAssertNil(bob.identity.classicalInitSecretKey)
		XCTAssertNil(bob.identity.pqInitSecretKey)
		XCTAssertNil(alice.identity.pqInitSecretKey)
		XCTAssertNotNil(
			alice.identity.classicalInitSecretKey,
			"the initiator still needs it to join Group_B")

		let (aliceAfter, bobAfter) = try SessionTestSupport.establishedAndExchanged()
		XCTAssertNil(aliceAfter.identity.classicalInitSecretKey)
		XCTAssertNil(aliceAfter.identity.pqInitSecretKey)
		XCTAssertNil(bobAfter.identity.classicalInitSecretKey)
		XCTAssertNil(bobAfter.identity.pqInitSecretKey)

		var bobAfterMutable = bobAfter
		let checkpoint = try bobAfterMutable.stateUpdate(kind: .checkpoint).archive
		let restored = try TwoMLSSession.restore(
			core: nil, checkpoint: checkpoint,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		XCTAssertNil(restored.identity.classicalInitSecretKey)
		XCTAssertNil(restored.identity.pqInitSecretKey)
	}

	/// Group_A is a full pair: both halves carry a consistent `APQInfo`
	/// (the identity fields the combiner's own `verifyPair` compares, checked
	/// here via the public `APQInfo` fields directly — `verifyPair` itself
	/// already ran, and threw nothing, inside `joinFull`/`CombinerGroup.join`).
	func testGroupAFullPairAPQInfoIsConsistent() throws {
		let (_, bob, _, _, _, _) = try SessionTestSupport.established()
		let groupA = try XCTUnwrap(bob.recvGroup)
		let pq = try XCTUnwrap(groupA.pq)

		let classicalInfo = try XCTUnwrap(
			try MLS.Combiner.APQInfo.read(
				fromExtensionsOf: groupA.classical.context,
				type: MLS.Combiner.Codepoints.deployed.apqInfoExtensionType))
		let pqInfo = try XCTUnwrap(
			try MLS.Combiner.APQInfo.read(
				fromExtensionsOf: pq.context,
				type: MLS.Combiner.Codepoints.deployed.apqInfoExtensionType))

		XCTAssertEqual(classicalInfo.tSessionGroupID, pqInfo.tSessionGroupID)
		XCTAssertEqual(classicalInfo.pqSessionGroupID, pqInfo.pqSessionGroupID)
		XCTAssertEqual(classicalInfo.mode, pqInfo.mode)
		XCTAssertEqual(classicalInfo.tCipherSuite, pqInfo.tCipherSuite)
		XCTAssertEqual(classicalInfo.pqCipherSuite, pqInfo.pqCipherSuite)
		XCTAssertEqual(classicalInfo.tSessionGroupID, groupA.classical.context.groupID)
		XCTAssertEqual(classicalInfo.pqSessionGroupID, pq.context.groupID)
		XCTAssertEqual(classicalInfo.tEpoch, groupA.classical.context.epoch)
		XCTAssertEqual(pqInfo.pqEpoch, pq.context.epoch)

		XCTAssertEqual(groupA.classical.tree.nonBlankLeaves().count, 2)
		XCTAssertEqual(pq.tree.nonBlankLeaves().count, 2)
	}

	/// Group_B is classical-only: `pq == nil` on both the founder's (Bob) send
	/// group and the joiner's (Alice) receive group, and both rosters are 2.
	func testGroupBIsClassicalOnlyOnBothSides() throws {
		let (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let bobGroupB = try XCTUnwrap(bob.sendGroup)
		let aliceGroupB = try XCTUnwrap(alice.recvGroup)

		XCTAssertNil(bobGroupB.pq)
		XCTAssertNil(aliceGroupB.pq)
		XCTAssertEqual(bobGroupB.classical.tree.nonBlankLeaves().count, 2)
		XCTAssertEqual(aliceGroupB.classical.tree.nonBlankLeaves().count, 2)
	}

	/// Epochs converge on both directional pairs: Bob's copy of Group_A
	/// matches Alice's, and (once Alice has joined it) Alice's copy of Group_B
	/// matches Bob's.
	func testEpochsConverge() throws {
		let (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let aliceGroupA = try XCTUnwrap(alice.sendGroup)
		let bobGroupA = try XCTUnwrap(bob.recvGroup)
		XCTAssertEqual(aliceGroupA.classical.context, bobGroupA.classical.context)
		XCTAssertEqual(aliceGroupA.pq?.context, bobGroupA.pq?.context)

		let bobGroupB = try XCTUnwrap(bob.sendGroup)
		let aliceGroupB = try XCTUnwrap(alice.recvGroup)
		XCTAssertEqual(bobGroupB.classical.context, aliceGroupB.classical.context)
	}

	/// The load-bearing cross-party binding proof: join Group_B's classical
	/// Welcome via the profile's `Group.joining` with an EMPTY PSK resolver —
	/// it must throw `unresolvedPreSharedKey`, proving Group_B's creation
	/// commit referenced the cross-party PSK the joiner is required to
	/// resolve. Mirrors the combiner's own `establishBindsFounderSideApqPsk`.
	/// Run inside `.uint32` component-id width so the `PreSharedKeyID` decodes
	/// at the deployed width — otherwise the join fails earlier, on a wire/parse
	/// error, not the asserted `unresolvedPreSharedKey`.
	func testGroupBWelcomeBindsCrossPartyPSK() throws {
		let (_, _, aliceIdentity, _, _, welcomeB) = try SessionTestSupport.established()
		let (classicalWelcomeBytes, pqWelcomeBytes) = try Frames.decodeAPQWelcome(welcomeB)
		XCTAssertEqual(pqWelcomeBytes, Data())
		let welcome = try MLS.RFC9420.Welcome(mlsEncoded: classicalWelcomeBytes)

		// `PendingJoin` is `~Copyable`, so `XCTAssertThrowsError`'s `Copyable`-bound
		// generic cannot wrap this call — a plain do/catch instead.
		try withDeployedWireConventions {
			do {
				_ = try MLS.RFC9420.Group.joining(
					SessionTestSupport.classicalProvider, welcome: welcome,
					credentials: aliceIdentity.classicalJoinCredentials,
					psk: { _ in nil })
				XCTFail("expected unresolvedPreSharedKey")
			} catch let error as MLS.RFC9420.GroupError {
				XCTAssertEqual(error, .unresolvedPreSharedKey)
			}
		}

		// minor-3: pin the session layer's own cross-party PSK component id —
		// distinct from the combiner's `apq_psk` component (`0xFF01`).
		XCTAssertEqual(TwoMLSSession.crossPartyComponentID.rawValue, 0xFF02)
	}

	/// MAJOR-4: once Alice has joined Group_B, a frame carrying a DIFFERENT
	/// welcome staple — a fresh, unrelated pair's Group_B welcome — must be
	/// rejected outright, not silently re-joined. The idempotent early-return
	/// in `joinGroupBIfNeeded` only covers a byte-identical restaple of the
	/// SAME welcome.
	func testProcessIncomingRejectsADifferentWelcomeOnceEstablished() throws {
		var (alice, _) = try SessionTestSupport.establishedAndExchanged()

		let (otherAlice, otherBobSession, _, _, _, _) =
			try SessionTestSupport
			.established(alice: "alice-intruder", bob: "bob-intruder")
		var otherBob = otherBobSession
		_ = try otherBob.prepareToEncrypt()
		let intruderFrame = try otherBob.encrypt(Data("intruder".utf8)).frame

		// PR2: `intruderFrame` is header-sealed under a key from a totally
		// unrelated pair — alice's `openOrRaw` cannot open it (none of her
		// window keys match) and falls back to passing the still-sealed
		// bytes straight through, so the sealed path fails at the frame
		// decode (a near-uniform random leading byte) rather than the
		// welcome-digest check this test originally pinned.
		XCTAssertThrowsError(try alice.processIncoming(intruderFrame))

		// Restore the deterministic check via the documented `openOrRaw`
		// pass-through: `otherAlice` (the intruder pair's own recipient) can
		// open `intruderFrame` with her window key, recovering the plaintext
		// message frame with the intruder's `APQWelcome_B` staple. Feeding
		// that ALREADY-OPENED frame to `alice.processIncoming` exercises the
		// same `openOrRaw` fallback (it fails AEAD under every one of
		// alice's window keys and passes through raw), but this time the raw
		// bytes decode as a genuine frame, so processing reaches
		// `joinGroupBIfNeeded` and rejects the foreign welcome digest
		// deterministically.
		let raw = try XCTUnwrap(otherAlice.tryOpen(intruderFrame))
		XCTAssertThrowsError(try alice.processIncoming(raw)) {
			XCTAssertEqual($0 as? TwoMLSError, .unexpectedWelcome)
		}
	}

	/// minor-2: a staple welcome not already joined but carrying a non-empty
	/// pq slot — a full (Group_A-shaped) welcome — is a protocol state
	/// `processIncoming` cannot process; only the explicit `receive()` entry
	/// point joins those. The app section is a real sealed `privateMessage`
	/// (borrowed from an actual frame) so the check under test is actually
	/// reached, past the earlier `Message` decode.
	func testProcessIncomingRejectsFullWelcomeStaple() throws {
		var (alice, bob, _, _, _, _) = try SessionTestSupport.established()
		_ = try bob.prepareToEncrypt()
		let realFrame = try bob.encrypt(Data("payload".utf8)).frame
		// PR2: opened via `alice` (the recipient).
		let (_, _, appSection) = try Frames.decodeMessageFrame(alice.openOrRaw(realFrame))

		let fullWelcomeStaple = Frames.encodeAPQWelcome(
			t: Data("fake-t".utf8), pq: Data("fake-pq".utf8))
		let proposalSection = Frames.encodeProposalSection(
			proposing: Data("client".utf8), message: Data("dummy".utf8))
		let forgedFrame = Frames.encodeMessageFrame(
			staple: fullWelcomeStaple, proposal: proposalSection, app: appSection)

		XCTAssertThrowsError(try alice.processIncoming(forgedFrame)) { error in
			XCTAssertEqual(error as? TwoMLSError, .fullEstablishmentStapleUnsupported)
		}
	}

	// MARK: - Group_B join gates: cross-party PSK + creator pin, parse-then-export

	/// A forged Group_B welcome: a classical-only creation commit under
	/// `creatorName`'s fresh identity (a solid `TwoMLSIdentity`, so the commit
	/// and Welcome are genuinely signed — Basic credentials carry no proof,
	/// which is the point), deferred-shape `APQInfo`, `Add(joinerKP)` — and,
	/// unless `crossPSK` is supplied, NO cross-party PSK. Hand-rolled rather
	/// than `APQGroup.establishClassicalOnly`, which always binds the PSK.
	private func forgedGroupBWelcome(
		creatorName: String,
		adding joinerKP: MLS.RFC9420.KeyPackage,
		crossPSK: MLS.Combiner.ExportedPsk? = nil
	) throws -> Data {
		let creator = try SessionTestSupport.identity(creatorName)
		let provider = SessionTestSupport.classicalProvider
		return try withDeployedWireConventions {
			let info = MLS.Combiner.APQInfo(
				tSessionGroupID: provider.randomBytes(provider.hashSize),
				pqSessionGroupID: provider.randomBytes(provider.hashSize),
				mode: 0,
				tCipherSuite: provider.cipherSuite,
				pqCipherSuite: SessionTestSupport.pqProvider.cipherSuite,
				tEpoch: 1,
				pqEpoch: epochUnbound)
			let infoExtension = try info.asExtension(
				type: MLS.Combiner.Codepoints.deployed.apqInfoExtensionType)

			var pskStore = MLS.Combiner.PSKStore()
			if let crossPSK { pskStore.register(crossPSK) }

			let epoch0 = try MLS.RFC9420.Group.create(
				provider, groupID: provider.randomBytes(provider.hashSize),
				leafNode: creator.keyPackage.classical.leafNode,
				leafSecretKey: creator.classicalLeafSecretKey,
				extensions: [infoExtension],
				epochSecret: SecretBytes(randomByteCount: provider.hashSize))
			var proposals: [MLS.RFC9420.ProposalOrRef] = [.proposal(.add(joinerKP))]
			if let crossPSK {
				proposals.append(
					.proposal(
						crossPSK.proposal(
							nonce: provider.randomBytes(
								provider.hashSize))))
			}
			try TwoPartyRules.validateCreationProposals(proposals)
			let transition = try epoch0.committing(
				provider, proposals: proposals, signingKey: creator.signingKey,
				randomness: try .generate(provider), psk: pskStore.resolver())
			let sent = transition.takeOutput()
			guard let welcome = sent.welcome else {
				throw MLS.Combiner.Error.missingWelcome
			}
			return Frames.encodeAPQWelcome(
				t: try welcome.mlsEncoded(), pq: Data())
		}
	}

	/// Frame `staple` as a `0x03` message frame with a real sealed (borrowed)
	/// app section — the app must decode as a `.privateMessage` before
	/// `handleStaple` runs, so a rejected welcome staple still reaches the
	/// code under test.
	private func forgedWelcomeFrame(staple: Data, app: Data) -> Data {
		let proposalSection = Frames.encodeProposalSection(
			proposing: Data("bob".utf8), message: Data("dummy-upd".utf8))
		return Frames.encodeMessageFrame(
			staple: staple, proposal: proposalSection, app: app)
	}

	/// An unwelcome welcome must be refused, not joined: a forged Group_B
	/// welcome naming NO cross-party PSK — even under the creator id Alice
	/// expects (an impersonation that pre-fix joined and returned the
	/// attacker's plaintext) — is rejected with `.missingCrossPartyPSK`, and
	/// Alice stays unestablished.
	func testGroupBJoinRejectsAWelcomeWithoutTheCrossPartyPSK() throws {
		var (alice, bob, aliceIdentity, _, _, _) = try SessionTestSupport.established()
		_ = try bob.prepareToEncrypt()
		let genuineFrame = try bob.encrypt(Data("genuine".utf8)).frame
		// PR2: opened via `alice` (the recipient).
		let (_, _, appSection) = try Frames.decodeMessageFrame(
			alice.openOrRaw(genuineFrame))

		let forgedStaple = try forgedGroupBWelcome(
			creatorName: "bob", adding: aliceIdentity.keyPackage.classical)
		let forgedFrame = forgedWelcomeFrame(staple: forgedStaple, app: appSection)

		XCTAssertThrowsError(try alice.processIncoming(forgedFrame)) { error in
			XCTAssertEqual(error as? TwoMLSError, .missingCrossPartyPSK)
		}
		XCTAssertFalse(alice.isEstablished)
		XCTAssertNil(alice.recvGroup)
		XCTAssertNil(alice.joinedWelcomeDigest)
	}

	/// The creator-identity half: a forged Group_B welcome carrying a VALID
	/// cross-party PSK (Alice's own, exported off a copy of her Group_A) but
	/// created under a different identity ("mallory", not the "bob" Alice is
	/// established against) passes the PSK gate and is caught by the creator
	/// pin — `.remoteIdentityMismatch`, the same error `receive` throws for a
	/// wrong KeyPackage. This is the only route to the creator gate: a foreign
	/// welcome without the PSK never gets here.
	func testGroupBJoinRejectsAWelcomeFromAnUnexpectedCreator() throws {
		var (alice, bob, aliceIdentity, _, _, _) = try SessionTestSupport.established()
		_ = try bob.prepareToEncrypt()
		let genuineFrame = try bob.encrypt(Data("genuine".utf8)).frame
		// PR2: opened via `alice` (the recipient).
		let (_, _, appSection) = try Frames.decodeMessageFrame(
			alice.openOrRaw(genuineFrame))

		var groupACopy = try XCTUnwrap(alice.sendGroup)
		let crossPSK = try MLS.Combiner.ExportedPsk.export(
			from: &groupACopy.classical, SessionTestSupport.classicalProvider,
			componentID: TwoMLSSession.crossPartyComponentID)
		let forgedStaple = try forgedGroupBWelcome(
			creatorName: "mallory", adding: aliceIdentity.keyPackage.classical,
			crossPSK: crossPSK)
		let forgedFrame = forgedWelcomeFrame(staple: forgedStaple, app: appSection)

		XCTAssertThrowsError(try alice.processIncoming(forgedFrame)) { error in
			XCTAssertEqual(error as? TwoMLSError, .remoteIdentityMismatch)
		}
		XCTAssertFalse(alice.isEstablished)
		XCTAssertNil(alice.recvGroup)
		XCTAssertNil(alice.joinedWelcomeDigest)
	}

	/// One malformed — or well-formed-but-foreign — welcome staple must not
	/// permanently wedge the initiator: the one-shot `0xFF02` exporter leaf is
	/// consumed only after the Welcome parses, all writes land on locals, and
	/// a failed join writes nothing back — so Bob's genuine first frame still
	/// joins afterward.
	func testMalformedWelcomeStapleLeavesTheGenuineOneJoinable() throws {
		var (alice, bob, _, _, _, _) = try SessionTestSupport.established()
		_ = try bob.prepareToEncrypt()
		let genuineFrame = try bob.encrypt(Data("genuine".utf8)).frame
		// PR2: opened via `alice` (the recipient).
		let (_, _, appSection) = try Frames.decodeMessageFrame(
			alice.openOrRaw(genuineFrame))

		// (a) A `0x01` welcome staple whose classical `t` slot is garbage — the
		// Welcome fails to parse, before any exporter leaf is consumed.
		let garbageStaple = Frames.encodeAPQWelcome(
			t: Data("not-a-welcome".utf8), pq: Data())
		XCTAssertThrowsError(
			try alice.processIncoming(
				forgedWelcomeFrame(staple: garbageStaple, app: appSection)))
		XCTAssertTrue(alice.sendCrossPSKLedger.isEmpty)
		XCTAssertFalse(alice.isEstablished)

		// (b) A well-formed but FOREIGN welcome — another pair's real Group_B
		// welcome. It dies inside `Welcome.decryptGroupSecrets` (a
		// `GroupError`, not a `TwoMLSError` — asserted accordingly), again
		// without touching Alice's exporter leaf.
		var (otherAlice, otherBob, _, _, _, otherWelcomeB) =
			try SessionTestSupport.established(
				alice: "alice-other", bob: "bob-other")
		_ = try otherBob.prepareToEncrypt()
		let otherGenuineFrame = try otherBob.encrypt(Data("other".utf8)).frame
		// PR2: opened via `otherAlice` (the recipient in that OTHER pair).
		let (_, _, otherAppSection) = try Frames.decodeMessageFrame(
			otherAlice.openOrRaw(otherGenuineFrame))
		XCTAssertThrowsError(
			try alice.processIncoming(
				forgedWelcomeFrame(staple: otherWelcomeB, app: otherAppSection))
		) { error in
			XCTAssertEqual(error as? MLS.RFC9420.GroupError, .noMatchingWelcomeSecret)
		}
		XCTAssertTrue(alice.sendCrossPSKLedger.isEmpty)
		XCTAssertFalse(alice.isEstablished)

		// Bob's genuine first frame now joins cleanly — no wedge.
		_ = try bob.prepareToEncrypt()
		let realFrame = try bob.encrypt(Data("bob-hello".utf8)).frame
		let decrypted = try alice.processIncoming(realFrame)
		XCTAssertEqual(decrypted.applicationMessage, Data("bob-hello".utf8))
		XCTAssertTrue(alice.isEstablished)
	}

	// MARK: - AS establishment identity binding

	/// `receive` must reject a caller-supplied `theirClassicalKeyPackage` that
	/// names a third party rather than the creator the Welcome actually joined.
	func testReceiveRejectsWrongPeerKeyPackage() throws {
		let alice = try SessionTestSupport.identity("as-alice")
		let bob = try SessionTestSupport.identity("as-bob")
		let carol = try SessionTestSupport.identity("as-carol")
		let initiated = try TwoMLSSession.initiate(
			identity: alice, their: bob.keyPackage,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		XCTAssertThrowsError(
			try TwoMLSSession.receive(
				identity: bob, welcome: initiated.welcome,
				theirClassicalKeyPackage: carol.keyPackage.classical,
				bootstrapKPCommitment: try initiated.session
					.bootstrapKPCommitment(),
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .remoteIdentityMismatch)
		}
	}

	/// The self-id case: Bob's OWN KeyPackage passed as the peer's must be
	/// rejected — the check is equality with the joined creator, not mere
	/// membership (Bob's own id is "known" via `mine`, but is not the creator).
	func testReceiveRejectsSelfIdentityKeyPackage() throws {
		let alice = try SessionTestSupport.identity("as-alice-2")
		let bob = try SessionTestSupport.identity("as-bob-2")
		let initiated = try TwoMLSSession.initiate(
			identity: alice, their: bob.keyPackage,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		XCTAssertThrowsError(
			try TwoMLSSession.receive(
				identity: bob, welcome: initiated.welcome,
				theirClassicalKeyPackage: bob.keyPackage.classical,
				bootstrapKPCommitment: try initiated.session
					.bootstrapKPCommitment(),
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .remoteIdentityMismatch)
		}
	}

	/// `initiate` must reject a peer whose classical and PQ `KeyPackage` halves
	/// present different identities.
	func testInitiateRejectsMismatchedPeerHalves() throws {
		let alice = try SessionTestSupport.identity("as-alice-3")
		let bob = try SessionTestSupport.identity("as-bob-3")
		let carol = try SessionTestSupport.identity("as-carol-3")
		let mismatched = CombinerKeyPackage(
			classical: bob.keyPackage.classical, pq: carol.keyPackage.pq)
		XCTAssertThrowsError(
			try TwoMLSSession.initiate(
				identity: alice, their: mismatched,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .remoteIdentityMismatch)
		}
	}
}
