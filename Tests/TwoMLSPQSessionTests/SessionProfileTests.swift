import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes
import XCTest

@testable import TwoMLSPQSession

// Book group-rules.md rule 9: the session profile is chosen from the two
// classical key packages, recorded on both classical halves, and run.

@available(iOS 26, macOS 26, *)
final class SessionProfileTests: XCTestCase {
	private let classicalProvider = SessionTestSupport.classicalProvider
	private let pqProvider = SessionTestSupport.pqProvider
	private let correctType = MLS.RFC9420.ExtensionType(rawValue: 0xF0A3)

	private func recorded(_ group: MLS.RFC9420.Group?) throws -> SessionProfile {
		try SessionProfile.recorded(in: try XCTUnwrap(group).context)
	}

	private func advertises(_ leaf: MLS.RFC9420.LeafNode) -> Bool {
		leaf.capabilities.extensions.contains(correctType)
	}

	// MARK: - Key packages

	/// Kills: the classical leaf not advertising when opted in; the PQ leaf
	/// advertising; the default (no opt-in) advertising anything.
	func testKeyPackagesAdvertiseOnTheClassicalLeafOnly() throws {
		let quiet = try Principal.generate(
			clientID: Data("kp".utf8), classicalProvider: classicalProvider,
			pqProvider: pqProvider)
		let quietKP = try XCTUnwrap(
			quiet.generateInvitation(lastResort: false).invitation.combinerKeyPackage)
		XCTAssertFalse(advertises(quietKP.classical.leafNode))

		let loud = try SessionTestSupport.principal("kp-loud", profile: .correct)
		let kp = try XCTUnwrap(
			loud.generateInvitation(lastResort: false).invitation.combinerKeyPackage)
		XCTAssertTrue(advertises(kp.classical.leafNode))
		XCTAssertFalse(advertises(kp.pq.leafNode))
		let reparsed = try XCTUnwrap(CombinerKeyPackage(publishedBlob: kp.publishedBlob()))
		XCTAssertTrue(advertises(reparsed.classical.leafNode))
	}

	/// Founding leaves follow the party's own classical key package. Kills:
	/// founding leaves not advertising in a correct session.
	func testFoundingLeavesFollowTheOwnKeyPackage() throws {
		let (alice, bob) = try SessionTestSupport.establishedAndExchanged(profile: .correct)
		XCTAssertTrue(
			advertises(try TwoMLSSession.ownLeaf(of: try XCTUnwrap(alice.sendGroup).classical)))
		XCTAssertTrue(
			advertises(try TwoMLSSession.ownLeaf(of: try XCTUnwrap(bob.sendGroup).classical)))
		XCTAssertFalse(
			advertises(try TwoMLSSession.ownLeaf(of: try XCTUnwrap(alice.sendGroup?.pq))))
	}

	// MARK: - Negotiation and record

	/// Kills: not recording; not mirroring; recording on a PQ half.
	func testBothAdvertiseRecordsTheCorrectProfileOnBothClassicalHalves() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged(profile: .correct)
		XCTAssertEqual(try recorded(alice.sendGroup?.classical), .correct)
		XCTAssertEqual(try recorded(bob.recvGroup?.classical), .correct)
		XCTAssertEqual(try recorded(bob.sendGroup?.classical), .correct)
		XCTAssertEqual(try recorded(alice.recvGroup?.classical), .correct)
		XCTAssertEqual(try recorded(alice.sendGroup?.pq), .deployedCompatible)
		XCTAssertEqual(alice.profile, .correct)
		XCTAssertEqual(bob.profile, .correct)

		let kp = try alice.pqBootstrapBegin().frame
		_ = try alice.pqBootstrapJoin(try bob.pqBootstrapRespond(kp).frame)
		XCTAssertEqual(try recorded(bob.sendGroup?.pq), .deployedCompatible)
		XCTAssertEqual(try recorded(alice.recvGroup?.pq), .deployedCompatible)
	}

	/// Kills: recording when only one key package advertises.
	func testOneSidedAdvertRecordsNothing() throws {
		for (aliceProfile, bobProfile) in [
			(SessionProfile.correct, SessionProfile.deployedCompatible),
			(.deployedCompatible, .correct),
		] {
			let alicePrincipal = try SessionTestSupport.principal("os-a", profile: aliceProfile)
			let bobPrincipal = try SessionTestSupport.principal("os-b", profile: bobProfile)
			var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: true)
			let initiated = try TwoMLSSession.initiate(
				principal: alicePrincipal, their: try XCTUnwrap(invitation.combinerKeyPackage))
			XCTAssertEqual(
				try recorded(initiated.session.sendGroup?.classical), .deployedCompatible)
			let bob = try invitation.receive(
				welcome: initiated.welcome,
				theirClassicalKeyPackage: initiated.session.identity.keyPackage.classical,
				bootstrapKPCommitment: try initiated.session.bootstrapKPCommitment(),
				spawnToken: Data("s".utf8)
			).session
			XCTAssertEqual(bob.profile, .deployedCompatible)
		}
	}

	// MARK: - The acceptor's check

	/// A Group_A welcome built by hand, with `classicalExtra` on its
	/// classical half.
	private func forgedWelcomeA(
		alice: TwoMLSIdentity, bob: TwoMLSIdentity,
		classicalExtra: [MLS.RFC9420.Extension]
	) throws -> Data {
		func half(
			_ leaf: FoundingLeaf, peer: MLS.RFC9420.KeyPackage,
			_ provider: any MLS.CipherSuiteProvider
		) throws -> MLS.Combiner.HalfCreation {
			MLS.Combiner.HalfCreation(
				groupID: provider.randomBytes(provider.hashSize), leafNode: leaf.leafNode,
				leafSecretKey: leaf.leafSecretKey, signingKey: leaf.key.signingKey,
				epochSecret: SecretBytes(randomByteCount: provider.hashSize),
				randomness: try .generate(provider), peerKeyPackage: peer)
		}
		let classical = try TwoMLSIdentity.mintFoundingLeaf(
			clientID: alice.clientID, provider: classicalProvider,
			capabilities: TwoMLSIdentity.leafCapabilities(advertising: [.correct]))
		let pq = try TwoMLSIdentity.mintFoundingLeaf(clientID: alice.clientID, provider: pqProvider)
		let (_, welcome) = try MLS.Combiner.CombinerGroup.establish(
			classical: try half(classical, peer: bob.keyPackage.classical, classicalProvider),
			pq: try half(pq, peer: bob.keyPackage.pq, pqProvider), mode: 0,
			classicalProvider: classicalProvider, pqProvider: pqProvider,
			classicalExtraExtensions: classicalExtra)
		return Frames.encodeAPQWelcome(
			t: try EstablishmentMessages.encodeWelcome(welcome.tWelcome),
			pq: try EstablishmentMessages.encodeWelcome(welcome.pqWelcome))
	}

	private func assertReceiveRejects(
		alice: TwoMLSIdentity, bob: TwoMLSIdentity, welcome: Data,
		file: StaticString = #filePath, line: UInt = #line
	) {
		XCTAssertThrowsError(
			try TwoMLSSession.receive(
				identity: bob, welcome: welcome,
				theirClassicalKeyPackage: alice.keyPackage.classical,
				bootstrapKPCommitment: Data(repeating: 0, count: 32),
				classicalProvider: classicalProvider, pqProvider: pqProvider),
			file: file, line: line
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .sessionProfileMismatch, file: file, line: line)
		}
	}

	/// Kills: dropping the acceptor's comparison (either direction).
	func testAcceptorRejectsARecordItsOwnComputationDisagreesWith() throws {
		let record = SessionProfile.correct.recordExtensions
		// Recorded, but the acceptor's key package does not advertise.
		let aliceC = try SessionTestSupport.identity("ac-a", profile: .correct)
		let bobQuiet = try SessionTestSupport.identity("ac-b")
		assertReceiveRejects(
			alice: aliceC, bob: bobQuiet,
			welcome: try forgedWelcomeA(alice: aliceC, bob: bobQuiet, classicalExtra: record))
		// Recorded, but the initiator's return key package does not advertise.
		let aliceQuiet = try SessionTestSupport.identity("ac-a2")
		let bobC = try SessionTestSupport.identity("ac-b2", profile: .correct)
		assertReceiveRejects(
			alice: aliceQuiet, bob: bobC,
			welcome: try forgedWelcomeA(alice: aliceQuiet, bob: bobC, classicalExtra: record))
		// Both advertise, but the record was stripped.
		let aliceC3 = try SessionTestSupport.identity("ac-a3", profile: .correct)
		let bobC3 = try SessionTestSupport.identity("ac-b3", profile: .correct)
		assertReceiveRejects(
			alice: aliceC3, bob: bobC3,
			welcome: try forgedWelcomeA(alice: aliceC3, bob: bobC3, classicalExtra: []))
		// Control: the genuine record is accepted.
		XCTAssertNoThrow(
			try TwoMLSSession.receive(
				identity: bobC3,
				welcome: try forgedWelcomeA(alice: aliceC3, bob: bobC3, classicalExtra: record),
				theirClassicalKeyPackage: aliceC3.keyPackage.classical,
				bootstrapKPCommitment: Data(repeating: 0, count: 32),
				classicalProvider: classicalProvider, pqProvider: pqProvider))
	}

	/// Kills: `recorded(in:)` ignoring contents or duplicates.
	func testMalformedRecordIsRejected() throws {
		let alice = try SessionTestSupport.identity("mr-a", profile: .correct)
		let bob = try SessionTestSupport.identity("mr-b", profile: .correct)
		let withContents = [MLS.RFC9420.Extension(type: correctType, data: Data([1]))]
		assertReceiveRejects(
			alice: alice, bob: bob,
			welcome: try forgedWelcomeA(alice: alice, bob: bob, classicalExtra: withContents))
		let twice =
			SessionProfile.correct.recordExtensions + SessionProfile.correct.recordExtensions
		XCTAssertThrowsError(
			try SessionProfile.recorded(
				in: MLS.RFC9420.GroupContext(
					version: .mls10, cipherSuite: classicalProvider.cipherSuite,
					groupID: Data([1]), epoch: 0, treeHash: Data(),
					confirmedTranscriptHash: Data(), extensions: twice))
		) { XCTAssertEqual($0 as? TwoMLSError, .sessionProfileMismatch) }
	}

	/// A rejected welcome consumes nothing: a single-use invitation still
	/// accepts the genuine one. Kills: checking after the invitation claims.
	func testRejectedRecordLeavesTheInvitationUnconsumed() throws {
		let bobPrincipal = try SessionTestSupport.principal("inv-b")
		var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: false)
		let their = try XCTUnwrap(invitation.combinerKeyPackage)
		let alice = try SessionTestSupport.identity("inv-a", profile: .correct)
		let bobIdentity = try XCTUnwrap(invitation.identity)
		let forged = try forgedWelcomeA(
			alice: alice, bob: bobIdentity,
			classicalExtra: SessionProfile.correct.recordExtensions)
		XCTAssertThrowsError(
			try invitation.receive(
				welcome: forged, theirClassicalKeyPackage: alice.keyPackage.classical,
				bootstrapKPCommitment: Data(repeating: 0, count: 32),
				spawnToken: Data("f".utf8))
		) { XCTAssertEqual($0 as? TwoMLSError, .sessionProfileMismatch) }
		let genuine = try TwoMLSSession.initiate(
			identity: alice, their: their, classicalProvider: classicalProvider,
			pqProvider: pqProvider)
		XCTAssertNoThrow(
			try invitation.receive(
				welcome: genuine.welcome, theirClassicalKeyPackage: alice.keyPackage.classical,
				bootstrapKPCommitment: try genuine.session.bootstrapKPCommitment(),
				spawnToken: Data("g".utf8)))
	}

	// MARK: - The initiator's check

	/// Kills: dropping the return-welcome comparison.
	func testInitiatorRejectsAReturnWelcomeThatDropsOrAddsTheRecord() throws {
		// Both advertise (recorded: correct), or only alice does (recorded:
		// nothing) — alice's return key package advertises either way.
		for (bobProfile, forgedRecord) in [
			(SessionProfile.correct, SessionProfile.deployedCompatible),
			(.deployedCompatible, .correct),
		] {
			let profile = bobProfile
			let alicePrincipal = try SessionTestSupport.principal("rw-a", profile: .correct)
			let bobPrincipal = try SessionTestSupport.principal("rw-b", profile: bobProfile)
			var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: true)
			let initiated = try TwoMLSSession.initiate(
				principal: alicePrincipal, their: try XCTUnwrap(invitation.combinerKeyPackage))
			var alice = initiated.session
			var bob = try invitation.receive(
				welcome: initiated.welcome,
				theirClassicalKeyPackage: alice.identity.keyPackage.classical,
				bootstrapKPCommitment: try alice.bootstrapKPCommitment(),
				spawnToken: Data("rw".utf8)
			).session
			XCTAssertEqual(alice.profile, bobProfile)
			_ = try bob.prepareToEncrypt()
			let genuine = try bob.encrypt(Data("b1".utf8)).frame
			let (_, proposal, app) = try Frames.decodeMessageFrame(alice.openOrRaw(genuine))

			var groupA = try XCTUnwrap(alice.sendGroup)
			let crossPSK = try MLS.Combiner.ExportedPsk.export(
				from: &groupA.classical, classicalProvider,
				componentID: TwoMLSSession.crossPartyComponentID)
			let founding = try TwoMLSIdentity.mintFoundingLeaf(
				clientID: Data("rw-b".utf8), provider: classicalProvider,
				capabilities: TwoMLSIdentity.leafCapabilities(advertising: [.correct]))
			let (_, welcomeB) = try APQGroup.establishClassicalOnly(
				founder: MLS.Combiner.HalfCreation(
					groupID: classicalProvider.randomBytes(classicalProvider.hashSize),
					leafNode: founding.leafNode, leafSecretKey: founding.leafSecretKey,
					signingKey: founding.key.signingKey,
					epochSecret: SecretBytes(randomByteCount: classicalProvider.hashSize),
					randomness: try .generate(classicalProvider),
					peerKeyPackage: alice.identity.keyPackage.classical),
				pqGroupID: pqProvider.randomBytes(pqProvider.hashSize), crossPSK: crossPSK,
				nonce: classicalProvider.randomBytes(classicalProvider.hashSize),
				provider: classicalProvider, profile: forgedRecord)
			let staple = Frames.encodeAPQWelcome(
				t: try EstablishmentMessages.encodeWelcome(welcomeB), pq: Data())
			let forged = Frames.encodeMessageFrame(staple: staple, proposal: proposal, app: app)
			XCTAssertThrowsError(try alice.processIncoming(forged)) {
				XCTAssertEqual($0 as? TwoMLSError, .sessionProfileMismatch, "\(profile)")
			}
			XCTAssertNil(alice.recvGroup)
			_ = try alice.processIncomingDecrypted(genuine)
			XCTAssertTrue(alice.isEstablished)
		}
	}

	// MARK: - Leaves keep advertising

	/// A peer's replacement leaf in a correct session's classical group
	/// without the type. Kills: dropping the approval check or the fold check.
	func testReplacementLeafMustKeepAdvertising() throws {
		for profile in [SessionProfile.correct, .deployedCompatible] {
			for atFold in [false, true] {
				var (alice, bob, _, _, _, _) = try SessionTestSupport.established(
					alice: "ka-a", bob: "ka-b", profile: profile)
				_ = try bob.prepareToEncrypt()
				let send = try XCTUnwrap(bob.sendGroup).classical
				let aliceIndex = try XCTUnwrap(
					send.tree.nonBlankLeaves().first { $0.index != send.myLeafIndex }?.index)
				var leaf = try MLS.RFC9420.LeafNode(
					mlsEncoded: try XCTUnwrap(send.tree.leaf(at: aliceIndex)).encoded)
				leaf.encryptionKey = try classicalProvider.hpkeGenerateKeyPair().1
				leaf.capabilities = TwoMLSIdentity.leafCapabilities
				leaf.source = .update
				let key = alice.identity.signingKey
				leaf.signature = try MLS.signWithLabel(
					classicalProvider, privateKey: key, label: "LeafNodeTBS",
					content: try leaf.toBeSigned(
						placement: .inGroup(groupID: send.context.groupID, leafIndex: aliceIndex)))
				let pub = try MLS.RFC9420.protectPublic(
					classicalProvider,
					content: MLS.RFC9420.FramedContent(
						groupID: send.context.groupID, epoch: send.context.epoch,
						sender: .member(aliceIndex), authenticatedData: Data(),
						content: .proposal(.update(leaf))),
					groupContext: send.context, confirmationTag: nil, signingKey: key,
					membershipKey: send.epoch.membershipKey)
				let message = try MLS.RFC9420.Message.publicMessage(pub).mlsEncoded()
				let digest = classicalProvider.randomBytes(8)
				let offered = (digest: digest, proposing: Data("ka-a".utf8), message: message)
				let attempt: () throws -> Void
				if atFold {
					bob.queuedProposal = offered
					attempt = { _ = try bob.prepareToEncrypt() }
				} else {
					bob.offeredProposal = offered
					attempt = { _ = try bob.queueProposal(digest: digest) }
				}
				if profile == .correct {
					XCTAssertThrowsError(try attempt()) {
						XCTAssertEqual($0 as? TwoMLSError, .leafCapabilityUnadvertised)
					}
				} else {
					XCTAssertNoThrow(try attempt(), "fold: \(atFold)")
				}
				_ = alice
			}
		}
	}

	// MARK: - PQ halves record none

	/// Kills: the PQ-half check inside `verifyPQHalfUnbound` accepting a
	/// record.
	func testPQHalfRecordIsRejected() throws {
		let (leaf, secret, _) = try TwoMLSIdentity.mintFoundingLeaf(
			clientID: Data("pqr-a".utf8), provider: pqProvider)
		let group = try MLS.RFC9420.Group.create(
			pqProvider, groupID: Data([7]), leafNode: leaf, leafSecretKey: secret,
			extensions: SessionProfile.correct.recordExtensions,
			epochSecret: SecretBytes(randomByteCount: pqProvider.hashSize))
		XCTAssertThrowsError(try verifyPQHalfUnbound(group)) {
			XCTAssertEqual($0 as? TwoMLSError, .sessionProfileMismatch)
		}
		XCTAssertNoThrow(try verifyPQHalfUnbound(nil))
	}

	// MARK: - Running the profile

	/// C1: the correct profile announces nothing on an id-changing A.5.
	/// Kills: `profile` not reading the record.
	func testCorrectProfileAnnouncesNothing() throws {
		for profile in [SessionProfile.correct, .deployedCompatible] {
			var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob(profile: profile)
			let bob2 = Data("bob-2".utf8)
			_ = try bob.prepareToEncrypt(rotating: bob2)
			let offer = try bob.encrypt(Data("offer".utf8)).frame
			if case .initiating = bob.pqInflight {
				bob.pqInflight = nil
				bob.pendingSideBand = nil
			}
			let decrypted = try alice.processIncomingDecrypted(offer)
			_ = try alice.queueProposal(digest: decrypted.queuedProposal.digest)
			_ = try alice.prepareToEncrypt()
			_ = try bob.processIncomingDecrypted(try alice.encrypt(Data("fold".utf8)).frame)
			let begin = try bob.pqRekeyBegin()
			let updBytes = try Frames.decodePQRekeyUpd(alice.openOrRaw(begin.frame))
			guard case .publicMessage(let pub) = try MLS.RFC9420.Message(mlsEncoded: updBytes)
			else { return XCTFail("expected a publicMessage Upd'") }
			XCTAssertEqual(
				pub.content.authenticatedData, profile == .correct ? Data() : bob2, "\(profile)")
			// The responder hint is leaf-derived, so it is the same in both.
			XCTAssertEqual(try alice.pqRekeyRespond(begin.frame).rotatedCredential, bob2)
		}
	}

	/// C2: the correct profile opens the reciprocal A.5 as soon as the
	/// peer's leaf lags. Kills: `profile` not reading the record.
	func testCorrectProfileOpensTheReciprocalAtOnce() throws {
		for profile in [SessionProfile.correct, .deployedCompatible] {
			var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob(profile: profile)
			_ = try alice.prepareToEncrypt(rotating: Data("alice-2".utf8))
			let offer = try alice.encrypt(Data("offer".utf8)).frame
			let decrypted = try bob.processIncomingDecrypted(offer)
			_ = try bob.queueProposal(digest: decrypted.queuedProposal.digest)
			_ = try bob.prepareToEncrypt()
			let fold = try bob.encrypt(Data("fold".utf8)).frame
			if case .initiating = bob.pqInflight {
				bob.pqInflight = nil
				bob.pendingSideBand = nil
			}
			_ = try alice.processIncomingDecrypted(fold)
			_ = try alice.prepareToEncrypt()
			_ = try bob.processIncomingDecrypted(try alice.encrypt(Data("ack".utf8)).frame)
			_ = try bob.prepareToEncrypt()
			_ = try bob.encrypt(Data("turn".utf8))
			switch (profile, bob.pqInflight) {
			case (.correct, .some(.rekeyInitiated)), (.deployedCompatible, .some(.initiating)):
				break
			default:
				XCTFail("\(profile): unexpected \(String(describing: bob.pqInflight))")
			}
		}
	}

	/// The profile is derived from the group, so it survives a restore.
	func testProfileSurvivesRestore() throws {
		var (alice, _) = try SessionTestSupport.establishedAndExchanged(profile: .correct)
		let checkpoint = try alice.stateUpdate(kind: .checkpoint).archive
		let restored = try TwoMLSSession.restore(
			core: nil, checkpoint: checkpoint,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
		XCTAssertEqual(restored.profile, SessionProfile.correct)
	}
}
