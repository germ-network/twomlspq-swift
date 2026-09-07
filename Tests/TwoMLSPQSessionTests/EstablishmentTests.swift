import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSExtensions
import MLSProfileRFC9420
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
		try withDeployedWireWidth {
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

		let (_, otherBobSession, _, _, _, _) = try SessionTestSupport.established(
			alice: "alice-intruder", bob: "bob-intruder")
		var otherBob = otherBobSession
		_ = try otherBob.prepareToEncrypt()
		let intruderFrame = try otherBob.encrypt(Data("intruder".utf8))

		XCTAssertThrowsError(try alice.processIncoming(intruderFrame)) { error in
			XCTAssertEqual(error as? TwoMLSError, .unexpectedWelcome)
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
		let realFrame = try bob.encrypt(Data("payload".utf8))
		let (_, _, appSection) = try Frames.decodeMessageFrame(realFrame)

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
}
