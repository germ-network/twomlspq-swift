import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes
import TwoMLSPQCrypto
import XCTest

@testable import TwoMLSPQSession

/// Germ AS policy (two distinct principals, not RFC 9420- or book-mandated):
/// the peer this session establishes against, or later rotates to, can never
/// legitimately be this device's own identity.
@available(iOS 26, macOS 26, *)
final class OwnIdentityRejectionTests: XCTestCase {
	/// `initiate`'s "their" naming the initiator's own id — rejected before
	/// any group is built.
	func testInitiateRejectsAnOwnIDPeer() throws {
		let identity = try SessionTestSupport.identity("own-id-initiate")
		XCTAssertThrowsError(
			try TwoMLSSession.initiate(
				identity: identity, their: identity.keyPackage,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .remoteIdentityMismatch)
		}
	}

	/// `receive`'s own joined-creator own-id guard: a joiner built with the
	/// creator's own `clientID` (but its own keys/key packages) reaches the
	/// guard on the joined tree directly, without going through
	/// `initiate`'s own-id guard first.
	func testReceiveRejectsAJoinedCreatorNamingOwnID() throws {
		let alice = try SessionTestSupport.identity("own-id-receive-alice")
		let bob = try SessionTestSupport.identity("own-id-receive-bob")
		let initiated = try TwoMLSSession.initiate(
			identity: alice, their: bob.keyPackage,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		let mallory = TwoMLSIdentity(
			clientID: alice.clientID, signingKey: bob.signingKey,
			signatureKey: bob.signatureKey,
			pqSigningKey: bob.pqSigningKey, pqSignatureKey: bob.pqSignatureKey,
			classicalLeafSecretKey: bob.classicalLeafSecretKey,
			classicalInitSecretKey: bob.classicalInitSecretKey,
			pqLeafSecretKey: bob.pqLeafSecretKey, pqInitSecretKey: bob.pqInitSecretKey,
			keyPackage: bob.keyPackage)
		XCTAssertThrowsError(
			try TwoMLSSession.receive(
				identity: mallory, welcome: initiated.welcome,
				theirClassicalKeyPackage: alice.keyPackage.classical,
				bootstrapKPCommitment: try initiated.session
					.bootstrapKPCommitment(),
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .remoteIdentityMismatch)
		}
	}

	/// `prepareToEncrypt(rotating:)` naming one of the PEER's own known
	/// ids — rejected before any candidate is minted or authorized.
	func testPrepareToEncryptRejectsRotatingToAPeerID() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged(
			alice: "own-id-rotate-alice", bob: "own-id-rotate-bob")
		let peerID = bob.identity.clientID
		XCTAssertTrue(alice.auth.theirs.knownIDs.contains(peerID))

		let candidateBefore = alice.rotationCandidate
		let authorizedBefore = alice.auth.mine.authorizedNext

		XCTAssertThrowsError(try alice.prepareToEncrypt(rotating: peerID)) { error in
			XCTAssertEqual(error as? TwoMLSError, .invalidSuccession)
		}
		XCTAssertNil(alice.rotationCandidate)
		XCTAssertEqual(
			alice.rotationCandidate?.clientID, candidateBefore?.clientID,
			"no candidate was minted")
		XCTAssertEqual(
			alice.auth.mine.authorizedNext, authorizedBefore,
			"no authorization was added")
	}
}
