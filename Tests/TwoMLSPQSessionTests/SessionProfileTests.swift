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
}
