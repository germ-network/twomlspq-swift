import Foundation
import MLSCodec
import MLSCrypto
import MLSProfileRFC9420
import MLSTreeMath
import XCTest

@testable import TwoMLSPQSession

@available(iOS 26, macOS 26, *)
final class TwoPartyRulesTests: XCTestCase {
	// MARK: - ensureTwoParty

	func testEnsureTwoPartyAcceptsTwoMembers() throws {
		let (_, bob, _, _, _, _) = try SessionTestSupport.established()
		let groupA = try XCTUnwrap(bob.recvGroup)
		XCTAssertNoThrow(try TwoPartyRules.ensureTwoParty(groupA.classical))
	}

	func testEnsureTwoPartyRejectsOneMember() throws {
		let alice = try SessionTestSupport.identity("solo-alice")
		let provider = SessionTestSupport.classicalProvider
		let group = try MLS.RFC9420.Group.create(
			provider, groupID: provider.randomBytes(provider.hashSize),
			leafNode: alice.keyPackage.classical.leafNode,
			leafSecretKey: alice.classicalLeafSecretKey,
			epochSecret: provider.randomBytes(provider.hashSize))
		XCTAssertThrowsError(try TwoPartyRules.ensureTwoParty(group)) { error in
			XCTAssertEqual(error as? TwoMLSError, .notTwoParty(count: 1))
		}
	}

	func testEnsureTwoPartyRejectsThreeMembers() throws {
		let alice = try SessionTestSupport.identity("trio-alice")
		let bob = try SessionTestSupport.identity("trio-bob")
		let carol = try SessionTestSupport.identity("trio-carol")
		let provider = SessionTestSupport.classicalProvider

		let epoch0 = try MLS.RFC9420.Group.create(
			provider, groupID: provider.randomBytes(provider.hashSize),
			leafNode: alice.keyPackage.classical.leafNode,
			leafSecretKey: alice.classicalLeafSecretKey,
			epochSecret: provider.randomBytes(provider.hashSize))
		let transition = try epoch0.committing(
			provider,
			proposals: [
				.proposal(.add(bob.keyPackage.classical)),
				.proposal(.add(carol.keyPackage.classical)),
			],
			signingKey: alice.signingKey, randomness: try .generate(provider))
		let adopted = transition.group
		let advanced = try transition.takeOutput().takePending().apply(onto: adopted)

		XCTAssertThrowsError(try TwoPartyRules.ensureTwoParty(advanced.group)) { error in
			XCTAssertEqual(error as? TwoMLSError, .notTwoParty(count: 3))
		}
	}

	// MARK: - validateCreationProposals

	func testValidateCreationProposalsAcceptsAddPlusPSK() throws {
		let bob = try SessionTestSupport.identity("guard-bob")
		let proposals: [MLS.RFC9420.ProposalOrRef] = [
			.proposal(.add(bob.keyPackage.classical)),
			.proposal(
				.preSharedKey(
					.external(pskID: Data("x".utf8), nonce: Data("n".utf8)))),
		]
		XCTAssertNoThrow(try TwoPartyRules.validateCreationProposals(proposals))
	}

	func testValidateCreationProposalsRejectsTwoAdds() throws {
		let bob = try SessionTestSupport.identity("guard-bob-2")
		let carol = try SessionTestSupport.identity("guard-carol-2")
		let proposals: [MLS.RFC9420.ProposalOrRef] = [
			.proposal(.add(bob.keyPackage.classical)),
			.proposal(.add(carol.keyPackage.classical)),
		]
		XCTAssertThrowsError(try TwoPartyRules.validateCreationProposals(proposals)) {
			error in
			XCTAssertEqual(error as? TwoMLSError, .invalidCreationProposals)
		}
	}

	func testValidateCreationProposalsRejectsRemove() {
		let proposals: [MLS.RFC9420.ProposalOrRef] = [
			.proposal(.remove(MLS.LeafIndex(value: 0)))
		]
		XCTAssertThrowsError(try TwoPartyRules.validateCreationProposals(proposals)) {
			error in
			XCTAssertEqual(error as? TwoMLSError, .invalidCreationProposals)
		}
	}
}
