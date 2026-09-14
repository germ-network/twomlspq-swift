import Foundation
import MLSCodec
import MLSCrypto
import MLSExtensions
import MLSProfileRFC9420
import MLSTreeMath
import SecretBytes
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
			epochSecret: SecretBytes(randomByteCount: provider.hashSize))
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
			epochSecret: SecretBytes(randomByteCount: provider.hashSize))
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

	// MARK: - validateInlineProposals

	/// Non-vacuous sanity check: a proposal list carrying exactly the
	/// permitted application/external ids passes — so the rejections below
	/// are demonstrably about the specific id/type under test, not the
	/// function rejecting everything.
	func testValidateInlineProposalsAcceptsExactlyTheExpectedSet() throws {
		let componentID = MLS.Extensions.ComponentID(rawValue: 0xFF01)
		let applicationIdentifier = MLS.RFC9420.PreSharedKeyIdentifier.application(
			componentID: componentID, pskID: Data("app-id".utf8), nonce: Data("n1".utf8)
		)
		let applicationStorageID = try XCTUnwrap(
			try applicationIdentifier.applicationStorageID())
		let externalID = Data("ext-id".utf8)
		let proposals: [MLS.RFC9420.ProposalOrRef] = [
			.proposal(.preSharedKey(applicationIdentifier)),
			.proposal(
				.preSharedKey(.external(pskID: externalID, nonce: Data("n2".utf8)))),
		]
		XCTAssertNoThrow(
			try TwoPartyRules.validateInlineProposals(
				proposals,
				expectedApplicationStorageIDs: [applicationStorageID],
				expectedExternalPSKIDs: [externalID],
				allowAttestation: false))
	}

	/// The exact-id tightening: an `application` PSK of a permitted
	/// COMPONENT (`0xFF01`, the `apq_psk` component) but a pskID not in the
	/// expected set — i.e. not the storage id the caller actually derived —
	/// is rejected, not merely type-checked.
	func testValidateInlineProposalsRejectsApplicationPSKNotInExpectedSet() throws {
		let componentID = MLS.Extensions.ComponentID(rawValue: 0xFF01)
		let expectedIdentifier = MLS.RFC9420.PreSharedKeyIdentifier.application(
			componentID: componentID, pskID: Data("expected-id".utf8),
			nonce: Data("n1".utf8))
		let expectedStorageID = try XCTUnwrap(
			try expectedIdentifier.applicationStorageID())
		let wrongIdentifier = MLS.RFC9420.PreSharedKeyIdentifier.application(
			componentID: componentID, pskID: Data("wrong-id".utf8),
			nonce: Data("n2".utf8))
		let proposals: [MLS.RFC9420.ProposalOrRef] = [
			.proposal(.preSharedKey(wrongIdentifier))
		]
		XCTAssertThrowsError(
			try TwoPartyRules.validateInlineProposals(
				proposals,
				expectedApplicationStorageIDs: [expectedStorageID],
				expectedExternalPSKIDs: [],
				allowAttestation: false)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .unexpectedProposal)
		}
	}

	func testValidateInlineProposalsRejectsExternalPSKNotInExpectedSet() {
		let proposals: [MLS.RFC9420.ProposalOrRef] = [
			.proposal(
				.preSharedKey(
					.external(pskID: Data("wrong".utf8), nonce: Data("n".utf8)))
			)
		]
		XCTAssertThrowsError(
			try TwoPartyRules.validateInlineProposals(
				proposals, expectedApplicationStorageIDs: [],
				expectedExternalPSKIDs: [Data("expected".utf8)],
				allowAttestation: false)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .unexpectedProposal)
		}
	}

	func testValidateInlineProposalsRejectsResumptionPSK() {
		let resumption = MLS.RFC9420.ResumptionPSK(
			usage: .application, groupID: Data("g".utf8), epoch: 1)
		let proposals: [MLS.RFC9420.ProposalOrRef] = [
			.proposal(.preSharedKey(.resumption(resumption, nonce: Data("n".utf8))))
		]
		XCTAssertThrowsError(
			try TwoPartyRules.validateInlineProposals(
				proposals, expectedApplicationStorageIDs: [],
				expectedExternalPSKIDs: [],
				allowAttestation: false)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .unexpectedProposal)
		}
	}

	func testValidateInlineProposalsRejectsGroupContextExtensions() {
		let proposals: [MLS.RFC9420.ProposalOrRef] = [
			.proposal(.groupContextExtensions([]))
		]
		XCTAssertThrowsError(
			try TwoPartyRules.validateInlineProposals(
				proposals, expectedApplicationStorageIDs: [],
				expectedExternalPSKIDs: [],
				allowAttestation: false)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .unexpectedProposal)
		}
	}

	func testValidateInlineProposalsRejectsAttestationWhenNotAllowed() {
		let proposals: [MLS.RFC9420.ProposalOrRef] = [
			.proposal(.custom(type: .init(.appDataUpdate), body: Data()))
		]
		XCTAssertThrowsError(
			try TwoPartyRules.validateInlineProposals(
				proposals, expectedApplicationStorageIDs: [],
				expectedExternalPSKIDs: [],
				allowAttestation: false)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .unexpectedProposal)
		}
	}

	func testValidateInlineProposalsAcceptsAttestationWhenAllowed() {
		let proposals: [MLS.RFC9420.ProposalOrRef] = [
			.proposal(.custom(type: .init(.appDataUpdate), body: Data()))
		]
		XCTAssertNoThrow(
			try TwoPartyRules.validateInlineProposals(
				proposals, expectedApplicationStorageIDs: [],
				expectedExternalPSKIDs: [],
				allowAttestation: true))
	}
}
