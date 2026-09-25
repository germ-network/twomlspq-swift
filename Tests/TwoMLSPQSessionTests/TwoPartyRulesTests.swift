import Foundation
import MLSCodec
import MLSCrypto
import MLSExtensions
import MLSProfileRFC9420
import MLSTreeMath
import SecretBytes
import Testing

@testable import TwoMLSPQSession

@Suite struct TwoPartyRulesTests {
	// MARK: - ensureTwoParty

	@available(iOS 26, macOS 26, *)
	@Test func ensureTwoPartyAcceptsTwoMembers() throws {
		let (_, bob, _, _, _, _) = try SessionTestSupport.established()
		let groupA = try #require(bob.recvGroup)
		#expect(throws: Never.self) {
			try TwoPartyRules.ensureTwoParty(groupA.classical)
		}
	}

	@available(iOS 26, macOS 26, *)
	@Test func ensureTwoPartyRejectsOneMember() throws {
		let alice = try SessionTestSupport.identity("solo-alice")
		let provider = SessionTestSupport.classicalProvider
		let group = try MLS.RFC9420.Group.create(
			provider, groupID: provider.randomBytes(provider.hashSize),
			leafNode: alice.keyPackage.classical.leafNode,
			leafSecretKey: alice.classicalLeafSecretKey,
			epochSecret: SecretBytes(randomByteCount: provider.hashSize))
		#expect(throws: TwoMLSError.notTwoParty(count: 1)) {
			try TwoPartyRules.ensureTwoParty(group)
		}
	}

	@available(iOS 26, macOS 26, *)
	@Test func ensureTwoPartyRejectsThreeMembers() throws {
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

		#expect(throws: TwoMLSError.notTwoParty(count: 3)) {
			try TwoPartyRules.ensureTwoParty(advanced.group)
		}
	}

	// MARK: - validateCreationProposals

	@available(iOS 26, macOS 26, *)
	@Test func validateCreationProposalsAcceptsAddPlusPSK() throws {
		let bob = try SessionTestSupport.identity("guard-bob")
		let proposals: [MLS.RFC9420.ProposalOrRef] = [
			.proposal(.add(bob.keyPackage.classical)),
			.proposal(
				.preSharedKey(
					.external(pskID: Data("x".utf8), nonce: Data("n".utf8)))),
		]
		#expect(throws: Never.self) {
			try TwoPartyRules.validateCreationProposals(proposals)
		}
	}

	@available(iOS 26, macOS 26, *)
	@Test func validateCreationProposalsRejectsTwoAdds() throws {
		let bob = try SessionTestSupport.identity("guard-bob-2")
		let carol = try SessionTestSupport.identity("guard-carol-2")
		let proposals: [MLS.RFC9420.ProposalOrRef] = [
			.proposal(.add(bob.keyPackage.classical)),
			.proposal(.add(carol.keyPackage.classical)),
		]
		#expect(throws: TwoMLSError.invalidCreationProposals) {
			try TwoPartyRules.validateCreationProposals(proposals)
		}
	}

	@Test func validateCreationProposalsRejectsRemove() {
		let proposals: [MLS.RFC9420.ProposalOrRef] = [
			.proposal(.remove(MLS.LeafIndex(value: 0)))
		]
		#expect(throws: TwoMLSError.invalidCreationProposals) {
			try TwoPartyRules.validateCreationProposals(proposals)
		}
	}

	// MARK: - validateInlineProposals

	/// Non-vacuous sanity check: a proposal list carrying exactly the
	/// permitted application/external ids passes — so the rejections below
	/// are demonstrably about the specific id/type under test, not the
	/// function rejecting everything.
	@Test func validateInlineProposalsAcceptsExactlyTheExpectedSet() throws {
		let componentID = MLS.Extensions.ComponentID(rawValue: 0xFF01)
		let applicationIdentifier = MLS.RFC9420.PreSharedKeyIdentifier.application(
			componentID: componentID, pskID: Data("app-id".utf8), nonce: Data("n1".utf8)
		)
		let rawApplicationStorageID = try applicationIdentifier.applicationStorageID()
		let applicationStorageID = try #require(rawApplicationStorageID)
		let externalID = Data("ext-id".utf8)
		let proposals: [MLS.RFC9420.ProposalOrRef] = [
			.proposal(.preSharedKey(applicationIdentifier)),
			.proposal(
				.preSharedKey(.external(pskID: externalID, nonce: Data("n2".utf8)))),
		]
		#expect(throws: Never.self) {
			try TwoPartyRules.validateInlineProposals(
				proposals,
				expectedApplicationStorageIDs: [applicationStorageID],
				expectedExternalPSKIDs: [externalID],
				allowAttestation: false)
		}
	}

	/// The exact-id tightening: an `application` PSK of a permitted
	/// COMPONENT (`0xFF01`, the `apq_psk` component) but a pskID not in the
	/// expected set — i.e. not the storage id the caller actually derived —
	/// is rejected, not merely type-checked.
	@Test func validateInlineProposalsRejectsApplicationPSKNotInExpectedSet() throws {
		let componentID = MLS.Extensions.ComponentID(rawValue: 0xFF01)
		let expectedIdentifier = MLS.RFC9420.PreSharedKeyIdentifier.application(
			componentID: componentID, pskID: Data("expected-id".utf8),
			nonce: Data("n1".utf8))
		let rawExpectedStorageID = try expectedIdentifier.applicationStorageID()
		let expectedStorageID = try #require(rawExpectedStorageID)
		let wrongIdentifier = MLS.RFC9420.PreSharedKeyIdentifier.application(
			componentID: componentID, pskID: Data("wrong-id".utf8),
			nonce: Data("n2".utf8))
		let proposals: [MLS.RFC9420.ProposalOrRef] = [
			.proposal(.preSharedKey(wrongIdentifier))
		]
		#expect(throws: TwoMLSError.unexpectedProposal) {
			try TwoPartyRules.validateInlineProposals(
				proposals,
				expectedApplicationStorageIDs: [expectedStorageID],
				expectedExternalPSKIDs: [],
				allowAttestation: false)
		}
	}

	@Test func validateInlineProposalsRejectsExternalPSKNotInExpectedSet() {
		let proposals: [MLS.RFC9420.ProposalOrRef] = [
			.proposal(
				.preSharedKey(
					.external(pskID: Data("wrong".utf8), nonce: Data("n".utf8)))
			)
		]
		#expect(throws: TwoMLSError.unexpectedProposal) {
			try TwoPartyRules.validateInlineProposals(
				proposals, expectedApplicationStorageIDs: [],
				expectedExternalPSKIDs: [Data("expected".utf8)],
				allowAttestation: false)
		}
	}

	@Test func validateInlineProposalsRejectsResumptionPSK() {
		let resumption = MLS.RFC9420.ResumptionPSK(
			usage: .application, groupID: Data("g".utf8), epoch: 1)
		let proposals: [MLS.RFC9420.ProposalOrRef] = [
			.proposal(.preSharedKey(.resumption(resumption, nonce: Data("n".utf8))))
		]
		#expect(throws: TwoMLSError.unexpectedProposal) {
			try TwoPartyRules.validateInlineProposals(
				proposals, expectedApplicationStorageIDs: [],
				expectedExternalPSKIDs: [],
				allowAttestation: false)
		}
	}

	@Test func validateInlineProposalsRejectsGroupContextExtensions() {
		let proposals: [MLS.RFC9420.ProposalOrRef] = [
			.proposal(.groupContextExtensions([]))
		]
		#expect(throws: TwoMLSError.unexpectedProposal) {
			try TwoPartyRules.validateInlineProposals(
				proposals, expectedApplicationStorageIDs: [],
				expectedExternalPSKIDs: [],
				allowAttestation: false)
		}
	}

	@Test func validateInlineProposalsRejectsAttestationWhenNotAllowed() {
		let proposals: [MLS.RFC9420.ProposalOrRef] = [
			.proposal(.custom(type: .init(.appDataUpdate), body: Data()))
		]
		#expect(throws: TwoMLSError.unexpectedProposal) {
			try TwoPartyRules.validateInlineProposals(
				proposals, expectedApplicationStorageIDs: [],
				expectedExternalPSKIDs: [],
				allowAttestation: false)
		}
	}

	@Test func validateInlineProposalsAcceptsAttestationWhenAllowed() {
		let proposals: [MLS.RFC9420.ProposalOrRef] = [
			.proposal(.custom(type: .init(.appDataUpdate), body: Data()))
		]
		#expect(throws: Never.self) {
			try TwoPartyRules.validateInlineProposals(
				proposals, expectedApplicationStorageIDs: [],
				expectedExternalPSKIDs: [],
				allowAttestation: true)
		}
	}
}
