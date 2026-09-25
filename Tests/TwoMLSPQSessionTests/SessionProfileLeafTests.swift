import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes
import Testing

@testable import TwoMLSPQSession

// Book group-rules.md rule 9's tail: a profile-carrying group only ever
// contains leaves that advertise the recorded type.

@Suite struct SessionProfileLeafTests {
	/// Computed, not stored: `SessionTestSupport.classicalProvider` is gated
	/// to iOS/macOS 26 (the whole `SessionTestSupport` enum is), so a stored
	/// `let` initialized from it would require this ungated suite's own
	/// stored-property initializer to run in a gated context, which the
	/// compiler refuses — see `CombinerKeyPackageWireTests.makeIdentity()`.
	@available(iOS 26, macOS 26, *)
	private var classicalProvider: any MLS.CipherSuiteProvider {
		SessionTestSupport.classicalProvider
	}
	@available(iOS 26, macOS 26, *)
	private var pqProvider: any MLS.CipherSuiteProvider { SessionTestSupport.pqProvider }

	@available(iOS 26, macOS 26, *)
	private func half(
		_ leaf: FoundingLeaf, peer: MLS.RFC9420.KeyPackage,
		_ provider: any MLS.CipherSuiteProvider
	) throws -> MLS.Combiner.HalfCreation {
		MLS.Combiner.HalfCreation(
			groupID: provider.randomBytes(provider.hashSize), leafNode: leaf.leafNode,
			leafSecretKey: leaf.leafSecretKey, signingKey: leaf.key.signingKey,
			epochSecret: SecretBytes(randomByteCount: provider.hashSize),
			randomness: try .generate(provider), peerKeyPackage: peer)
	}

	/// The creation choke points refuse a correct-profile group with a
	/// non-advertising founder or peer. Kills: dropping either check in
	/// `establishFull` / `establishClassicalOnly`.
	@available(iOS 26, macOS 26, *)
	@Test func creationRefusesANonAdvertisingLeaf() throws {
		let advertising = try SessionTestSupport.identity("cr-adv", profile: .correct)
		let quiet = try SessionTestSupport.identity("cr-quiet")
		let loud = try TwoMLSIdentity.mintFoundingLeaf(
			clientID: Data("cr-f".utf8), provider: classicalProvider,
			capabilities: TwoMLSIdentity.leafCapabilities(advertising: [.correct]))
		let mute = try TwoMLSIdentity.mintFoundingLeaf(
			clientID: Data("cr-f".utf8), provider: classicalProvider)
		let pq = try TwoMLSIdentity.mintFoundingLeaf(
			clientID: Data("cr-f".utf8), provider: pqProvider)
		for (founder, peer) in [(mute, advertising), (loud, quiet)] {
			#expect(throws: TwoMLSError.leafCapabilityUnadvertised) {
				try APQGroup.establishFull(
					classical: try half(founder, peer: peer.keyPackage.classical, classicalProvider),
					pq: try half(pq, peer: peer.keyPackage.pq, pqProvider), mode: 0,
					classicalProvider: classicalProvider, pqProvider: pqProvider,
					profile: .correct)
			}

			var groupA = try APQGroup.establishFull(
				classical: try half(loud, peer: advertising.keyPackage.classical, classicalProvider),
				pq: try half(pq, peer: advertising.keyPackage.pq, pqProvider), mode: 0,
				classicalProvider: classicalProvider, pqProvider: pqProvider
			).group
			let crossPSK = try MLS.Combiner.ExportedPsk.export(
				from: &groupA.classical, classicalProvider,
				componentID: TwoMLSSession.crossPartyComponentID)
			#expect(throws: TwoMLSError.leafCapabilityUnadvertised) {
				try APQGroup.establishClassicalOnly(
					founder: try half(founder, peer: peer.keyPackage.classical, classicalProvider),
					pqGroupID: Data(repeating: 1, count: 32), crossPSK: crossPSK,
					nonce: Data(repeating: 2, count: 32), provider: classicalProvider,
					profile: .correct)
			}
		}
	}

	/// Both key packages advertise and the welcome records the profile, but
	/// the creator leaf actually in Group_A does not advertise. Kills:
	/// dropping the acceptor's creator-leaf check.
	@available(iOS 26, macOS 26, *)
	@Test func acceptorRefusesANonAdvertisingCreatorLeaf() throws {
		let alice = try SessionTestSupport.identity("cl-a", profile: .correct)
		let bob = try SessionTestSupport.identity("cl-b", profile: .correct)
		let mute = try TwoMLSIdentity.mintFoundingLeaf(
			clientID: alice.clientID, provider: classicalProvider)
		let pq = try TwoMLSIdentity.mintFoundingLeaf(clientID: alice.clientID, provider: pqProvider)
		let (_, welcome) = try MLS.Combiner.CombinerGroup.establish(
			classical: try half(mute, peer: bob.keyPackage.classical, classicalProvider),
			pq: try half(pq, peer: bob.keyPackage.pq, pqProvider), mode: 0,
			classicalProvider: classicalProvider, pqProvider: pqProvider,
			classicalExtraExtensions: SessionProfile.correct.recordExtensions)
		let frame = Frames.encodeAPQWelcome(
			t: try EstablishmentMessages.encodeWelcome(welcome.tWelcome),
			pq: try EstablishmentMessages.encodeWelcome(welcome.pqWelcome))
		#expect(throws: TwoMLSError.leafCapabilityUnadvertised) {
			try TwoMLSSession.receive(
				identity: bob, welcome: frame,
				theirClassicalKeyPackage: alice.keyPackage.classical,
				bootstrapKPCommitment: Data(repeating: 0, count: 32),
				classicalProvider: classicalProvider, pqProvider: pqProvider)
		}
	}

	/// The return welcome records the profile, but its creator leaf does not
	/// advertise. Kills: dropping the initiator's creator-leaf check.
	@available(iOS 26, macOS 26, *)
	@Test func initiatorRefusesANonAdvertisingReturnCreatorLeaf() throws {
		var (alice, bob, _, _, _, _) = try SessionTestSupport.established(
			alice: "rc-a", bob: "rc-b", profile: .correct)
		_ = try bob.prepareToEncrypt()
		let genuine = try bob.encrypt(Data("b1".utf8)).frame
		let (_, proposal, app) = try Frames.decodeMessageFrame(alice.openOrRaw(genuine))
		var groupA = try #require(alice.sendGroup)
		let crossPSK = try MLS.Combiner.ExportedPsk.export(
			from: &groupA.classical, classicalProvider,
			componentID: TwoMLSSession.crossPartyComponentID)
		let mute = try TwoMLSIdentity.mintFoundingLeaf(
			clientID: Data("rc-b".utf8), provider: classicalProvider)

		let staple: Data = try withDeployedWireConventions {
			let groupID = classicalProvider.randomBytes(classicalProvider.hashSize)
			let info = MLS.Combiner.APQInfo(
				tSessionGroupID: groupID,
				pqSessionGroupID: pqProvider.randomBytes(pqProvider.hashSize), mode: 0,
				tCipherSuite: classicalProvider.cipherSuite,
				pqCipherSuite: pqProvider.cipherSuite, tEpoch: 1, pqEpoch: epochUnbound)
			var pskStore = MLS.Combiner.PSKStore()
			pskStore.register(crossPSK)
			let epoch0 = try MLS.RFC9420.Group.create(
				classicalProvider, groupID: groupID, leafNode: mute.leafNode,
				leafSecretKey: mute.leafSecretKey,
				extensions: [
					try info.asExtension(
						type: MLS.Combiner.Codepoints.deployed.apqInfoExtensionType)
				] + SessionProfile.correct.recordExtensions,
				epochSecret: SecretBytes(randomByteCount: classicalProvider.hashSize))
			let transition = try epoch0.committing(
				classicalProvider,
				proposals: [
					.proposal(.add(alice.identity.keyPackage.classical)),
					.proposal(
						crossPSK.proposal(
							nonce: classicalProvider.randomBytes(classicalProvider.hashSize))),
				],
				signingKey: mute.key.signingKey, randomness: try .generate(classicalProvider),
				psk: pskStore.resolver())
			let sent = transition.takeOutput()
			guard let welcome = sent.welcome else { throw MLS.Combiner.Error.missingWelcome }
			return Frames.encodeAPQWelcome(
				t: try EstablishmentMessages.encodeWelcome(welcome), pq: Data())
		}
		let forged = Frames.encodeMessageFrame(staple: staple, proposal: proposal, app: app)
		#expect(throws: TwoMLSError.leafCapabilityUnadvertised) {
			try alice.processIncoming(forged)
		}
		#expect(alice.recvGroup == nil)
		_ = try alice.processIncomingDecrypted(genuine)
	}
}
