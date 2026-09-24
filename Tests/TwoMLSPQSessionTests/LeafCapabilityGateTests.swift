import Crypto
import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes
import TwoMLSPQCrypto
import XCTest

@testable import TwoMLSPQSession

/// Book `wire-format.md`: "Every occupied leaf must advertise the `APQInfo`
/// extension (`0xF0A1`) and the `AppDataUpdate` proposal (`0x0008`) types; a
/// leaf that cannot support them is rejected rather than silently degraded."
/// One test per ingress site (the send-group offer/fold/establishment
/// sites, and the recv-group join-time sites),
/// each covering both the 0x0008-missing and the 0xF0A1-missing variant,
/// asserting `.leafCapabilityUnadvertised` and that the rejected leaf never
/// took effect.
@available(iOS 26, macOS 26, *)
final class LeafCapabilityGateTests: XCTestCase {

	// MARK: - Rogue capability sets

	/// `preCutCapabilities`-style rogue sets, one per missing codepoint —
	/// otherwise a full, valid capability set (both suites, Basic
	/// credentials), so only the ONE named clause is what trips the gate.
	private enum MissingCapability: CaseIterable {
		case appDataUpdate  // missing 0x0008
		case apqInfo  // missing 0xF0A1

		var capabilities: MLS.RFC9420.Capabilities {
			switch self {
			case .appDataUpdate:
				return MLS.RFC9420.Capabilities(
					versions: [.mls10],
					cipherSuites: [TwoMLSSuite.classical, TwoMLSSuite.pq],
					extensions: [
						MLS.Combiner.Codepoints.deployed
							.apqInfoExtensionType
					],
					proposals: [],
					credentials: [MLS.RFC9420.CredentialType(.basic)])
			case .apqInfo:
				return MLS.RFC9420.Capabilities(
					versions: [.mls10],
					cipherSuites: [TwoMLSSuite.classical, TwoMLSSuite.pq],
					extensions: [],
					proposals: [MLS.RFC9420.ProposalType(.appDataUpdate)],
					credentials: [MLS.RFC9420.CredentialType(.basic)])
			}
		}
	}

	// MARK: - Rogue identity/KeyPackage construction

	/// Mirrors `TwoMLSIdentity`'s own private `signedKeyPackage`, parameterized
	/// on `capabilities` — the only difference from a genuine identity.
	private static func rogueSignedKeyPackage(
		cipherSuite: MLS.CipherSuite, provider: any MLS.CipherSuiteProvider,
		clientID: Data, signingKey: MLS.SignatureSecretKey,
		signatureKey: MLS.SignaturePublicKey, leafPublicKey: MLS.HpkePublicKey,
		initPublicKey: MLS.HpkePublicKey, capabilities: MLS.RFC9420.Capabilities
	) throws -> MLS.RFC9420.KeyPackage {
		var leaf = MLS.RFC9420.LeafNode(
			encryptionKey: leafPublicKey, signatureKey: signatureKey,
			credential: .basic(identity: clientID), capabilities: capabilities,
			source: .keyPackage(.init(notBefore: 0, notAfter: .max)),
			extensions: [], signature: Data())
		leaf.signature = try MLS.signWithLabel(
			provider, privateKey: signingKey, label: "LeafNodeTBS",
			content: try leaf.toBeSigned(placement: .keyPackage))
		var keyPackage = MLS.RFC9420.KeyPackage(
			version: .mls10, cipherSuite: cipherSuite, initKey: initPublicKey,
			leafNode: leaf, extensions: [], signature: Data())
		keyPackage.signature = try MLS.signWithLabel(
			provider, privateKey: signingKey, label: "KeyPackageTBS",
			content: try keyPackage.toBeSigned())
		return keyPackage
	}

	/// A full `TwoMLSIdentity` whose classical AND PQ leaves both carry
	/// `capabilities` instead of the real, fixed `TwoMLSIdentity.
	/// leafCapabilities` — built via the internal memberwise init (this
	/// module's own `@testable` access), since the public `generate()`
	/// factory always uses the real set.
	private static func rogueIdentity(
		_ name: String, capabilities: MLS.RFC9420.Capabilities
	) throws -> TwoMLSIdentity {
		try rogueIdentity(
			name, classicalCapabilities: capabilities, pqCapabilities: capabilities)
	}

	/// The general form: classical and PQ halves may carry DIFFERENT
	/// capability sets, so a caller can isolate which half's own gate it is
	/// exercising.
	private static func rogueIdentity(
		_ name: String, classicalCapabilities: MLS.RFC9420.Capabilities,
		pqCapabilities: MLS.RFC9420.Capabilities
	) throws -> TwoMLSIdentity {
		let clientID = Data(name.utf8)
		let classicalProvider = SessionTestSupport.classicalProvider
		let pqProvider = SessionTestSupport.pqProvider
		let (signingKey, signatureKey) = try TwoMLSIdentity.mintSignatureKeypair()
		let (pqSigningKey, pqSignatureKey) = try TwoMLSIdentity.mintSignatureKeypair()
		let (classicalLeafSecretKey, classicalLeafPublicKey) =
			try classicalProvider.hpkeGenerateKeyPair()
		let (classicalInitSecretKey, classicalInitPublicKey) =
			try classicalProvider.hpkeGenerateKeyPair()
		let (pqLeafSecretKey, pqLeafPublicKey) = try pqProvider.hpkeGenerateKeyPair()
		let (pqInitSecretKey, pqInitPublicKey) = try pqProvider.hpkeGenerateKeyPair()

		let classicalKP = try rogueSignedKeyPackage(
			cipherSuite: TwoMLSSuite.classical, provider: classicalProvider,
			clientID: clientID, signingKey: signingKey, signatureKey: signatureKey,
			leafPublicKey: classicalLeafPublicKey,
			initPublicKey: classicalInitPublicKey,
			capabilities: classicalCapabilities)
		let pqKP = try rogueSignedKeyPackage(
			cipherSuite: MLS.CipherSuite(id: MLKEM768CipherSuiteProvider.cipherSuiteID),
			provider: pqProvider, clientID: clientID, signingKey: pqSigningKey,
			signatureKey: pqSignatureKey, leafPublicKey: pqLeafPublicKey,
			initPublicKey: pqInitPublicKey, capabilities: pqCapabilities)

		return TwoMLSIdentity(
			clientID: clientID, signingKey: signingKey, signatureKey: signatureKey,
			pqSigningKey: pqSigningKey, pqSignatureKey: pqSignatureKey,
			classicalLeafSecretKey: classicalLeafSecretKey,
			classicalInitSecretKey: classicalInitSecretKey,
			pqLeafSecretKey: pqLeafSecretKey, pqInitSecretKey: pqInitSecretKey,
			keyPackage: CombinerKeyPackage(classical: classicalKP, pq: pqKP))
	}

	/// A standalone classical `KeyPackage` for `clientID` with `capabilities`
	/// — no `TwoMLSIdentity` behind it (Basic credentials carry no proof, so
	/// this is enough to stand in for "what the caller CLAIMS the peer's
	/// KeyPackage looks like").
	private static func rogueClassicalKeyPackage(
		_ name: String, capabilities: MLS.RFC9420.Capabilities
	) throws -> MLS.RFC9420.KeyPackage {
		let provider = SessionTestSupport.classicalProvider
		let (signingKey, signatureKey) = try TwoMLSIdentity.mintSignatureKeypair()
		let (_, leafPublicKey) = try provider.hpkeGenerateKeyPair()
		let (_, initPublicKey) = try provider.hpkeGenerateKeyPair()
		return try rogueSignedKeyPackage(
			cipherSuite: provider.cipherSuite, provider: provider,
			clientID: Data(name.utf8), signingKey: signingKey,
			signatureKey: signatureKey,
			leafPublicKey: leafPublicKey, initPublicKey: initPublicKey,
			capabilities: capabilities)
	}

	// MARK: - Offer approval / fold commit: forged peer Update replacing the occupied leaf

	/// Hand-forges a validly-FRAMED "Alice Update" targeting bob's send
	/// group (Group_B): the enclosing proposal is signed under Alice's REAL,
	/// currently-occupying classical key (so `Group.verifying(proposal:)`
	/// accepts the framing), but the embedded replacement leaf carries
	/// `missing`'s rogue capabilities — credential and signature key stay
	/// identical to Alice's real leaf, so this is a plain non-rotating
	/// Update. Mirrors `AppBindingTests.forgedUncapableUpdate`'s technique.
	private func forgedRogueUpdate(missing: MissingCapability) throws -> (
		committer: TwoMLSSession, message: Data, digest: Data, proposingID: Data
	) {
		let provider = SessionTestSupport.classicalProvider
		let (alice, bob, _, _, _, _) = try SessionTestSupport.established(
			alice: "cap-gate-alice-\(missing)", bob: "cap-gate-bob-\(missing)")
		var received = bob
		_ = try alice
		_ = try received.prepareToEncrypt()

		let committerSend = try XCTUnwrap(received.sendGroup).classical
		let aliceLeafIndex = try XCTUnwrap(
			committerSend.tree.nonBlankLeaves()
				.first { $0.index != committerSend.myLeafIndex }?.index)
		let realLeafRecord = try XCTUnwrap(committerSend.tree.leaf(at: aliceLeafIndex))
		let realLeaf = try MLS.RFC9420.LeafNode(mlsEncoded: realLeafRecord.encoded)

		let (_, rogueEncryptionKey) = try provider.hpkeGenerateKeyPair()
		var rogueLeaf = realLeaf
		rogueLeaf.encryptionKey = rogueEncryptionKey
		rogueLeaf.capabilities = missing.capabilities
		rogueLeaf.source = .update
		guard case .basic(let aliceID) = realLeaf.credential else {
			XCTFail("expected a Basic credential")
			throw TwoMLSError.unsupportedCredential
		}

		// Basic credentials carry no proof — sign under a fresh key that
		// merely CLAIMS Alice's id, matching `forgedUncapableUpdate`'s own
		// reasoning; the enclosing `FramedContent` below is what actually
		// carries Alice's REAL current signing key.
		let (rogueSigningKey, _) = try TwoMLSIdentity.mintSignatureKeypair()
		rogueLeaf.signature = try MLS.signWithLabel(
			provider, privateKey: rogueSigningKey, label: "LeafNodeTBS",
			content: try rogueLeaf.toBeSigned(
				placement: .inGroup(
					groupID: committerSend.context.groupID,
					leafIndex: aliceLeafIndex)))

		// The real Alice session's current send-classical signing key —
		// what actually authenticates the enclosing proposal's framing.
		var realAlice = try SessionTestSupport.established(
			alice: "cap-gate-alice-\(missing)", bob: "cap-gate-bob-\(missing)"
		).alice
		_ = realAlice
		let aliceSigningKey = try alice.sendClassicalSigningKey()

		let content = MLS.RFC9420.FramedContent(
			groupID: committerSend.context.groupID, epoch: committerSend.context.epoch,
			sender: .member(aliceLeafIndex), authenticatedData: Data(),
			content: .proposal(.update(rogueLeaf)))
		let forged = try MLS.RFC9420.protectPublic(
			provider, content: content, groupContext: committerSend.context,
			confirmationTag: nil, signingKey: aliceSigningKey,
			membershipKey: committerSend.epoch.membershipKey)
		let message = try MLS.RFC9420.Message.publicMessage(forged).mlsEncoded()

		return (
			committer: received, message: message,
			digest: provider.randomBytes(8), proposingID: aliceID
		)
	}

	/// Offer approval: `validateOfferedUpdate` (via `queueProposal`) rejects a peer's
	/// replacement leaf missing either codepoint, before `offeredProposal`
	/// is ever cleared.
	func testOfferApprovalRejectsCapabilityLessReplacementLeaf() throws {
		for missing in MissingCapability.allCases {
			let round = try forgedRogueUpdate(missing: missing)
			var committer = round.committer
			committer.offeredProposal = (
				digest: round.digest, proposing: round.proposingID,
				message: round.message
			)
			XCTAssertThrowsError(try committer.queueProposal(digest: round.digest)) {
				error in
				XCTAssertEqual(error as? TwoMLSError, .leafCapabilityUnadvertised)
			}
			XCTAssertNotNil(committer.offeredProposal, "the rejected offer is restored")
			XCTAssertNil(committer.queuedProposal)
		}
	}

	/// The fold commit: `committingRound`'s own re-check — defense in depth, independent
	/// of offer approval — catches the same rogue leaf when it is FOLDED (a
	/// `queuedProposal` injected directly, bypassing `queueProposal`'s own
	/// gate, exactly as an already-approved-but-now-rogue offer would
	/// reach this second check).
	func testFoldCommitRejectsCapabilityLessFoldedLeaf() throws {
		for missing in MissingCapability.allCases {
			let round = try forgedRogueUpdate(missing: missing)
			var committer = round.committer
			committer.queuedProposal = (
				digest: round.digest, proposing: round.proposingID,
				message: round.message
			)
			XCTAssertThrowsError(try committer.prepareToEncrypt()) { error in
				XCTAssertEqual(error as? TwoMLSError, .leafCapabilityUnadvertised)
			}
			XCTAssertNotNil(committer.queuedProposal, "no partial fold landed")
		}
	}

	// MARK: - `initiate`'s peer KeyPackage halves

	private static func rogueBobPQKeyPackage(
		_ name: String, capabilities: MLS.RFC9420.Capabilities
	) throws -> MLS.RFC9420.KeyPackage {
		let bobPQProvider = SessionTestSupport.pqProvider
		let (pqSigningKey, pqSignatureKey) = try TwoMLSIdentity.mintSignatureKeypair()
		let (_, pqLeafPublicKey) = try bobPQProvider.hpkeGenerateKeyPair()
		let (_, pqInitPublicKey) = try bobPQProvider.hpkeGenerateKeyPair()
		return try Self.rogueSignedKeyPackage(
			cipherSuite: MLS.CipherSuite(id: MLKEM768CipherSuiteProvider.cipherSuiteID),
			provider: bobPQProvider, clientID: Data(name.utf8),
			signingKey: pqSigningKey, signatureKey: pqSignatureKey,
			leafPublicKey: pqLeafPublicKey, initPublicKey: pqInitPublicKey,
			capabilities: capabilities)
	}

	/// Each half is checked independently: a rogue CLASSICAL half with a
	/// well-capable PQ half still throws, and vice versa — proving neither
	/// of `initiate`'s two checks can silently ride on the other.
	func testInitiateRejectsACapabilityLessPeerKeyPackage() throws {
		for missing in MissingCapability.allCases {
			let bobName = "cap-gate-s3-bob-\(missing)"
			let wellCapablePQ = try Self.rogueBobPQKeyPackage(
				bobName, capabilities: TwoMLSIdentity.leafCapabilities)
			let wellCapableClassical = try Self.rogueClassicalKeyPackage(
				bobName, capabilities: TwoMLSIdentity.leafCapabilities)

			let rogueClassical = try Self.rogueClassicalKeyPackage(
				bobName, capabilities: missing.capabilities)
			let alice1 = try SessionTestSupport.identity(
				"cap-gate-s3-alice1-\(missing)")
			XCTAssertThrowsError(
				try TwoMLSSession.initiate(
					identity: alice1,
					their: CombinerKeyPackage(
						classical: rogueClassical, pq: wellCapablePQ),
					classicalProvider: SessionTestSupport.classicalProvider,
					pqProvider: SessionTestSupport.pqProvider)
			) { error in
				XCTAssertEqual(error as? TwoMLSError, .leafCapabilityUnadvertised)
			}

			let roguePQ = try Self.rogueBobPQKeyPackage(
				bobName, capabilities: missing.capabilities)
			let alice2 = try SessionTestSupport.identity(
				"cap-gate-s3-alice2-\(missing)")
			XCTAssertThrowsError(
				try TwoMLSSession.initiate(
					identity: alice2,
					their: CombinerKeyPackage(
						classical: wellCapableClassical, pq: roguePQ),
					classicalProvider: SessionTestSupport.classicalProvider,
					pqProvider: SessionTestSupport.pqProvider)
			) { error in
				XCTAssertEqual(error as? TwoMLSError, .leafCapabilityUnadvertised)
			}
		}
	}

	// MARK: - `receive`'s caller-supplied `theirClassicalKeyPackage`

	func testReceiveRejectsACapabilityLessTheirClassicalKeyPackageClaim() throws {
		for missing in MissingCapability.allCases {
			let aliceName = "cap-gate-s4-alice-\(missing)"
			let alice = try SessionTestSupport.identity(aliceName)
			let bob = try SessionTestSupport.identity("cap-gate-s4-bob-\(missing)")
			let initiated = try TwoMLSSession.initiate(
				identity: alice, their: bob.keyPackage,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
			let rogueClaim = try Self.rogueClassicalKeyPackage(
				aliceName, capabilities: missing.capabilities)

			XCTAssertThrowsError(
				try TwoMLSSession.receive(
					identity: bob, welcome: initiated.welcome,
					theirClassicalKeyPackage: rogueClaim,
					bootstrapKPCommitment: try initiated.session
						.bootstrapKPCommitment(),
					classicalProvider: SessionTestSupport.classicalProvider,
					pqProvider: SessionTestSupport.pqProvider)
			) { error in
				XCTAssertEqual(error as? TwoMLSError, .leafCapabilityUnadvertised)
			}
		}
	}

	// MARK: - `pqBootstrapRespond`'s incoming KP′

	func testPqBootstrapRespondRejectsACapabilityLessKPPrime() throws {
		for missing in MissingCapability.allCases {
			var (alice, bob, _, _, _, _) = try SessionTestSupport.established(
				alice: "cap-gate-s5-alice-\(missing)",
				bob: "cap-gate-s5-bob-\(missing)")
			_ = alice

			// A rogue KP′, standing in for Alice's real bootstrap KeyPackage
			// — Bob pins its commitment at `receive`, so re-mint Bob's own
			// session with the rogue commitment instead of the real one.
			let rogueKP = try Self.rogueClassicalKeyPackage(
				"cap-gate-s5-alice-\(missing)-kpprime",
				capabilities: missing.capabilities)
			let rogueKPBytes = try MLS.RFC9420.Message.keyPackage(rogueKP).mlsEncoded()
			let rogueCommitment = try SessionTestSupport.classicalProvider.hash(
				rogueKPBytes)

			let aliceIdentity = try SessionTestSupport.identity(
				"cap-gate-s5-alice2-\(missing)")
			let bobIdentity = try SessionTestSupport.identity(
				"cap-gate-s5-bob2-\(missing)")
			let initiated = try TwoMLSSession.initiate(
				identity: aliceIdentity, their: bobIdentity.keyPackage,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
			var received = try TwoMLSSession.receive(
				identity: bobIdentity, welcome: initiated.welcome,
				theirClassicalKeyPackage: aliceIdentity.keyPackage.classical,
				bootstrapKPCommitment: rogueCommitment,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider
			).session
			_ = try received.prepareToEncrypt()
			let frame = try received.encrypt(Data("hello".utf8)).frame
			var initiatedSession = initiated.session
			_ = try initiatedSession.processIncomingDecrypted(frame)

			let inbound = Frames.encodePQBootstrapKP(rogueKPBytes)
			XCTAssertThrowsError(try received.pqBootstrapRespond(inbound)) { error in
				XCTAssertEqual(error as? TwoMLSError, .leafCapabilityUnadvertised)
			}
			XCTAssertNil(received.sendGroup?.pq, "Group_B.pq was never founded")
		}
	}

	// MARK: - `pqRekeyRespond`'s proposed Upd′

	func testPqRekeyRespondRejectsACapabilityLessUpdPrime() throws {
		for missing in MissingCapability.allCases {
			var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
			_ = alice

			var mirror = try XCTUnwrap(bob.recvGroup)
			let (freshSigningKey, freshSignatureKey) =
				try TwoMLSIdentity.mintSignatureKeypair()
			let (message, _) = try mirror.pq!.proposeUpdate(
				SessionTestSupport.pqProvider,
				sign: MLS.RFC9420.signingClosure(
					SessionTestSupport.pqProvider,
					current: try bob.recvPQSigningKey(), new: freshSigningKey),
				framing: .publicMessage,
				newIdentity: MLS.RFC9420.NewSigningIdentity(
					credential: .basic(identity: bob.identity.clientID),
					signatureKey: freshSignatureKey))
			// Swap in rogue capabilities on the already-signed leaf node —
			// mirrors the offer-approval/fold-commit forged-leaf technique one layer down (a PQ
			// proposal instead of classical).
			guard case .publicMessage(var proposalPub) = message else {
				XCTFail("expected a publicMessage-framed Upd′")
				return
			}
			guard case .proposal(.update(var rogueLeaf)) = proposalPub.content.content
			else {
				XCTFail("expected an .update proposal")
				return
			}
			rogueLeaf.capabilities = missing.capabilities
			rogueLeaf.signature = try MLS.signWithLabel(
				SessionTestSupport.pqProvider, privateKey: freshSigningKey,
				label: "LeafNodeTBS",
				content: try rogueLeaf.toBeSigned(
					placement: .inGroup(
						groupID: mirror.pq!.context.groupID,
						leafIndex: mirror.pq!.myLeafIndex)))
			proposalPub.content.content = .proposal(.update(rogueLeaf))
			proposalPub = try MLS.RFC9420.protectPublic(
				SessionTestSupport.pqProvider, content: proposalPub.content,
				groupContext: mirror.pq!.context, confirmationTag: nil,
				signingKey: try bob.recvPQSigningKey(),
				membershipKey: mirror.pq!.epoch.membershipKey)
			let updBytes = try MLS.RFC9420.Message.publicMessage(proposalPub)
				.mlsEncoded()
			let frame = Frames.encodePQRekeyUpd(updBytes)

			XCTAssertThrowsError(try alice.pqRekeyRespond(frame)) { error in
				XCTAssertEqual(error as? TwoMLSError, .leafCapabilityUnadvertised)
			}
			XCTAssertNil(alice.pqInflight)
		}
	}

	// MARK: - `receive`'s just-joined Group_A creator leaves

	/// The initiator's OWN identity (not "their", which `initiate`'s own gate already covers)
	/// carries rogue capabilities — `initiate` never checks its own
	/// founder leaf, so Group_A founds successfully with a rogue creator
	/// leaf. Isolates the Group_A join check from `receive`'s
	/// `theirClassicalKeyPackage` ARGUMENT check: the `theirClassicalKeyPackage` ARGUMENT
	/// supplied to `receive` is a SEPARATE, fully-capable claim for the
	/// same id, so only the Group_A join check on the REAL joined tree leaf can catch
	/// this.
	func testGroupAJoinRejectsACapabilityLessCreatorLeaf() throws {
		// `.appDataUpdate` alone is unreachable here: `establishFull`'s own
		// founding commit carries the `AppDataUpdate` attestation, and
		// swift-mls's own proposal-type-support enforcement
		// (`CommitProcessing.swift`) already rejects ANY occupied leaf,
		// including the founder's own, that lacks it — before this
		// session layer's own gate is ever reached. `.apqInfo` has no such
		// swift-mls-side enforcement (the profile has no opinion on this
		// module's own GCE), so it alone exercises the Group_A join check itself.
		// Each half checked independently — a rogue CLASSICAL creator leaf
		// with a well-capable PQ one still throws, and vice versa.
		for missing: MissingCapability in [.apqInfo] {
			let aliceRogueClassical = try Self.rogueIdentity(
				"cap-gate-r1a-alice-\(missing)",
				classicalCapabilities: missing.capabilities,
				pqCapabilities: TwoMLSIdentity.leafCapabilities)
			try assertR1Rejects(aliceRogueClassical, suffix: "r1a-alice-\(missing)")

			let aliceRoguePQ = try Self.rogueIdentity(
				"cap-gate-r1b-alice-\(missing)",
				classicalCapabilities: TwoMLSIdentity.leafCapabilities,
				pqCapabilities: missing.capabilities)
			try assertR1Rejects(aliceRoguePQ, suffix: "r1b-alice-\(missing)")
		}
	}

	private func assertR1Rejects(_ aliceRogue: TwoMLSIdentity, suffix: String) throws {
		let bob = try SessionTestSupport.identity("cap-gate-\(suffix)-bob")
		let initiated = try TwoMLSSession.initiate(
			identity: aliceRogue, their: bob.keyPackage,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		let wellCapableClaim = try Self.rogueClassicalKeyPackage(
			"cap-gate-\(suffix)", capabilities: TwoMLSIdentity.leafCapabilities)

		XCTAssertThrowsError(
			try TwoMLSSession.receive(
				identity: bob, welcome: initiated.welcome,
				theirClassicalKeyPackage: wellCapableClaim,
				bootstrapKPCommitment: try initiated.session
					.bootstrapKPCommitment(),
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .leafCapabilityUnadvertised)
		}
	}

	// MARK: - `joinGroupB`'s just-joined creator leaf

	/// Hand-rolls a Group_B welcome exactly like
	/// `EstablishmentTests.forgedGroupBWelcome`, but the creator leaf
	/// carries rogue capabilities and a REAL cross-party PSK rides it (so
	/// `.missingCrossPartyPSK` never fires first) — isolating the Group_B join check.
	private func forgedRogueGroupBWelcome(
		creatorName: String, adding joinerKP: MLS.RFC9420.KeyPackage,
		crossPSK: MLS.Combiner.ExportedPsk, capabilities: MLS.RFC9420.Capabilities
	) throws -> Data {
		let provider = SessionTestSupport.classicalProvider
		let (signingKey, signatureKey) = try TwoMLSIdentity.mintSignatureKeypair()
		let (leafSecretKey, leafPublicKey) = try provider.hpkeGenerateKeyPair()
		let creatorKP = try Self.rogueSignedKeyPackage(
			cipherSuite: provider.cipherSuite, provider: provider,
			clientID: Data(creatorName.utf8), signingKey: signingKey,
			signatureKey: signatureKey, leafPublicKey: leafPublicKey,
			initPublicKey: leafPublicKey, capabilities: capabilities)

		return try withDeployedWireConventions {
			// `tSessionGroupID` must equal the classical group's OWN id
			// (`verifyAPQInfoDeferred`'s `observedGroupID` check) — the
			// same value goes to both `APQInfo` and `Group.create`.
			let groupID = provider.randomBytes(provider.hashSize)
			let info = MLS.Combiner.APQInfo(
				tSessionGroupID: groupID,
				pqSessionGroupID: provider.randomBytes(provider.hashSize),
				mode: 0, tCipherSuite: provider.cipherSuite,
				pqCipherSuite: SessionTestSupport.pqProvider.cipherSuite,
				tEpoch: 1, pqEpoch: epochUnbound)
			let infoExtension = try info.asExtension(
				type: MLS.Combiner.Codepoints.deployed.apqInfoExtensionType)

			var pskStore = MLS.Combiner.PSKStore()
			pskStore.register(crossPSK)

			let epoch0 = try MLS.RFC9420.Group.create(
				provider, groupID: groupID,
				leafNode: creatorKP.leafNode, leafSecretKey: leafSecretKey,
				extensions: [infoExtension],
				epochSecret: SecretBytes(randomByteCount: provider.hashSize))
			let proposals: [MLS.RFC9420.ProposalOrRef] = [
				.proposal(.add(joinerKP)),
				.proposal(
					crossPSK.proposal(
						nonce: provider.randomBytes(provider.hashSize))),
			]
			try TwoPartyRules.validateCreationProposals(proposals)
			let transition = try epoch0.committing(
				provider, proposals: proposals, signingKey: signingKey,
				randomness: try .generate(provider), psk: pskStore.resolver())
			let sent = transition.takeOutput()
			guard let welcome = sent.welcome else {
				throw MLS.Combiner.Error.missingWelcome
			}
			return Frames.encodeAPQWelcome(t: try welcome.mlsEncoded(), pq: Data())
		}
	}

	func testGroupBJoinRejectsACapabilityLessCreatorLeaf() throws {
		for missing in MissingCapability.allCases {
			var (alice, bob, aliceIdentity, _, _, _) =
				try SessionTestSupport.established(
					alice: "cap-gate-r2-alice-\(missing)",
					bob: "cap-gate-r2-bob-\(missing)")
			_ = try bob.prepareToEncrypt()
			let genuineFrame = try bob.encrypt(Data("cap-gate-r2".utf8)).frame
			let (_, _, appSection) = try Frames.decodeMessageFrame(
				alice.openOrRaw(genuineFrame))

			guard var groupA = alice.sendGroup else {
				XCTFail("expected alice's Group_A")
				return
			}
			let crossPSK = try MLS.Combiner.ExportedPsk.export(
				from: &groupA.classical, SessionTestSupport.classicalProvider,
				componentID: TwoMLSSession.crossPartyComponentID)

			let forgedStaple = try forgedRogueGroupBWelcome(
				creatorName: "cap-gate-r2-bob-\(missing)",
				adding: aliceIdentity.keyPackage.classical, crossPSK: crossPSK,
				capabilities: missing.capabilities)
			let proposalSection = Frames.encodeProposalSection(
				proposing: Data("cap-gate-r2-bob-\(missing)".utf8),
				message: Data("dummy-upd".utf8))
			let forgedFrame = Frames.encodeMessageFrame(
				staple: forgedStaple, proposal: proposalSection, app: appSection)

			XCTAssertThrowsError(try alice.processIncoming(forgedFrame)) { error in
				XCTAssertEqual(error as? TwoMLSError, .leafCapabilityUnadvertised)
			}
			XCTAssertNil(alice.recvGroup, "the rogue join never landed")
		}
	}

	// MARK: - `pqBootstrapJoin`'s just-joined Group_B.pq creator leaf

	/// `initiate`'s own peer-KeyPackage gate would catch a rogue "their" KeyPackage
	/// immediately — and bob's real identity IS what alice's `initiate`
	/// necessarily adds as "their" (the same keypair he later joins with),
	/// so establishment itself must go through with bob's REAL, well-
	/// capable identity. Bob's PQ leaf turns rogue only afterward, by
	/// swapping `identity` on his LIVE session (`@testable`, mirrors how
	/// `testRule4Pin` hand-ages other session state directly) — re-signed
	/// under his own real PQ signing key, so `leafKeys.sendPQ.current`
	/// (already seeded before the swap) still validly signs the founding
	/// commit `pqBootstrapRespond` builds off `identity.keyPackage.pq.
	/// leafNode`. No OTHER gate checks a session's own identity against
	/// itself, so this reaches `pqBootstrapRespond` unblocked, and only the
	/// Group_B.pq join check, on Alice's side, catches the rogue creator
	/// leaf she just joined.
	func testGroupBPQJoinRejectsACapabilityLessCreatorLeaf() throws {
		for missing in MissingCapability.allCases {
			var (aliceSession, bobSession, aliceIdentity, bobIdentity, _, _) =
				try SessionTestSupport.established(
					alice: "cap-gate-r3-alice-\(missing)",
					bob: "cap-gate-r3-bob-\(missing)")
			_ = aliceIdentity

			let rogueBobPQLeafNode = try Self.rogueSignedPQLeaf(
				bobIdentity, capabilities: missing.capabilities)
			let rogueBobIdentity = TwoMLSIdentity(
				clientID: bobIdentity.clientID, signingKey: bobIdentity.signingKey,
				signatureKey: bobIdentity.signatureKey,
				pqSigningKey: bobIdentity.pqSigningKey,
				pqSignatureKey: bobIdentity.pqSignatureKey,
				classicalLeafSecretKey: bobIdentity.classicalLeafSecretKey,
				classicalInitSecretKey: bobIdentity.classicalInitSecretKey,
				pqLeafSecretKey: bobIdentity.pqLeafSecretKey,
				pqInitSecretKey: bobIdentity.pqInitSecretKey,
				keyPackage: CombinerKeyPackage(
					classical: bobIdentity.keyPackage.classical,
					pq: rogueBobPQLeafNode))
			bobSession.identity = rogueBobIdentity

			_ = try bobSession.prepareToEncrypt()
			let helloFrame = try bobSession.encrypt(Data("hello".utf8)).frame
			_ = try aliceSession.processIncomingDecrypted(helloFrame)

			let kpFrame = try aliceSession.pqBootstrapBegin().frame
			let welcomeFrame = try bobSession.pqBootstrapRespond(kpFrame).frame

			XCTAssertThrowsError(try aliceSession.pqBootstrapJoin(welcomeFrame)) {
				error in
				XCTAssertEqual(error as? TwoMLSError, .leafCapabilityUnadvertised)
			}
			XCTAssertNil(aliceSession.recvGroup?.pq, "the rogue join never landed")
		}
	}

	/// Bob's real PQ `KeyPackage`, re-signed under his OWN real PQ signing
	/// key but with `capabilities` swapped for the rogue set — same id,
	/// same encryption/signature keys, so `leafKeys.sendPQ.current`
	/// (already seeded from the real pair) still matches.
	private static func rogueSignedPQLeaf(
		_ identity: TwoMLSIdentity, capabilities: MLS.RFC9420.Capabilities
	) throws -> MLS.RFC9420.KeyPackage {
		let provider = SessionTestSupport.pqProvider
		var leaf = identity.keyPackage.pq.leafNode
		leaf.capabilities = capabilities
		leaf.signature = try MLS.signWithLabel(
			provider, privateKey: identity.pqSigningKey, label: "LeafNodeTBS",
			content: try leaf.toBeSigned(placement: .keyPackage))
		var keyPackage = identity.keyPackage.pq
		keyPackage.leafNode = leaf
		keyPackage.signature = try MLS.signWithLabel(
			provider, privateKey: identity.pqSigningKey, label: "KeyPackageTBS",
			content: try keyPackage.toBeSigned())
		return keyPackage
	}
}
