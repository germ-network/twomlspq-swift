import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes
import TwoMLSPQCrypto
import XCTest

@testable import TwoMLSPQSession

/// Shared scaffolding for the session tests: identity generation and a
/// two-party establishment helper, mirroring `CombinerTestSupport`'s
/// `member(...)`/`establishedPair(...)` shape one layer up.
@available(iOS 26, macOS 26, *)
enum SessionTestSupport {
	static let classicalProvider: any MLS.CipherSuiteProvider = {
		SwiftCryptoProvider().cipherSuiteProvider(for: .curve25519ChaCha)!
	}()
	static let pqProvider = MLKEM768CipherSuiteProvider()

	static func identity(_ name: String) throws -> TwoMLSIdentity {
		try TwoMLSIdentity.generate(
			clientID: Data(name.utf8), classicalProvider: classicalProvider,
			pqProvider: pqProvider)
	}

	/// Alice initiates to Bob's freshly-minted invitation, Bob receives. Bob
	/// is established immediately; Alice becomes established only once she
	/// processes Bob's first inbound frame (see `establishedAndExchanged`).
	/// Both identities are returned too — needed by tests that reach for a
	/// peer's own join credentials (e.g. the cross-party PSK binding proof);
	/// each is the fresh leaf bundle `Principal`/`Invitation` minted for
	/// this session (`session.identity`), not the principal itself.
	static func established(alice aliceName: String = "alice", bob bobName: String = "bob")
		throws -> (
			alice: TwoMLSSession, bob: TwoMLSSession, aliceIdentity: TwoMLSIdentity,
			bobIdentity: TwoMLSIdentity, welcomeA: Data, welcomeB: Data
		)
	{
		let alicePrincipal = try Principal.generate(
			clientID: Data(aliceName.utf8), classicalProvider: classicalProvider,
			pqProvider: pqProvider)
		let bobPrincipal = try Principal.generate(
			clientID: Data(bobName.utf8), classicalProvider: classicalProvider,
			pqProvider: pqProvider)
		var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: true)
		guard let theirCombinerKP = invitation.combinerKeyPackage else {
			throw TwoMLSError.invitationSpent
		}

		let initiated = try TwoMLSSession.initiate(
			principal: alicePrincipal, their: theirCombinerKP)
		let spawnToken = classicalProvider.randomBytes(16)
		let received = try invitation.receive(
			welcome: initiated.welcome,
			theirClassicalKeyPackage: initiated.session.identity.keyPackage.classical,
			bootstrapKPCommitment: try initiated.session.bootstrapKPCommitment(),
			spawnToken: spawnToken)

		return (
			alice: initiated.session, bob: received.session,
			aliceIdentity: initiated.session.identity,
			bobIdentity: received.session.identity, welcomeA: initiated.welcome,
			welcomeB: received.session.currentStaple
		)
	}

	/// `established()`, plus Bob's first frame (a no-op app message) delivered
	/// to Alice, so both sides are `isEstablished` — matching the reference's
	/// "initiator established only once it has received the acceptor's first
	/// frame" ordering.
	/// Slice 11: `established()`'s born-dedicated analogue — Bob receives
	/// under a fresh `newClientID`, so his session founds Group_B under a
	/// dedicated principal D distinct from the invitation identity, and owes
	/// the contract-26 handoff envelope. `invitationClientID` is Bob's
	/// invitation identity's own clientID (== `bobName`, `TwoMLSIdentity.
	/// generate`'s `clientID` param passed straight through by
	/// `Principal.generateInvitation`) — the id `bob.leafKeys.recvClassical`
	/// still presents as `current` until the recv-leaf catch-up.
	static func establishedDedicated(
		alice aliceName: String = "alice", bob bobName: String = "bob",
		dedicatedClientID: Data = Data("bob-dedicated".utf8)
	) throws -> (
		alice: TwoMLSSession, bob: TwoMLSSession, aliceIdentity: TwoMLSIdentity,
		invitationClientID: Data, dedicatedClientID: Data
	) {
		let alicePrincipal = try Principal.generate(
			clientID: Data(aliceName.utf8), classicalProvider: classicalProvider,
			pqProvider: pqProvider)
		let bobPrincipal = try Principal.generate(
			clientID: Data(bobName.utf8), classicalProvider: classicalProvider,
			pqProvider: pqProvider)
		var (invitation, _) = try bobPrincipal.generateInvitation(lastResort: true)
		guard let theirCombinerKP = invitation.combinerKeyPackage else {
			throw TwoMLSError.invitationSpent
		}

		let initiated = try TwoMLSSession.initiate(
			principal: alicePrincipal, their: theirCombinerKP)
		let spawnToken = classicalProvider.randomBytes(16)
		let received = try invitation.receive(
			welcome: initiated.welcome,
			theirClassicalKeyPackage: initiated.session.identity.keyPackage.classical,
			bootstrapKPCommitment: try initiated.session.bootstrapKPCommitment(),
			spawnToken: spawnToken, newClientID: dedicatedClientID)

		return (
			alice: initiated.session, bob: received.session,
			aliceIdentity: initiated.session.identity,
			invitationClientID: Data(bobName.utf8), dedicatedClientID: dedicatedClientID
		)
	}

	/// `establishedDedicated()` taken through the install/standalone/approve
	/// dance: install the envelope, deliver the welcome standalone, and
	/// approve it — landing both parties established (not yet
	/// `isFullyEstablished`; no §A.3 bootstrap has run). Shared by
	/// `BornDedicatedTests` and any other suite needing a born-dedicated
	/// starting point.
	static func establishedDedicatedAndApproved(
		dedicatedClientID: Data = Data("bob-dedicated".utf8)
	) throws -> (
		alice: TwoMLSSession, bob: TwoMLSSession, invitationClientID: Data,
		dedicatedClientID: Data, envelope: Data
	) {
		var (alice, bob, _, invitationClientID, resolvedDedicatedClientID) =
			try establishedDedicated(dedicatedClientID: dedicatedClientID)
		let envelope = Data("fake-signed-handoff".utf8)
		_ = try bob.installEstablishmentEnvelope(envelope)
		let standalone = try XCTUnwrap(try bob.standaloneWelcome())
		let opened = try XCTUnwrap(try alice.openIncoming(standalone))
		guard case .pendingEstablishment = try alice.processIncoming(opened.frame) else {
			XCTFail("expected a pause on the un-approved 0x0B")
			throw TwoMLSError.notEstablished
		}
		let (envelopeBytes, welcomeBytes) = try Frames.decodeEstablishmentHandoff(
			bob.currentStaple)
		guard
			case .joined = try alice.processIncomingApproved(
				opened.frame,
				approvedEnvelopeDigest: try classicalProvider.hash(envelopeBytes),
				approvedWelcomeDigest: try classicalProvider.hash(welcomeBytes),
				expectedCreator: resolvedDedicatedClientID)
		else {
			XCTFail("expected .joined on the approved re-feed")
			throw TwoMLSError.notEstablished
		}
		return (
			alice: alice, bob: bob, invitationClientID: invitationClientID,
			dedicatedClientID: resolvedDedicatedClientID, envelope: envelope
		)
	}

	static func establishedAndExchanged(
		alice aliceName: String = "alice", bob bobName: String = "bob"
	) throws -> (alice: TwoMLSSession, bob: TwoMLSSession) {
		var (alice, bob, _, _, _, _) = try established(alice: aliceName, bob: bobName)
		_ = try bob.prepareToEncrypt()
		let frame = try bob.encrypt(Data("bob-hello".utf8)).frame
		_ = try alice.processIncomingDecrypted(frame)
		return (alice: alice, bob: bob)
	}

	/// An own Update whose HPKE pair `session.recvGroup.classical` NEVER
	/// holds — no write-back to `session` at all, unlike
	/// `RotationTests.authorRotatingUpd`/`DeployedStateTests.
	/// handBuiltUnframedOwnOffer`, which both stage their fresh key into
	/// `leafKeys`. This is the shape the own-offer window's caller-supplied-
	/// `leafSecret` branch (`insertMigratedOwnUpdate`) actually exercises: a
	/// migrated session's snapshot never carries these pairs, so production
	/// resolution runs on the secret the window blob itself supplies, not on
	/// anything the group already has. Built entirely from public swift-mls
	/// API: a fresh X25519 pair, a self-signed `LeafNode(source: .update)`,
	/// framed and verified on a scratch `ProposalStore` so the caller gets
	/// both the wire bytes and the bare proposal/ref/secret needed for a
	/// `MigratedOwnOffer`.
	static func knownSecretOwnOffer(in session: TwoMLSSession) throws -> (
		framedMessage: Data, ref: Data, bareProposal: Data, leafSecret: SecretBytes,
		epoch: UInt64, groupID: Data, senderLeafIndex: UInt32
	) {
		let provider = classicalProvider
		let throwaway = try XCTUnwrap(session.recvGroup)
		var group = throwaway.classical
		let current = try TwoMLSSession.ownLeaf(of: group)
		let (hpkeSecret, hpkePublic) = try provider.hpkeGenerateKeyPair()
		var leaf = MLS.RFC9420.LeafNode(
			encryptionKey: hpkePublic, signatureKey: current.signatureKey,
			credential: current.credential, capabilities: current.capabilities,
			source: .update, extensions: current.extensions, signature: Data())
		let tbs = try leaf.toBeSigned(
			placement: .inGroup(
				groupID: group.context.groupID, leafIndex: group.myLeafIndex))
		leaf.signature = try MLS.signWithLabel(
			provider, privateKey: try session.recvClassicalSigningKey(),
			label: "LeafNodeTBS", content: tbs)
		// A throwaway `proposeUpdate` call, only to get a correctly-shaped
		// sender for the hand-built `FramedContent` below — its own Update
		// leaf/keys are discarded.
		let (template, _) = try group.proposeUpdate(
			provider,
			sign: MLS.RFC9420.signingClosure(
				provider, try session.recvClassicalSigningKey()),
			framing: .publicMessage)
		guard case .publicMessage(let templatePub) = template else {
			throw TwoMLSError.malformedSideBandMessage
		}
		let content = MLS.RFC9420.FramedContent(
			groupID: group.context.groupID, epoch: group.context.epoch,
			sender: templatePub.content.sender, authenticatedData: Data(),
			content: .proposal(.update(leaf)))
		let pub = try MLS.RFC9420.protectPublic(
			provider, content: content, groupContext: group.context,
			confirmationTag: nil,
			signingKey: try session.recvClassicalSigningKey(),
			membershipKey: group.epoch.membershipKey)
		var scratch = MLS.RFC9420.ProposalStore()
		let verified = try group.verifying(provider, proposal: pub)
		let ref = try scratch.insert(verified, provider)
		let bare = try withDeployedWireConventions {
			try MLS.RFC9420.Proposal.update(leaf).mlsEncoded()
		}
		return (
			try MLS.RFC9420.Message.publicMessage(pub).mlsEncoded(), ref.data, bare,
			hpkeSecret.data, group.context.epoch, group.context.groupID,
			group.myLeafIndex.value
		)
	}

	/// Drives whatever PQ round the turn-holder (`initiator`) currently
	/// holds opens on its next send — an A.4 ratchet or an A.5 re-key,
	/// dispatched by the parked leg's own shape (`pqInflight`, since
	/// `pqPendingOutbound()` returns a header-sealed frame, not the raw
	/// tagged one) — through the responder's reply and the initiator's
	/// discharge, exactly as
	/// `ReciprocalCatchUpConformanceTests.driveOneA4Round` does for the
	/// A.4-only case. Returns the opening leg's own tag (`Frames.pqEKTag`
	/// or `Frames.pqRekeyUpdTag`), so a caller can assert which round
	/// actually opened.
	@discardableResult
	static func drivePQRound(
		initiator: inout TwoMLSSession, responder: inout TwoMLSSession,
		file: StaticString = #filePath, line: UInt = #line
	) throws -> UInt8 {
		_ = try initiator.prepareToEncrypt()
		_ = try initiator.encrypt(Data("pq-round-probe".utf8))
		let openFrame = try XCTUnwrap(initiator.pqPendingOutbound(), file: file, line: line)
		let tag: UInt8
		switch initiator.pqInflight {
		case .some(.initiating):
			tag = Frames.pqEKTag
			let ctFrame = try responder.pqRatchetRespond(openFrame).frame
			_ = try initiator.pqRatchetBind(ctFrame)
		case .some(.rekeyInitiated):
			tag = Frames.pqRekeyUpdTag
			let commitFrame = try responder.pqRekeyRespond(openFrame).frame
			_ = try initiator.pqRekeyApply(commitFrame)
		default:
			XCTFail(
				"drivePQRound: unexpected pqInflight \(String(describing: initiator.pqInflight))",
				file: file, line: line)
			throw TwoMLSError.sessionNotReady
		}
		let discharge = try initiator.prepareToEncrypt()
		XCTAssertTrue(discharge.didCommit, file: file, line: line)
		let boundFrame = try initiator.encrypt(Data("pq-round-discharge".utf8)).frame
		_ = try responder.processIncomingDecrypted(boundFrame, file: file, line: line)
		return tag
	}
}

/// Slice 11: `processIncoming` now returns the 4-case `IncomingResult`
/// instead of a bare `DecryptResult` — this mechanically migrates the
/// hundreds of pre-existing call sites that only ever cared about the
/// everyday `0x03` app-frame path. Fails the test (via `XCTFail`, not a
/// thrown error) on any other case, since none of those call sites expect
/// one.
@available(iOS 26, macOS 26, *)
extension TwoMLSSession {
	mutating func processIncomingDecrypted(
		_ inbound: Data, file: StaticString = #filePath, line: UInt = #line
	) throws -> DecryptResult {
		switch try processIncoming(inbound) {
		case .decrypted(let result):
			return result
		case .joined, .pendingEstablishment, .ignored, .preEstablishment:
			XCTFail(
				"expected .decrypted, got a non-decrypted IncomingResult",
				file: file,
				line: line)
			throw TwoMLSError.notEstablished
		}
	}
}
