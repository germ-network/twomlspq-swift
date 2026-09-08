import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import TwoMLSPQCrypto
import XCTest

@testable import TwoMLSPQSession

/// §A.3: KP′ exchange + Bob founds Group_B.pq + Alice joins (chunk A), then
/// the bind — Alice's owed PQ commit discharged against a licensed classical
/// commit, stapled `0x05`, turn returned to Bob (chunk B).
@available(iOS 26, macOS 26, *)
final class BootstrapTests: XCTestCase {
	func testFullBootstrapRoundReachesFullyEstablished() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		XCTAssertTrue(alice.myPQTurn)
		XCTAssertFalse(bob.myPQTurn)
		XCTAssertFalse(alice.isFullyEstablished)
		XCTAssertFalse(bob.isFullyEstablished)

		let kpFrame = try alice.pqBootstrapBegin()
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame)
		XCTAssertTrue(bob.isFullyEstablished)
		XCTAssertFalse(alice.isFullyEstablished)

		try alice.pqBootstrapJoin(welcomeFrame)
		XCTAssertTrue(alice.isFullyEstablished)
	}

	/// The joined Group_B.pq's mirror `APQInfo` and epoch land where §3
	/// specifies: `pqEpoch == 1`, `tEpoch` unbound, and both rosters are 2.
	func testJoinedPQHalfHasMirrorAPQInfoAndEpochOne() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let kpFrame = try alice.pqBootstrapBegin()
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame)
		try alice.pqBootstrapJoin(welcomeFrame)

		let alicePQ = try XCTUnwrap(alice.recvGroup?.pq)
		let bobPQ = try XCTUnwrap(bob.sendGroup?.pq)
		XCTAssertEqual(alicePQ.context.epoch, 1)
		XCTAssertEqual(bobPQ.context.epoch, 1)
		XCTAssertEqual(alicePQ.tree.nonBlankLeaves().count, 2)
		XCTAssertEqual(bobPQ.tree.nonBlankLeaves().count, 2)

		let info = try XCTUnwrap(
			try MLS.Combiner.APQInfo.read(
				fromExtensionsOf: alicePQ.context,
				type: MLS.Combiner.Codepoints.deployed.apqInfoExtensionType))
		XCTAssertEqual(info.tEpoch, epochUnbound)
		XCTAssertEqual(info.pqEpoch, 1)
		XCTAssertEqual(info.pqSessionGroupID, alicePQ.context.groupID)
	}

	// MARK: - Negatives

	func testReceiveRejectsNonThirtyTwoByteCommitment() throws {
		let alice = try SessionTestSupport.identity("alice")
		let bob = try SessionTestSupport.identity("bob")
		let initiated = try TwoMLSSession.initiate(
			identity: alice, their: bob.keyPackage,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		XCTAssertThrowsError(
			try TwoMLSSession.receive(
				identity: bob, welcome: initiated.welcome,
				theirClassicalKeyPackage: alice.keyPackage.classical,
				bootstrapKPCommitment: Data([1, 2, 3]),
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .bootstrapKPMismatch)
		}
	}

	func testRespondRejectsWrongCommitment() throws {
		let alice = try SessionTestSupport.identity("alice")
		let bob = try SessionTestSupport.identity("bob")
		let initiated = try TwoMLSSession.initiate(
			identity: alice, their: bob.keyPackage,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		// A commitment of the right length but the wrong value.
		let wrongCommitment = Data(repeating: 0xAB, count: 32)
		let received = try TwoMLSSession.receive(
			identity: bob, welcome: initiated.welcome,
			theirClassicalKeyPackage: alice.keyPackage.classical,
			bootstrapKPCommitment: wrongCommitment,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		var (aliceSession, bobSession) = (initiated.session, received.session)
		_ = try bobSession.prepareToEncrypt()
		let frame = try bobSession.encrypt(Data("bob-hello".utf8))
		_ = try aliceSession.processIncoming(frame)

		let kpFrame = try aliceSession.pqBootstrapBegin()
		XCTAssertThrowsError(try bobSession.pqBootstrapRespond(kpFrame)) { error in
			XCTAssertEqual(error as? TwoMLSError, .bootstrapKPMismatch)
		}
	}

	func testBeginRejectsWhenNotMyTurn() throws {
		var (_, bob) = try SessionTestSupport.establishedAndExchanged()
		XCTAssertThrowsError(try bob.pqBootstrapBegin()) { error in
			XCTAssertEqual(error as? TwoMLSError, .sessionNotReady)
		}
	}

	// MARK: - Chunk B: the bind

	/// The full A.3 round: KP′ exchange, the bind's discharge (licensed by
	/// Bob's establishment-time frame, per §11 #8), and the turn returning to
	/// Bob. Asserts the exact epoch positions §11 #10 calls out: only
	/// Group_A.pq (ASG-PQ) moves 1 -> 2; Group_B's halves stay where the
	/// bootstrap left them.
	func testFullBootstrapRoundBindsAndReturnsTurn() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()

		let kpFrame = try alice.pqBootstrapBegin()
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame)
		XCTAssertTrue(bob.isFullyEstablished)

		try alice.pqBootstrapJoin(welcomeFrame)
		XCTAssertTrue(alice.isFullyEstablished)
		XCTAssertNotNil(alice.owedBind)

		// Bob's establishment-time frame already licensed Alice (§11 #8), so
		// the very next `prepareToEncrypt` discharges immediately.
		let prepared = try alice.prepareToEncrypt()
		XCTAssertTrue(prepared.didCommit)
		XCTAssertNil(alice.owedBind)
		let frame = try alice.encrypt(Data("bound".utf8))

		let (staple, _, _) = try Frames.decodeMessageFrame(frame)
		XCTAssertEqual(Frames.stapleKind(staple.first!), .apqPrivateMessage)

		let decrypted = try bob.processIncoming(frame)
		XCTAssertEqual(decrypted.applicationMessage, Data("bound".utf8))
		XCTAssertTrue(bob.myPQTurn)

		let alicePQEpoch = try XCTUnwrap(alice.sendGroup?.pq?.context.epoch)
		let bobRecvPQEpoch = try XCTUnwrap(bob.recvGroup?.pq?.context.epoch)
		let aliceClassicalEpoch = try XCTUnwrap(alice.sendGroup?.classical.context.epoch)
		let bobRecvClassicalEpoch = try XCTUnwrap(bob.recvGroup?.classical.context.epoch)
		let bobSendPQEpoch = try XCTUnwrap(bob.sendGroup?.pq?.context.epoch)
		let aliceRecvPQEpoch = try XCTUnwrap(alice.recvGroup?.pq?.context.epoch)
		XCTAssertEqual(alicePQEpoch, 2)
		XCTAssertEqual(bobRecvPQEpoch, 2)
		XCTAssertEqual(aliceClassicalEpoch, 2)
		XCTAssertEqual(bobRecvClassicalEpoch, 2)
		XCTAssertEqual(bobSendPQEpoch, 1)
		XCTAssertEqual(aliceRecvPQEpoch, 1)
	}

	/// §11 #2: the `0x05` staple re-rides every Alice→Bob frame until her next
	/// commit. A second frame after the bind must decrypt without re-applying
	/// (no throw, no double epoch-advance, no re-consuming the spent PSKs).
	func testSecondFrameAfterBindIsIdempotent() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let kpFrame = try alice.pqBootstrapBegin()
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame)
		try alice.pqBootstrapJoin(welcomeFrame)

		_ = try alice.prepareToEncrypt()
		let boundFrame = try alice.encrypt(Data("bound".utf8))
		_ = try bob.processIncoming(boundFrame)

		let secondPrepared = try alice.prepareToEncrypt()
		XCTAssertFalse(secondPrepared.didCommit)
		let secondFrame = try alice.encrypt(Data("again".utf8))

		let decrypted = try bob.processIncoming(secondFrame)
		XCTAssertEqual(decrypted.applicationMessage, Data("again".utf8))

		let bobRecvPQEpoch = try XCTUnwrap(bob.recvGroup?.pq?.context.epoch)
		let bobRecvClassicalEpoch = try XCTUnwrap(bob.recvGroup?.classical.context.epoch)
		XCTAssertEqual(bobRecvPQEpoch, 2)
		XCTAssertEqual(bobRecvClassicalEpoch, 2)
	}

	// MARK: - Chunk B negatives

	/// Discharge attempted before the license: `owedBind` stays parked and the
	/// staple is not re-stapled `0x05` until Bob's inbound Upd has evidenced
	/// applying Alice's current send epoch.
	func testDischargeWithoutLicenseDoesNotCommit() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let kpFrame = try alice.pqBootstrapBegin()
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame)
		try alice.pqBootstrapJoin(welcomeFrame)
		XCTAssertNotNil(alice.owedBind)

		// Simulate Bob's licensing Upd never having arrived.
		alice.peerAppliedSendEpoch = nil

		let prepared = try alice.prepareToEncrypt()
		XCTAssertFalse(prepared.didCommit)
		XCTAssertNotNil(alice.owedBind)

		let frame = try alice.encrypt(Data("still-owed".utf8))
		let (staple, _, _) = try Frames.decodeMessageFrame(frame)
		XCTAssertNotEqual(Frames.stapleKind(staple.first!), .apqPrivateMessage)
	}

	/// `dischargeOwedBindIfLicensed`'s own re-check catches an `owedBind`
	/// whose parked epochs no longer match the live send groups, before ever
	/// building a wire commit — the guard `verifyFullCommitAttestation`
	/// backstops on the receive side (§11 #9's attestation check is the
	/// combiner's; this is the discharge-side belt).
	func testTamperedOwedBindEpochThrowsEpochDesync() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let kpFrame = try alice.pqBootstrapBegin()
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame)
		try alice.pqBootstrapJoin(welcomeFrame)

		alice.owedBind?.pqEpoch += 1

		XCTAssertThrowsError(try alice.prepareToEncrypt()) { error in
			XCTAssertEqual(error as? TwoMLSError, .epochDesync)
		}
	}

	/// A bit-flip inside the `0x05` staple's PQ commit section breaks its
	/// framing signature — `applyBind` must reject it, not silently apply a
	/// forged commit or burn the single-shot cross-party PSK leaf. Also
	/// pins the rollback (Bob's receive groups are untouched by the
	/// rejected attempt) and that the genuine frame — and a subsequent
	/// Bob→Alice post-bind message — still apply cleanly afterward.
	func testCorruptedBindStapleIsRejected() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let kpFrame = try alice.pqBootstrapBegin()
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame)
		try alice.pqBootstrapJoin(welcomeFrame)
		_ = try alice.prepareToEncrypt()
		let frame = try alice.encrypt(Data("bound".utf8))

		let (staple, proposal, app) = try Frames.decodeMessageFrame(frame)
		let (t, pq) = try Frames.decodeAPQPrivateMessage(staple)
		var corruptedPQ = pq
		corruptedPQ[corruptedPQ.count / 2] ^= 0xFF
		let corruptedStaple = Frames.encodeAPQPrivateMessage(t: t, pq: corruptedPQ)
		let corruptedFrame = Frames.encodeMessageFrame(
			staple: corruptedStaple, proposal: proposal, app: app)

		let bobRecvClassicalEpochBefore = bob.recvGroup?.classical.context.epoch
		let bobRecvPQEpochBefore = bob.recvGroup?.pq?.context.epoch

		XCTAssertThrowsError(try bob.processIncoming(corruptedFrame))

		XCTAssertEqual(bob.recvGroup?.classical.context.epoch, bobRecvClassicalEpochBefore)
		XCTAssertEqual(bob.recvGroup?.pq?.context.epoch, bobRecvPQEpochBefore)

		// The genuine frame still applies cleanly after the rejected attempt.
		let decrypted = try bob.processIncoming(frame)
		XCTAssertEqual(decrypted.applicationMessage, Data("bound".utf8))
		XCTAssertTrue(bob.myPQTurn)

		// Bob -> Alice post-bind: the license re-stamps (against Alice's now
		// bind-advanced send epoch), and the `0x01` welcome staple Bob still
		// rides (Group_B.classical never moved) idempotently skips, since
		// Alice already joined it.
		_ = try bob.prepareToEncrypt()
		let postBindFrame = try bob.encrypt(Data("post-bind".utf8))
		let aliceDecrypted = try alice.processIncoming(postBindFrame)
		XCTAssertEqual(aliceDecrypted.applicationMessage, Data("post-bind".utf8))
	}

	// MARK: - MAJOR-3: the cross-half attestation check, pinned

	/// The receive-side cross-half attestation check (§11 #9,
	/// `MLS.Combiner.verifyFullCommitAttestation`) is otherwise unpinned by
	/// this suite: deleting it still passes every other test. Hand-build a
	/// classical bind commit whose attestation lies about the post-commit
	/// PQ epoch (`owed.pqEpoch + 1` instead of the real `owed.pqEpoch`),
	/// staple it alongside the genuine, untouched PQ commit, and confirm
	/// Bob rejects the pair and rolls back rather than applying one half.
	func testWrongClassicalAttestationIsRejectedAndRolledBack() throws {
		let established = try SessionTestSupport.established()
		var alice = established.alice
		var bob = established.bob
		let aliceIdentity = established.aliceIdentity

		_ = try bob.prepareToEncrypt()
		let helloFrame = try bob.encrypt(Data("bob-hello".utf8))
		_ = try alice.processIncoming(helloFrame)

		let kpFrame = try alice.pqBootstrapBegin()
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame)
		try alice.pqBootstrapJoin(welcomeFrame)

		let owed = try XCTUnwrap(alice.owedBind)
		var send = try XCTUnwrap(alice.sendGroup)
		var recv = try XCTUnwrap(alice.recvGroup)

		let bobRecvClassicalEpochBefore = try XCTUnwrap(
			bob.recvGroup?.classical.context.epoch)
		let bobRecvPQEpochBefore = try XCTUnwrap(bob.recvGroup?.pq?.context.epoch)

		var pqForExport = try XCTUnwrap(send.pq)
		let apqPSK = try MLS.Combiner.ExportedPsk.export(
			from: &pqForExport, SessionTestSupport.pqProvider,
			componentID: MLS.Combiner.Codepoints.deployed.apqComponentID)
		send.pq = pqForExport

		var store = MLS.Combiner.PSKStore()
		store.register(apqPSK)

		// Deliberately WRONG: the real post-commit pq epoch is `owed.pqEpoch`.
		let badAttestation = MLS.Combiner.ApqInfoUpdate(
			tEpoch: owed.tEpoch, pqEpoch: owed.pqEpoch + 1)
		let proposals: [MLS.RFC9420.ProposalOrRef] = [
			.proposal(
				apqPSK.proposal(
					nonce: SessionTestSupport.classicalProvider.randomBytes(
						SessionTestSupport.classicalProvider.hashSize))),
			.proposal(
				try badAttestation.proposal(
					componentID: MLS.Combiner.Codepoints.deployed.apqComponentID
				)),
		]

		let (proposalMessage, _) = try recv.classical.proposeUpdate(
			SessionTestSupport.classicalProvider, signingKey: aliceIdentity.signingKey,
			framing: .publicMessage)
		let proposalBytes = try proposalMessage.mlsEncoded()
		let proposalHash = try SessionTestSupport.classicalProvider.hash(proposalBytes)

		// `Transition`/`SentCommit`/`PendingCommit` are `~Copyable`, so they
		// cannot cross `withDeployedWireWidth`'s generic `<T>` boundary — the
		// whole commit/adopt/apply sequence runs inside the closure, which
		// hands back only the `Copyable` results needed outside it.
		let (commitBytes, advancedClassical): (Data, MLS.RFC9420.Group) =
			try withDeployedWireWidth {
				let transition = try send.classical.committing(
					SessionTestSupport.classicalProvider, proposals: proposals,
					signingKey: aliceIdentity.signingKey,
					randomness: try .generate(
						SessionTestSupport.classicalProvider),
					includePath: true, framing: .publicMessage,
					psk: store.resolver())
				let adopted = transition.group
				let sent = transition.takeOutput()
				let bytes = try sent.message.mlsEncoded()
				let advanced = try sent.takePending().apply(onto: adopted)
				return (bytes, advanced.group)
			}
		send.classical = advancedClassical

		let appPM = try send.classical.protect(
			SessionTestSupport.classicalProvider, applicationData: Data("bound".utf8),
			authenticatedData: proposalHash, signingKey: aliceIdentity.signingKey)
		let appBytes = try MLS.RFC9420.Message.privateMessage(appPM).mlsEncoded()

		let badStaple = Frames.encodeAPQPrivateMessage(
			t: commitBytes, pq: owed.pqCommitMessage)
		let proposalSection = Frames.encodeProposalSection(
			proposing: aliceIdentity.clientID, message: proposalBytes)
		let frame = Frames.encodeMessageFrame(
			staple: badStaple, proposal: proposalSection, app: appBytes)

		XCTAssertThrowsError(try bob.processIncoming(frame)) { error in
			XCTAssertEqual(error as? MLS.Combiner.Error, .attestationMismatch)
		}

		XCTAssertEqual(bob.recvGroup?.classical.context.epoch, bobRecvClassicalEpochBefore)
		XCTAssertEqual(bob.recvGroup?.pq?.context.epoch, bobRecvPQEpochBefore)
	}

	// MARK: - MAJOR-4: the reverse-direction 0xFF02, pinned

	/// The bind's classical commit must carry both application PSKs
	/// (`apq_psk` `0xFF01` and the cross-party `0xFF02`) plus exactly one
	/// `AppDataUpdate` attestation — three by-value proposals, none by
	/// reference. Otherwise-unpinned: the cross-party injection
	/// (`dischargeOwedBindIfLicensed`'s `0xFF02` branch) could silently stop
	/// firing with every other test still green.
	func testBindCommitCarriesBothApplicationPSKsAndAttestation() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let kpFrame = try alice.pqBootstrapBegin()
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame)
		try alice.pqBootstrapJoin(welcomeFrame)

		let prepared = try alice.prepareToEncrypt()
		XCTAssertTrue(prepared.didCommit)
		let frame = try alice.encrypt(Data("bound".utf8))

		let (staple, _, _) = try Frames.decodeMessageFrame(frame)
		let (tBytes, _) = try Frames.decodeAPQPrivateMessage(staple)

		try withDeployedWireWidth {
			guard
				case .publicMessage(let tPub) = try MLS.RFC9420.Message(
					mlsEncoded: tBytes)
			else {
				XCTFail("expected a publicMessage classical commit")
				return
			}
			guard case .commit(let commit) = tPub.content.content else {
				XCTFail("expected a commit")
				return
			}
			XCTAssertEqual(commit.proposals.count, 3)

			var pskComponentIDs: Set<UInt16> = []
			var appDataUpdateCount = 0
			for entry in commit.proposals {
				guard case .proposal(let proposal) = entry else {
					XCTFail("expected a by-value proposal, got a reference")
					continue
				}
				switch proposal {
				case .preSharedKey(.application(let componentID, _, _)):
					pskComponentIDs.insert(componentID.rawValue)
				case .appDataUpdate:
					appDataUpdateCount += 1
				default:
					XCTFail("unexpected proposal type in bind commit")
				}
			}
			XCTAssertEqual(pskComponentIDs, [0xFF01, 0xFF02])
			XCTAssertEqual(appDataUpdateCount, 1)
		}

		// Consumption alternative (also verified): the cross-party PSK's
		// exporter leaf on Alice's own receive group is spent by the
		// discharge, so re-exporting it throws.
		XCTAssertThrowsError(
			try MLS.Combiner.ExportedPsk.export(
				from: &alice.recvGroup!.classical,
				SessionTestSupport.classicalProvider,
				componentID: TwoMLSSession.crossPartyComponentID))

		_ = try bob.processIncoming(frame)
	}
}
