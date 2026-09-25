import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import Testing
import TwoMLSPQCrypto

@testable import TwoMLSPQSession

/// §A.3: KP′ exchange + Bob founds Group_B.pq + Alice joins (chunk A), then
/// the bind — Alice's owed PQ commit discharged against a licensed classical
/// commit, stapled `0x05`, turn returned to Bob (chunk B).
@Suite struct BootstrapTests {
	@available(iOS 26, macOS 26, *)
	@Test func fullBootstrapRoundReachesFullyEstablished() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		#expect(alice.myPQTurn)
		#expect(!bob.myPQTurn)
		#expect(!alice.isFullyEstablished)
		#expect(!bob.isFullyEstablished)

		let kpFrame = try alice.pqBootstrapBegin().frame
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame).frame
		#expect(bob.isFullyEstablished)
		#expect(!alice.isFullyEstablished)

		_ = try alice.pqBootstrapJoin(welcomeFrame)
		#expect(alice.isFullyEstablished)
	}

	/// The joined Group_B.pq's mirror `APQInfo` and epoch land as
	/// expected: `pqEpoch == 1`, `tEpoch` unbound, and both rosters are 2.
	@available(iOS 26, macOS 26, *)
	@Test func joinedPQHalfHasMirrorAPQInfoAndEpochOne() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let kpFrame = try alice.pqBootstrapBegin().frame
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame).frame
		_ = try alice.pqBootstrapJoin(welcomeFrame)

		let alicePQ = try #require(alice.recvGroup?.pq)
		let bobPQ = try #require(bob.sendGroup?.pq)
		#expect(alicePQ.context.epoch == 1)
		#expect(bobPQ.context.epoch == 1)
		#expect(alicePQ.tree.nonBlankLeaves().count == 2)
		#expect(bobPQ.tree.nonBlankLeaves().count == 2)

		let infoRaw = try MLS.Combiner.APQInfo.read(
			fromExtensionsOf: alicePQ.context,
			type: MLS.Combiner.Codepoints.deployed.apqInfoExtensionType)
		let info = try #require(infoRaw)
		#expect(info.tEpoch == epochUnbound)
		#expect(info.pqEpoch == 1)
		#expect(info.pqSessionGroupID == alicePQ.context.groupID)
	}

	// MARK: - Negatives

	@available(iOS 26, macOS 26, *)
	@Test func receiveRejectsNonThirtyTwoByteCommitment() throws {
		let alice = try SessionTestSupport.identity("alice")
		let bob = try SessionTestSupport.identity("bob")
		let initiated = try TwoMLSSession.initiate(
			identity: alice, their: bob.keyPackage,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		#expect(throws: TwoMLSError.bootstrapKPMismatch) {
			try TwoMLSSession.receive(
				identity: bob, welcome: initiated.welcome,
				theirClassicalKeyPackage: alice.keyPackage.classical,
				bootstrapKPCommitment: Data([1, 2, 3]),
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		}
	}

	@available(iOS 26, macOS 26, *)
	@Test func respondRejectsWrongCommitment() throws {
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
		let frame = try bobSession.encrypt(Data("bob-hello".utf8)).frame
		_ = try aliceSession.processIncomingDecrypted(frame)

		let kpFrame = try aliceSession.pqBootstrapBegin().frame
		#expect(throws: TwoMLSError.bootstrapKPMismatch) {
			try bobSession.pqBootstrapRespond(kpFrame)
		}
	}

	@available(iOS 26, macOS 26, *)
	@Test func beginRejectsWhenNotMyTurn() throws {
		var (_, bob) = try SessionTestSupport.establishedAndExchanged()
		#expect(throws: TwoMLSError.sessionNotReady) {
			try bob.pqBootstrapBegin()
		}
	}

	// MARK: - Chunk B: the bind

	/// The full A.3 round: KP′ exchange, the bind's discharge (licensed by
	/// Bob's establishment-time frame), and the turn returning to
	/// Bob. Asserts the exact epoch positions: only
	/// Group_A.pq (ASG-PQ) moves 1 -> 2; Group_B's halves stay where the
	/// bootstrap left them.
	@available(iOS 26, macOS 26, *)
	@Test func fullBootstrapRoundBindsAndReturnsTurn() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()

		let kpFrame = try alice.pqBootstrapBegin().frame
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame).frame
		#expect(bob.isFullyEstablished)

		// The fidelity proof (D1): each side's PQ leaf presents its
		// OWN independent pq signing pair, distinct from its classical pair
		// — mirrors the deployed Rust `CombinerClient`'s two independent
		// per-half signing keys. Bob's Group_B.pq is founded fresh here
		// (`pqBootstrapRespond`), so this is provable immediately.
		let bobOwnPQLeaf = try TwoMLSSession.ownLeaf(of: try #require(bob.sendGroup?.pq))
		#expect(bobOwnPQLeaf.signatureKey == bob.leafKeys.sendPQ.current?.signatureKey)
		#expect(bobOwnPQLeaf.signatureKey != bob.identity.pqSignatureKey)
		#expect(bobOwnPQLeaf.signatureKey != bob.identity.signatureKey)

		_ = try alice.pqBootstrapJoin(welcomeFrame)
		#expect(alice.isFullyEstablished)
		#expect(alice.owedBind != nil)

		// Symmetrically, Alice's Group_A.pq own-leaf (present from
		// construction — Group_A is a full pair from `initiate`).
		let aliceOwnPQLeaf = try TwoMLSSession.ownLeaf(
			of: try #require(alice.sendGroup?.pq))
		#expect(
			aliceOwnPQLeaf.signatureKey == alice.leafKeys.sendPQ.current?.signatureKey)
		#expect(aliceOwnPQLeaf.signatureKey != alice.identity.pqSignatureKey)
		#expect(aliceOwnPQLeaf.signatureKey != alice.identity.signatureKey)

		// Bob's establishment-time frame already licensed Alice, so
		// the very next `prepareToEncrypt` discharges immediately.
		let prepared = try alice.prepareToEncrypt()
		#expect(prepared.didCommit)
		#expect(alice.owedBind == nil)
		let frame = try alice.encrypt(Data("bound".utf8)).frame

		// Opened via `bob` (the recipient).
		let (staple, _, _) = try Frames.decodeMessageFrame(bob.openOrRaw(frame))
		#expect(Frames.stapleKind(staple.first!) == .apqPrivateMessage)

		let decrypted = try bob.processIncomingDecrypted(frame)
		#expect(decrypted.applicationMessage == Data("bound".utf8))
		#expect(bob.myPQTurn)

		let alicePQEpoch = try #require(alice.sendGroup?.pq?.context.epoch)
		let bobRecvPQEpoch = try #require(bob.recvGroup?.pq?.context.epoch)
		let aliceClassicalEpoch = try #require(alice.sendGroup?.classical.context.epoch)
		let bobRecvClassicalEpoch = try #require(bob.recvGroup?.classical.context.epoch)
		let bobSendPQEpoch = try #require(bob.sendGroup?.pq?.context.epoch)
		let aliceRecvPQEpoch = try #require(alice.recvGroup?.pq?.context.epoch)
		#expect(alicePQEpoch == 2)
		#expect(bobRecvPQEpoch == 2)
		#expect(aliceClassicalEpoch == 2)
		#expect(bobRecvClassicalEpoch == 2)
		#expect(bobSendPQEpoch == 1)
		#expect(aliceRecvPQEpoch == 1)
	}

	/// The `0x05` staple re-rides every Alice→Bob frame until her next
	/// commit. A second frame after the bind must decrypt without re-applying
	/// (no throw, no double epoch-advance, no re-consuming the spent PSKs).
	@available(iOS 26, macOS 26, *)
	@Test func secondFrameAfterBindIsIdempotent() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let kpFrame = try alice.pqBootstrapBegin().frame
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame).frame
		_ = try alice.pqBootstrapJoin(welcomeFrame)

		_ = try alice.prepareToEncrypt()
		let boundFrame = try alice.encrypt(Data("bound".utf8)).frame
		_ = try bob.processIncomingDecrypted(boundFrame)

		let secondPrepared = try alice.prepareToEncrypt()
		#expect(!secondPrepared.didCommit)
		let secondFrame = try alice.encrypt(Data("again".utf8)).frame

		let decrypted = try bob.processIncomingDecrypted(secondFrame)
		#expect(decrypted.applicationMessage == Data("again".utf8))

		let bobRecvPQEpoch = try #require(bob.recvGroup?.pq?.context.epoch)
		let bobRecvClassicalEpoch = try #require(bob.recvGroup?.classical.context.epoch)
		#expect(bobRecvPQEpoch == 2)
		#expect(bobRecvClassicalEpoch == 2)
	}

	// MARK: - Chunk B negatives

	/// Discharge attempted before the license: `owedBind` stays parked and the
	/// staple is not re-stapled `0x05` until Bob's inbound Upd has evidenced
	/// applying Alice's current send epoch.
	@available(iOS 26, macOS 26, *)
	@Test func dischargeWithoutLicenseDoesNotCommit() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let kpFrame = try alice.pqBootstrapBegin().frame
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame).frame
		_ = try alice.pqBootstrapJoin(welcomeFrame)
		#expect(alice.owedBind != nil)

		// Simulate Bob's licensing Upd never having arrived.
		alice.peerAppliedSendEpoch = nil

		let prepared = try alice.prepareToEncrypt()
		#expect(!prepared.didCommit)
		#expect(alice.owedBind != nil)

		let frame = try alice.encrypt(Data("still-owed".utf8)).frame
		// Opened via `bob` (the recipient).
		let (staple, _, _) = try Frames.decodeMessageFrame(bob.openOrRaw(frame))
		#expect(Frames.stapleKind(staple.first!) != .apqPrivateMessage)
	}

	/// `dischargeOwedBindIfLicensed`'s own re-check catches an `owedBind`
	/// whose parked epochs no longer match the live send groups, before ever
	/// building a wire commit — the guard `verifyFullCommitAttestation`
	/// backstops on the receive side (the attestation check is the
	/// combiner's; this is the discharge-side belt).
	@available(iOS 26, macOS 26, *)
	@Test func tamperedOwedBindEpochThrowsEpochDesync() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let kpFrame = try alice.pqBootstrapBegin().frame
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame).frame
		_ = try alice.pqBootstrapJoin(welcomeFrame)

		alice.owedBind?.pqEpoch += 1

		#expect(throws: TwoMLSError.epochDesync) {
			try alice.prepareToEncrypt()
		}
	}

	/// A bit-flip inside the `0x05` staple's PQ commit section breaks its
	/// framing signature — `applyBind` must reject it, not silently apply a
	/// forged commit or burn the single-shot cross-party PSK leaf. Also
	/// pins the rollback (Bob's receive groups are untouched by the
	/// rejected attempt) and that the genuine frame — and a subsequent
	/// Bob→Alice post-bind message — still apply cleanly afterward.
	@available(iOS 26, macOS 26, *)
	@Test func corruptedBindStapleIsRejected() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let kpFrame = try alice.pqBootstrapBegin().frame
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame).frame
		_ = try alice.pqBootstrapJoin(welcomeFrame)
		_ = try alice.prepareToEncrypt()
		let frame = try alice.encrypt(Data("bound".utf8)).frame

		// Opened via `bob` (the recipient); the reconstructed
		// `corruptedFrame` below is fed to `bob.processIncoming` raw and
		// passes straight through its `openOrRaw` (an unsealable blob is
		// returned as-is).
		let (staple, proposal, app) = try Frames.decodeMessageFrame(bob.openOrRaw(frame))
		let (t, pq) = try Frames.decodeAPQPrivateMessage(staple)
		var corruptedPQ = pq
		corruptedPQ[corruptedPQ.count / 2] ^= 0xFF
		let corruptedStaple = Frames.encodeAPQPrivateMessage(t: t, pq: corruptedPQ)
		let corruptedFrame = Frames.encodeMessageFrame(
			staple: corruptedStaple, proposal: proposal, app: app)

		let bobRecvClassicalEpochBefore = bob.recvGroup?.classical.context.epoch
		let bobRecvPQEpochBefore = bob.recvGroup?.pq?.context.epoch

		#expect(throws: (any Error).self) {
			try bob.processIncomingDecrypted(corruptedFrame)
		}

		#expect(bob.recvGroup?.classical.context.epoch == bobRecvClassicalEpochBefore)
		#expect(bob.recvGroup?.pq?.context.epoch == bobRecvPQEpochBefore)

		// The genuine frame still applies cleanly after the rejected attempt.
		let decrypted = try bob.processIncomingDecrypted(frame)
		#expect(decrypted.applicationMessage == Data("bound".utf8))
		#expect(bob.myPQTurn)

		// Bob -> Alice post-bind: the license re-stamps (against Alice's now
		// bind-advanced send epoch), and the `0x01` welcome staple Bob still
		// rides (Group_B.classical never moved) idempotently skips, since
		// Alice already joined it.
		_ = try bob.prepareToEncrypt()
		let postBindFrame = try bob.encrypt(Data("post-bind".utf8)).frame
		let aliceDecrypted = try alice.processIncomingDecrypted(postBindFrame)
		#expect(aliceDecrypted.applicationMessage == Data("post-bind".utf8))
	}

	// MARK: - FULL bind must name its half's PSK

	/// A hand-built PQ bind commit carrying the FULL-commit attestation but NO
	/// injected external `S` (`LE64(epoch)‖group_id‖0x52`) proposal. The commit
	/// is framed from the caller-supplied `sendPQ` snapshot, which must be the
	/// PRE-apply Group_A.pq state (epoch 1) — `owePQBind` applies the genuine
	/// PQ commit to the session's own copy, so building after the join would
	/// frame at the post-apply epoch and fail framing, not reach the guard.
	@available(iOS 26, macOS 26, *)
	private func bindPQCommitWithoutInjectedS(
		sendPQ: MLS.RFC9420.Group, signingKey: MLS.SignatureSecretKey,
		tEpoch: UInt64, pqEpoch: UInt64
	) throws -> Data {
		try withDeployedWireConventions {
			let attestation = MLS.Combiner.ApqInfoUpdate(
				tEpoch: tEpoch, pqEpoch: pqEpoch)
			let proposals: [MLS.RFC9420.ProposalOrRef] = [
				.proposal(
					.custom(
						type: .init(.appDataUpdate),
						body: try attestation.appDataUpdate(
							componentID: MLS.Combiner.Codepoints
								.deployed.apqComponentID
						).mlsEncoded()))
			]
			let transition = try sendPQ.committing(
				SessionTestSupport.pqProvider, proposals: proposals,
				signingKey: signingKey,
				randomness: try .generate(SessionTestSupport.pqProvider),
				includePath: false, framing: .publicMessage, psk: { _ in nil })
			return try transition.takeOutput().message.mlsEncoded()
		}
	}

	/// A hand-built classical bind commit carrying the FULL-commit attestation
	/// but NO `apq_psk` (`0xFF01`) proposal.
	@available(iOS 26, macOS 26, *)
	private func bindClassicalCommitWithoutAPQPSK(
		alice: TwoMLSSession, aliceIdentity: TwoMLSIdentity, owed: OwedBind
	) throws -> Data {
		try withDeployedWireConventions {
			let sendClassical = try #require(alice.sendGroup?.classical)
			let attestation = MLS.Combiner.ApqInfoUpdate(
				tEpoch: owed.tEpoch, pqEpoch: owed.pqEpoch)
			let proposals: [MLS.RFC9420.ProposalOrRef] = [
				.proposal(
					.custom(
						type: .init(.appDataUpdate),
						body: try attestation.appDataUpdate(
							componentID: MLS.Combiner.Codepoints
								.deployed.apqComponentID
						).mlsEncoded()))
			]
			let transition = try sendClassical.committing(
				SessionTestSupport.classicalProvider, proposals: proposals,
				signingKey: try alice.sendClassicalSigningKey(),
				randomness: try .generate(SessionTestSupport.classicalProvider),
				includePath: true, framing: .publicMessage, psk: { _ in nil })
			return try transition.takeOutput().message.mlsEncoded()
		}
	}

	/// The PQ-half arm: a hand-built bind whose PQ commit carries the
	/// attestation but omits the injected external `S` is refused with
	/// `.missingBindPSK` after framing/membership verification. Nothing on
	/// Bob moves, and the genuine bind still applies afterward.
	@available(iOS 26, macOS 26, *)
	@Test func bindWithoutTheInjectedPQPSKIsRejected() throws {
		let established = try SessionTestSupport.established()
		var alice = established.alice
		var bob = established.bob
		let aliceIdentity = established.aliceIdentity

		_ = try bob.prepareToEncrypt()
		let helloFrame = try bob.encrypt(Data("bob-hello".utf8)).frame
		_ = try alice.processIncomingDecrypted(helloFrame)

		let kpFrame = try alice.pqBootstrapBegin().frame
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame).frame
		// Snapshot Group_A.pq at its PRE-apply epoch-1 state and forge the no-S
		// PQ commit BEFORE the join's `owePQBind` applies the genuine PQ commit
		// to the session's own copy — after that, the group frames at epoch 2
		// and would fail framing instead of reaching the PSK guard.
		let pqCommit = try bindPQCommitWithoutInjectedS(
			sendPQ: try #require(alice.sendGroup?.pq),
			signingKey: try alice.sendPQSigningKey(),
			tEpoch: 2, pqEpoch: 2)
		_ = try alice.pqBootstrapJoin(welcomeFrame)
		let owed = try #require(alice.owedBind)
		#expect(owed.tEpoch == 2)
		#expect(owed.pqEpoch == 2)

		let classicalCommit = try bindClassicalCommitWithoutAPQPSK(
			alice: alice, aliceIdentity: aliceIdentity, owed: owed)
		let badStaple = Frames.encodeAPQPrivateMessage(t: classicalCommit, pq: pqCommit)

		let bobPQEpochBefore = try #require(bob.recvGroup?.pq?.context.epoch)
		let bobClassicalEpochBefore = try #require(bob.recvGroup?.classical.context.epoch)
		let bobLastSendPQExportedBefore = bob.lastSendPQExported
		#expect(bob.pqInflight != nil)

		_ = try bob.prepareToEncrypt()
		let carrierFrame = try bob.encrypt(Data("carrier".utf8)).frame
		// Opened via `alice` (the recipient) — the app section is a
		// throwaway filler `bob.processIncoming` never reaches (the bind
		// staple is rejected first), so which peer's window opens it
		// doesn't otherwise matter.
		let (_, proposalSection, appSection) = try Frames.decodeMessageFrame(
			alice.openOrRaw(carrierFrame))
		let badFrame = Frames.encodeMessageFrame(
			staple: badStaple, proposal: proposalSection, app: appSection)

		#expect(throws: TwoMLSError.missingBindPSK) {
			try bob.processIncomingDecrypted(badFrame)
		}
		#expect(bob.recvGroup?.pq?.context.epoch == bobPQEpochBefore)
		#expect(bob.recvGroup?.classical.context.epoch == bobClassicalEpochBefore)
		#expect(bob.isFullyEstablished)
		#expect(bob.pqInflight != nil)
		#expect(bob.lastSendPQExported == bobLastSendPQExportedBefore)

		// The genuine bind still applies cleanly afterward (rollback proof).
		let prepared = try alice.prepareToEncrypt()
		#expect(prepared.didCommit)
		let boundFrame = try alice.encrypt(Data("bound".utf8)).frame
		let decrypted = try bob.processIncomingDecrypted(boundFrame)
		#expect(decrypted.didApplyRemoteCommit)
		#expect(bob.recvGroup?.pq?.context.epoch == bobPQEpochBefore + 1)
		#expect(bob.recvGroup?.classical.context.epoch == bobClassicalEpochBefore + 1)
	}

	/// The classical-half arm: the GENUINE PQ commit rides along (so the guard
	/// under test, not an earlier one, fires), but the classical half omits
	/// the `apq_psk` (`0xFF01`) proposal. De-conflated onto the library's
	/// `MLS.Combiner.verifyFullCommit` (`verifyApqPskBound` half): the
	/// `ResolutionRecord` never observed the current PQ epoch's `apq_psk`, so
	/// this now throws `MLS.Combiner.Error.apqPskNotBound` rather than the
	/// port's own (deleted) `.missingBindPSK` guard. Nothing on Bob moves —
	/// in particular `lastSendPQExported` stays unwritten, which is what the
	/// deferred-stamp fix buys.
	@available(iOS 26, macOS 26, *)
	@Test func bindWithoutTheClassicalAPQPSKIsRejected() throws {
		let established = try SessionTestSupport.established()
		var alice = established.alice
		var bob = established.bob
		let aliceIdentity = established.aliceIdentity

		_ = try bob.prepareToEncrypt()
		let helloFrame = try bob.encrypt(Data("bob-hello".utf8)).frame
		_ = try alice.processIncomingDecrypted(helloFrame)

		let kpFrame = try alice.pqBootstrapBegin().frame
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame).frame
		_ = try alice.pqBootstrapJoin(welcomeFrame)
		let owed = try #require(alice.owedBind)

		let pqCommit = owed.pqCommitMessage
		let classicalCommit = try bindClassicalCommitWithoutAPQPSK(
			alice: alice, aliceIdentity: aliceIdentity, owed: owed)
		let badStaple = Frames.encodeAPQPrivateMessage(t: classicalCommit, pq: pqCommit)

		let bobPQEpochBefore = try #require(bob.recvGroup?.pq?.context.epoch)
		let bobClassicalEpochBefore = try #require(bob.recvGroup?.classical.context.epoch)
		#expect(bob.lastSendPQExported == nil)
		#expect(bob.pqInflight != nil)

		_ = try bob.prepareToEncrypt()
		let carrierFrame = try bob.encrypt(Data("carrier".utf8)).frame
		// Opened via `alice` (the recipient) — the app section is a
		// throwaway filler `bob.processIncoming` never reaches (the bind
		// staple is rejected first), so which peer's window opens it
		// doesn't otherwise matter.
		let (_, proposalSection, appSection) = try Frames.decodeMessageFrame(
			alice.openOrRaw(carrierFrame))
		let badFrame = Frames.encodeMessageFrame(
			staple: badStaple, proposal: proposalSection, app: appSection)

		#expect(throws: MLS.Combiner.Error.apqPskNotBound) {
			try bob.processIncomingDecrypted(badFrame)
		}
		#expect(bob.recvGroup?.pq?.context.epoch == bobPQEpochBefore)
		#expect(bob.recvGroup?.classical.context.epoch == bobClassicalEpochBefore)
		#expect(bob.isFullyEstablished)
		#expect(bob.pqInflight != nil)
		#expect(bob.lastSendPQExported == nil)

		// The genuine bind still applies cleanly afterward.
		let prepared = try alice.prepareToEncrypt()
		#expect(prepared.didCommit)
		let boundFrame = try alice.encrypt(Data("bound".utf8)).frame
		let decrypted = try bob.processIncomingDecrypted(boundFrame)
		#expect(decrypted.didApplyRemoteCommit)
		#expect(bob.recvGroup?.pq?.context.epoch == bobPQEpochBefore + 1)
		#expect(bob.recvGroup?.classical.context.epoch == bobClassicalEpochBefore + 1)
	}

	// MARK: - Attestation presence/duplication (the wrapped FULL-commit attestation)

	/// Drive the pair to Alice owing the bind (the full §A.3 bootstrap round).
	@available(iOS 26, macOS 26, *)
	private func bootstrapToOwedBind() throws -> (
		alice: TwoMLSSession, bob: TwoMLSSession, aliceIdentity: TwoMLSIdentity,
		owed: OwedBind
	) {
		let established = try SessionTestSupport.established()
		var alice = established.alice
		var bob = established.bob
		let aliceIdentity = established.aliceIdentity

		_ = try bob.prepareToEncrypt()
		let helloFrame = try bob.encrypt(Data("bob-hello".utf8)).frame
		_ = try alice.processIncomingDecrypted(helloFrame)

		let kpFrame = try alice.pqBootstrapBegin().frame
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame).frame
		_ = try alice.pqBootstrapJoin(welcomeFrame)
		return (
			alice: alice, bob: bob, aliceIdentity: aliceIdentity,
			owed: try #require(alice.owedBind)
		)
	}

	/// A hand-built classical bind commit carrying the `apq_psk` (`0xFF01`) and
	/// the given number of wrapped FULL-commit attestation proposals — the
	/// absent (zero) and duplicate (two) cases the attestation check's nil and
	/// duplicate arms reject.
	@available(iOS 26, macOS 26, *)
	private func bindClassicalCommit(
		alice: TwoMLSSession, aliceIdentity: TwoMLSIdentity, owed: OwedBind,
		attestationCount: Int
	) throws -> Data {
		try withDeployedWireConventions {
			let sendClassical = try #require(alice.sendGroup?.classical)
			var pqForExport = try #require(alice.sendGroup?.pq)
			let apqPSK = try MLS.Combiner.ExportedPsk.export(
				from: &pqForExport, SessionTestSupport.pqProvider,
				componentID: MLS.Combiner.Codepoints.deployed.apqComponentID)
			var store = MLS.Combiner.PSKStore()
			store.register(apqPSK)

			var proposals: [MLS.RFC9420.ProposalOrRef] = [
				.proposal(
					apqPSK.proposal(
						nonce: SessionTestSupport.classicalProvider
							.randomBytes(
								SessionTestSupport.classicalProvider
									.hashSize)))
			]
			let attestation = MLS.Combiner.ApqInfoUpdate(
				tEpoch: owed.tEpoch, pqEpoch: owed.pqEpoch)
			for _ in 0..<attestationCount {
				proposals.append(
					.proposal(
						.custom(
							type: .init(.appDataUpdate),
							body: try attestation.appDataUpdate(
								componentID: MLS.Combiner.Codepoints
									.deployed.apqComponentID
							).mlsEncoded())))
			}

			let transition = try sendClassical.committing(
				SessionTestSupport.classicalProvider, proposals: proposals,
				signingKey: try alice.sendClassicalSigningKey(),
				randomness: try .generate(SessionTestSupport.classicalProvider),
				includePath: true, framing: .publicMessage, psk: store.resolver())
			return try transition.takeOutput().message.mlsEncoded()
		}
	}

	/// A classical bind commit carrying NO attestation proposal cannot pass the
	/// shape allow-list (a FULL bind requires its `.appDataUpdate` event) — the
	/// absent-attestation rejection, thrown before any apply. Nothing on Bob
	/// moves, and the genuine bind still applies afterward.
	@available(iOS 26, macOS 26, *)
	@Test func bindRejectsAbsentAttestation() throws {
		let (alice, bobFixture, aliceIdentity, owed) = try bootstrapToOwedBind()
		var bob = bobFixture

		let pqCommit = owed.pqCommitMessage
		let classicalCommit = try bindClassicalCommit(
			alice: alice, aliceIdentity: aliceIdentity, owed: owed, attestationCount: 0)
		let badStaple = Frames.encodeAPQPrivateMessage(t: classicalCommit, pq: pqCommit)

		let bobPQEpochBefore = try #require(bob.recvGroup?.pq?.context.epoch)
		let bobClassicalEpochBefore = try #require(bob.recvGroup?.classical.context.epoch)

		_ = try bob.prepareToEncrypt()
		let carrierFrame = try bob.encrypt(Data("carrier".utf8)).frame
		// Opened via `alice` (the recipient) — the app section is a
		// throwaway filler `bob.processIncoming` never reaches (the bind
		// staple is rejected first), so which peer's window opens it
		// doesn't otherwise matter.
		let (_, proposalSection, appSection) = try Frames.decodeMessageFrame(
			alice.openOrRaw(carrierFrame))
		let badFrame = Frames.encodeMessageFrame(
			staple: badStaple, proposal: proposalSection, app: appSection)

		#expect(throws: TwoMLSError.invalidBindEffects) {
			try bob.processIncomingDecrypted(badFrame)
		}
		#expect(bob.recvGroup?.pq?.context.epoch == bobPQEpochBefore)
		#expect(bob.recvGroup?.classical.context.epoch == bobClassicalEpochBefore)
		#expect(bob.pqInflight != nil)
	}

	/// A classical bind commit carrying TWO identical wrapped attestation
	/// proposals (the PQ half remains the genuine one) clears the shape
	/// allow-list and is then rejected by the attestation check's duplicate arm
	/// (`.attestationMismatch`), again before anything applies.
	@available(iOS 26, macOS 26, *)
	@Test func bindRejectsDuplicateAttestations() throws {
		let (alice, bobFixture, aliceIdentity, owed) = try bootstrapToOwedBind()
		var bob = bobFixture

		let pqCommit = owed.pqCommitMessage
		let classicalCommit = try bindClassicalCommit(
			alice: alice, aliceIdentity: aliceIdentity, owed: owed, attestationCount: 2)
		let badStaple = Frames.encodeAPQPrivateMessage(t: classicalCommit, pq: pqCommit)

		let bobPQEpochBefore = try #require(bob.recvGroup?.pq?.context.epoch)
		let bobClassicalEpochBefore = try #require(bob.recvGroup?.classical.context.epoch)

		_ = try bob.prepareToEncrypt()
		let carrierFrame = try bob.encrypt(Data("carrier".utf8)).frame
		// Opened via `alice` (the recipient) — the app section is a
		// throwaway filler `bob.processIncoming` never reaches (the bind
		// staple is rejected first), so which peer's window opens it
		// doesn't otherwise matter.
		let (_, proposalSection, appSection) = try Frames.decodeMessageFrame(
			alice.openOrRaw(carrierFrame))
		let badFrame = Frames.encodeMessageFrame(
			staple: badStaple, proposal: proposalSection, app: appSection)

		#expect(throws: MLS.Combiner.Error.attestationMismatch) {
			try bob.processIncomingDecrypted(badFrame)
		}
		#expect(bob.recvGroup?.pq?.context.epoch == bobPQEpochBefore)
		#expect(bob.recvGroup?.classical.context.epoch == bobClassicalEpochBefore)
		#expect(bob.pqInflight != nil)
	}

	// MARK: - The cross-half attestation check, pinned

	/// The receive-side cross-half attestation check
	/// (`MLS.Combiner.verifyFullCommitAttestation`) is otherwise unpinned by
	/// this suite: deleting it still passes every other test. Hand-build a
	/// classical bind commit whose attestation lies about the post-commit
	/// PQ epoch (`owed.pqEpoch + 1` instead of the real `owed.pqEpoch`),
	/// staple it alongside the genuine, untouched PQ commit, and confirm
	/// Bob rejects the pair and rolls back rather than applying one half.
	@available(iOS 26, macOS 26, *)
	@Test func wrongClassicalAttestationIsRejectedAndRolledBack() throws {
		let established = try SessionTestSupport.established()
		var alice = established.alice
		var bob = established.bob
		let aliceIdentity = established.aliceIdentity

		_ = try bob.prepareToEncrypt()
		let helloFrame = try bob.encrypt(Data("bob-hello".utf8)).frame
		_ = try alice.processIncomingDecrypted(helloFrame)

		let kpFrame = try alice.pqBootstrapBegin().frame
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame).frame
		_ = try alice.pqBootstrapJoin(welcomeFrame)

		let owed = try #require(alice.owedBind)
		var send = try #require(alice.sendGroup)
		var recv = try #require(alice.recvGroup)

		let bobRecvClassicalEpochBefore = try #require(
			bob.recvGroup?.classical.context.epoch)
		let bobRecvPQEpochBefore = try #require(bob.recvGroup?.pq?.context.epoch)

		var pqForExport = try #require(send.pq)
		let apqPSK = try MLS.Combiner.ExportedPsk.export(
			from: &pqForExport, SessionTestSupport.pqProvider,
			componentID: MLS.Combiner.Codepoints.deployed.apqComponentID)
		send.pq = pqForExport

		var store = MLS.Combiner.PSKStore()
		store.register(apqPSK)

		// Deliberately WRONG: the real post-commit pq epoch is `owed.pqEpoch`.
		let badAttestation = MLS.Combiner.ApqInfoUpdate(
			tEpoch: owed.tEpoch, pqEpoch: owed.pqEpoch + 1)
		// The `.custom` wrapped form, matching what `applyBind`'s
		// `withDeployedWireConventions` ambient now expects to decode — a bare
		// `.appDataUpdate` would misparse under that ambient instead of
		// reaching the attestation check this test targets. The body encode
		// itself must run under the same ambient (the deployed `.uint32`
		// `ComponentID` width), since — unlike the typed `.appDataUpdate` arm,
		// which defers encoding until `committing` below — `.custom`'s `body`
		// is already-encoded `Data` at construction time.
		let proposals: [MLS.RFC9420.ProposalOrRef] = [
			.proposal(
				apqPSK.proposal(
					nonce: SessionTestSupport.classicalProvider.randomBytes(
						SessionTestSupport.classicalProvider.hashSize))),
			.proposal(
				.custom(
					type: .init(.appDataUpdate),
					body: try withDeployedWireConventions {
						try badAttestation.appDataUpdate(
							componentID: MLS.Combiner.Codepoints
								.deployed.apqComponentID
						).mlsEncoded()
					})),
		]

		let (proposalMessage, _) = try recv.classical.proposeUpdate(
			SessionTestSupport.classicalProvider,
			signingKey: try alice.recvClassicalSigningKey(),
			framing: .publicMessage)
		let proposalBytes = try proposalMessage.mlsEncoded()
		let proposalHash = try SessionTestSupport.classicalProvider.hash(proposalBytes)

		// `Transition`/`SentCommit`/`PendingCommit` are `~Copyable`, so they
		// cannot cross `withDeployedWireConventions`'s generic `<T>` boundary — the
		// whole commit/adopt/apply sequence runs inside the closure, which
		// hands back only the `Copyable` results needed outside it.
		let (commitBytes, advancedClassical): (Data, MLS.RFC9420.Group) =
			try withDeployedWireConventions {
				let transition = try send.classical.committing(
					SessionTestSupport.classicalProvider, proposals: proposals,
					signingKey: try alice.sendClassicalSigningKey(),
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
			authenticatedData: proposalHash,
			signingKey: try alice.sendClassicalSigningKey())
		let appBytes = try MLS.RFC9420.Message.privateMessage(appPM).mlsEncoded()

		let badStaple = Frames.encodeAPQPrivateMessage(
			t: commitBytes, pq: owed.pqCommitMessage)
		let proposalSection = Frames.encodeProposalSection(
			proposing: aliceIdentity.clientID, message: proposalBytes)
		let frame = Frames.encodeMessageFrame(
			staple: badStaple, proposal: proposalSection, app: appBytes)

		#expect(throws: MLS.Combiner.Error.attestationMismatch) {
			try bob.processIncomingDecrypted(frame)
		}

		#expect(bob.recvGroup?.classical.context.epoch == bobRecvClassicalEpochBefore)
		#expect(bob.recvGroup?.pq?.context.epoch == bobRecvPQEpochBefore)
	}

	// MARK: - The reverse-direction 0xFF02, pinned

	/// The bind's classical commit must carry both application PSKs
	/// (`apq_psk` `0xFF01` and the cross-party `0xFF02`) plus exactly one
	/// `AppDataUpdate` attestation — three by-value proposals, none by
	/// reference. Otherwise-unpinned: the cross-party injection
	/// (`dischargeOwedBindIfLicensed`'s `0xFF02` branch) could silently stop
	/// firing with every other test still green.
	@available(iOS 26, macOS 26, *)
	@Test func bindCommitCarriesBothApplicationPSKsAndAttestation() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let kpFrame = try alice.pqBootstrapBegin().frame
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame).frame
		_ = try alice.pqBootstrapJoin(welcomeFrame)

		let prepared = try alice.prepareToEncrypt()
		#expect(prepared.didCommit)
		let frame = try alice.encrypt(Data("bound".utf8)).frame

		// Opened via `bob` (the recipient).
		let (staple, _, _) = try Frames.decodeMessageFrame(bob.openOrRaw(frame))
		let (tBytes, _) = try Frames.decodeAPQPrivateMessage(staple)

		try withDeployedWireConventions {
			guard
				case .publicMessage(let tPub) = try MLS.RFC9420.Message(
					mlsEncoded: tBytes)
			else {
				Issue.record("expected a publicMessage classical commit")
				return
			}
			guard case .commit(let commit) = tPub.content.content else {
				Issue.record("expected a commit")
				return
			}
			#expect(commit.proposals.count == 3)

			var pskComponentIDs: Set<UInt16> = []
			var appDataUpdateCount = 0
			for entry in commit.proposals {
				guard case .proposal(let proposal) = entry else {
					Issue.record(
						"expected a by-value proposal, got a reference")
					continue
				}
				switch proposal {
				case .preSharedKey(.application(let componentID, _, _)):
					pskComponentIDs.insert(componentID.rawValue)
				case .custom(let type, _) where type == .init(.appDataUpdate):
					// The deployed wrapped form — `Proposal.custom`, decoded
					// under the `customProposalTypes` ambient — not the typed
					// `.appDataUpdate` arm.
					appDataUpdateCount += 1
				default:
					Issue.record("unexpected proposal type in bind commit")
				}
			}
			#expect(pskComponentIDs == [0xFF01, 0xFF02])
			#expect(appDataUpdateCount == 1)
		}

		// Consumption alternative (also verified): the cross-party PSK's
		// exporter leaf on Alice's own receive group is spent by the
		// discharge, so re-exporting it throws.
		#expect(throws: (any Error).self) {
			try MLS.Combiner.ExportedPsk.export(
				from: &alice.recvGroup!.classical,
				SessionTestSupport.classicalProvider,
				componentID: TwoMLSSession.crossPartyComponentID)
		}

		_ = try bob.processIncomingDecrypted(frame)
	}

	// MARK: - KP′ is the identity's own PQ half

	/// KP′ is `identity.keyPackage.pq` itself, not a separately minted KP —
	/// survives restore, and once Alice joins Group_B.pq off it at §A.3,
	/// recv-PQ presents exactly that key.
	@available(iOS 26, macOS 26, *)
	@Test func kPPrimeIsTheIdentityPQHalf() throws {
		let aliceIdentity = try SessionTestSupport.identity("kpprime-alice")
		let bobIdentity = try SessionTestSupport.identity("kpprime-bob")
		let initiated = try TwoMLSSession.initiate(
			identity: aliceIdentity, their: bobIdentity.keyPackage,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		let bootstrapKP = try #require(initiated.session.bootstrapKPSecret?.keyPackage)
		#expect(bootstrapKP == aliceIdentity.keyPackage.pq)

		let checkpoint = try initiated.session.makeSessionArchive(kind: .checkpoint)
		let restored = try TwoMLSSession.restore(
			core: nil, checkpoint: checkpoint,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		#expect(restored.bootstrapKPSecret?.keyPackage == aliceIdentity.keyPackage.pq)

		var alice = initiated.session
		let received = try TwoMLSSession.receive(
			identity: bobIdentity, welcome: initiated.welcome,
			theirClassicalKeyPackage: aliceIdentity.keyPackage.classical,
			bootstrapKPCommitment: try initiated.session.bootstrapKPCommitment(),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		var bob = received.session
		_ = try bob.prepareToEncrypt()
		let hello = try bob.encrypt(Data("hello".utf8)).frame
		_ = try alice.processIncomingDecrypted(hello)

		let kpFrame = try alice.pqBootstrapBegin().frame
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame).frame
		_ = try alice.pqBootstrapJoin(welcomeFrame)

		let recvPQLeaf = try TwoMLSSession.ownLeaf(of: try #require(alice.recvGroup?.pq))
		#expect(
			recvPQLeaf.signatureKey == aliceIdentity.keyPackage.pq.leafNode.signatureKey
		)
		#expect(
			alice.leafKeys.recvPQ.current?.signatureKey
				== aliceIdentity.keyPackage.pq.leafNode.signatureKey)
	}
}
