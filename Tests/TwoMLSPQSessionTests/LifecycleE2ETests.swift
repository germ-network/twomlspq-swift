import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes
import TwoMLSPQCrypto
import XCTest

@testable import TwoMLSPQSession

/// One continuous, from-cold test asserting the BOOK's lifecycle
/// (session-lifecycle.md, protocol-flows.md §A.1-A.5, walkthrough.md) — not
/// today's engine — the way a host drives it: every outbound transmission is
/// `encrypt`'s frame plus `pqPendingOutbound()`; every inbound blob is
/// routed through `openIncoming` and dispatched by kind. Where the engine
/// has not yet caught up to the book, the book's behavior is still
/// asserted, wrapped in `XCTExpectFailure` so the run stays green today and
/// turns red the moment that gap closes. `E2EWalkthroughTests` is
/// classical-only by its own header; the PQ steps are otherwise tested only
/// from pre-established fixtures (`BootstrapTests`/`RatchetTests`/
/// `RekeyTests`) — this is the one place they all compose.
@available(iOS 26, macOS 26, *)
final class LifecycleE2ETests: XCTestCase {

	// MARK: - Host model

	/// One party's driving state: the live session, the two most-recent
	/// persisted archives (kept by highest `stateSeq` per kind, mirroring a
	/// real app's durable store), and a mailbox of blobs queued to the peer.
	private struct Host {
		var session: TwoMLSSession
		private(set) var latestCore: SecretArchive?
		private var latestCoreSeq: UInt64 = 0
		private(set) var latestCheckpoint: SecretArchive?
		private var latestCheckpointSeq: UInt64 = 0
		var outbox: [Blob] = []

		/// One queued wire blob: the sender's own classification (what it
		/// queued this as) plus, for a message frame, the sender's own
		/// `session.epochs.classicalEpoch` as of that send — cross-checked
		/// against the receiver's `DecryptResult.epoch` for the same frame.
		struct Blob {
			let bytes: Data
			let expectedKind: TwoMLSSession.OpenedFrameKind
			var sourceClassicalEpoch: UInt64?
		}

		init(_ session: TwoMLSSession) {
			self.session = session
		}

		mutating func persist(_ update: StateUpdate) {
			switch update.kind {
			case .core:
				guard latestCore == nil || update.stateSeq > latestCoreSeq else {
					return
				}
				latestCore = update.archive
				latestCoreSeq = update.stateSeq
			case .checkpoint:
				guard
					latestCheckpoint == nil
						|| update.stateSeq > latestCheckpointSeq
				else { return }
				latestCheckpoint = update.archive
				latestCheckpointSeq = update.stateSeq
			}
		}

		/// Host send rule: (1) idempotent A.3 begin, only while it's my turn
		/// and the PQ half isn't fully up (`bootstrapRule` lets the script
		/// turn this off, to prove the engine never self-starts it); (2)
		/// `prepareToEncrypt`; (3) `encrypt`, with the epoch/routing checks;
		/// (4) queue the message frame, then any side-band leg riding it —
		/// message first, since a leg `rewrapSideBand` just re-minted inside
		/// THIS `encrypt` call sits at the epoch the message's own staple
		/// advances to.
		@discardableResult
		mutating func send(
			_ app: Data, to peer: inout Host, rotating: Data? = nil,
			bootstrapRule: Bool = true,
			file: StaticString = #filePath, line: UInt = #line
		) throws -> (prepared: PrepareResult, result: EncryptResult) {
			if bootstrapRule, session.isEstablished, !session.isFullyEstablished,
				session.myPQTurn
			{
				persist(try session.pqBootstrapBegin().update)
			}
			let prepared = try session.prepareToEncrypt(rotating: rotating)
			persist(prepared.update)
			// Nothing may run between `prepareToEncrypt` and `encrypt` —
			// every side-band completion entry point refuses while a
			// proposal is pending, so holding these two calls back to back
			// is the host's own obligation, not an engine-enforced one.
			// Pinned once, here, the single choke point every send in this
			// test funnels through.
			XCTAssertNotNil(session.pendingProposal, file: file, line: line)
			let result = try session.encrypt(app)
			persist(result.update)

			// `session.epochs` right after `encrypt` against the internal
			// send-group read it derives from.
			let sendEpochs = session.epochs
			if let send = session.sendGroup {
				XCTAssertEqual(
					sendEpochs.classicalEpoch, send.classical.context.epoch,
					file: file, line: line)
				XCTAssertEqual(
					sendEpochs.pqEpoch, send.pq?.context.epoch ?? 0,
					file: file,
					line: line)
			}
			// Routing: where I post (my recv group's rendezvous) must be
			// somewhere the peer's own listen set (derived from THEIR send
			// group — the same underlying group) already covers.
			if let rendezvous = session.sendRendezvous() {
				XCTAssertTrue(
					peer.session.shouldListenOn().rendezvousByEpoch.contains {
						$0.rendezvousId == rendezvous
					}, "peer must be listening where this send posts",
					file: file,
					line: line)
			}

			outbox.append(
				Blob(
					bytes: result.frame, expectedKind: .message,
					sourceClassicalEpoch: sendEpochs.classicalEpoch))
			if let pending = session.pqPendingOutbound() {
				// A SEND-side classification: `openIncoming` needs MY OWN
				// receive windows, which key opening messages addressed TO
				// me, not my own outbound side-band leg (sealed under
				// whichever family it seals under FOR THE PEER) — read the
				// unsealed tag directly instead.
				let tag = try XCTUnwrap(
					session.pendingSideBand?.first, file: file, line: line)
				let kind = try XCTUnwrap(
					Self.pqFrameKind(forTag: tag), file: file, line: line)
				outbox.append(Blob(bytes: pending, expectedKind: .pqSideBand(kind)))
			}
			return (prepared, result)
		}

		private static func pqFrameKind(forTag tag: UInt8) -> TwoMLSSession.PqFrameKind? {
			switch tag {
			case Frames.pqBootstrapKPTag: return .bootstrapKP
			case Frames.pqBootstrapWelcomeTag: return .bootstrapWelcome
			case Frames.pqEKTag: return .ratchetEK
			case Frames.pqCTTag: return .ratchetCT
			case Frames.pqRekeyUpdTag: return .rekeyUpd
			case Frames.pqRekeyCommitTag: return .rekeyCommit
			default: return nil
			}
		}

		/// The next blob queued for THIS host, failing the test (rather than
		/// trapping) if the mailbox is unexpectedly empty — a kind mismatch
		/// earlier in the script should fail loudly, not crash the run.
		mutating func nextBlob(
			file: StaticString = #filePath, line: UInt = #line
		) throws -> Blob {
			guard !outbox.isEmpty else {
				XCTFail("outbox is empty", file: file, line: line)
				throw TwoMLSError.notEstablished
			}
			return outbox.removeFirst()
		}

		/// Deliver one queued blob to THIS host: open against the receive
		/// windows, assert the sender's declared kind matches what actually
		/// opened, then dispatch to the matching entry point and queue
		/// any response into THIS host's own outbox. A first delivery must
		/// succeed (any throw fails the test via propagation); a scripted
		/// re-delivery is wrapped by the caller in `XCTAssertThrowsError`/
		/// `XCTAssertNoThrow`, matching this suite's existing style
		/// (`BootstrapTests`/`RatchetTests`/`RekeyTests`).
		@discardableResult
		mutating func deliver(
			_ blob: Blob,
			approval: (
				envelopeDigest: Data, welcomeDigest: Data, expectedCreator: Data
			)? =
				nil,
			file: StaticString = #filePath, line: UInt = #line
		) throws -> Received {
			let opened = try XCTUnwrap(
				session.openIncoming(blob.bytes), file: file, line: line)
			XCTAssertEqual(opened.kind, blob.expectedKind, file: file, line: line)

			switch opened.kind {
			case .message:
				let result: IncomingResult
				if let approval {
					result = try session.processIncomingApproved(
						opened.frame,
						approvedEnvelopeDigest: approval.envelopeDigest,
						approvedWelcomeDigest: approval.welcomeDigest,
						expectedCreator: approval.expectedCreator)
				} else {
					result = try session.processIncoming(opened.frame)
				}
				switch result {
				case .decrypted(let d):
					persist(d.update)
					if let sourceClassicalEpoch = blob.sourceClassicalEpoch {
						XCTAssertEqual(
							d.epoch, sourceClassicalEpoch, file: file,
							line: line)
					}
					XCTAssertEqual(
						session.recvGroup?.classical.context.epoch, d.epoch,
						file: file,
						line: line)
				case .joined(_, let u):
					persist(u)
				case .pendingEstablishment, .ignored:
					break
				}
				return .message(result)

			case .pqSideBand(let kind):
				switch kind {
				case .bootstrapKP:
					let r = try session.pqBootstrapRespond(opened.frame)
					persist(r.update)
					outbox.append(
						Blob(
							bytes: r.frame,
							expectedKind: .pqSideBand(.bootstrapWelcome)
						))
					return .sideBandResponseQueued
				case .bootstrapWelcome:
					persist(try session.pqBootstrapJoin(opened.frame))
					return .sideBandApplied
				case .ratchetEK:
					let r = try session.pqRatchetRespond(opened.frame)
					persist(r.update)
					outbox.append(
						Blob(
							bytes: r.frame,
							expectedKind: .pqSideBand(.ratchetCT)))
					return .sideBandResponseQueued
				case .ratchetCT:
					persist(try session.pqRatchetBind(opened.frame))
					return .sideBandApplied
				case .rekeyUpd:
					let r = try session.pqRekeyRespond(opened.frame)
					persist(r.update)
					outbox.append(
						Blob(
							bytes: r.frame,
							expectedKind: .pqSideBand(.rekeyCommit)))
					return .sideBandResponseQueued
				case .rekeyCommit:
					persist(try session.pqRekeyApply(opened.frame))
					return .sideBandApplied
				}
			}
		}

		/// `deliver`, asserting the everyday `.decrypted` shape — mirrors
		/// `SessionTestSupport.processIncomingDecrypted`.
		@discardableResult
		mutating func deliverDecrypted(
			_ blob: Blob,
			approval: (
				envelopeDigest: Data, welcomeDigest: Data, expectedCreator: Data
			)? =
				nil,
			file: StaticString = #filePath, line: UInt = #line
		) throws -> DecryptResult {
			guard
				case .message(.decrypted(let d)) = try deliver(
					blob, approval: approval, file: file, line: line)
			else {
				XCTFail("expected .decrypted", file: file, line: line)
				throw TwoMLSError.notEstablished
			}
			return d
		}

		/// `TwoMLSSession.restore` from the persisted blobs — asserts the
		/// epoch pairs survive a restore unchanged.
		mutating func restart(
			file: StaticString = #filePath, line: UInt = #line
		) throws {
			let epochsBefore = session.epochs
			let recvClassicalBefore = session.recvGroup?.classical.context.epoch
			let recvPQBefore = session.recvGroup?.pq?.context.epoch
			let checkpoint = try XCTUnwrap(latestCheckpoint, file: file, line: line)
			session = try TwoMLSSession.restore(
				core: latestCore, checkpoint: checkpoint,
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
			XCTAssertEqual(session.epochs, epochsBefore, file: file, line: line)
			XCTAssertEqual(
				session.recvGroup?.classical.context.epoch, recvClassicalBefore,
				file: file,
				line: line)
			XCTAssertEqual(
				session.recvGroup?.pq?.context.epoch, recvPQBefore, file: file,
				line: line)
		}

		/// Drives whatever PQ round the turn-holder's (`self`) next send
		/// opens — an A.4 ratchet today, an A.5 re-key once the book's
		/// credential catch-up lands — to completion: the opening leg, the
		/// responder's reply, then the closing bind on `self`'s own next
		/// send. Dispatch is purely by the frame kind `deliver` observes, so
		/// the same driver works for either shape. Restarts both sides
		/// mid-round. Returns the opening leg's own kind, so the caller can
		/// assert which round actually opened.
		@discardableResult
		mutating func drivePQRoundToCompletion(
			responder: inout Host,
			file: StaticString = #filePath, line: UInt = #line
		) throws -> TwoMLSSession.PqFrameKind {
			_ = try send(
				Data("pq-round-open".utf8), to: &responder, file: file, line: line)
			guard outbox.count == 2,
				case .pqSideBand(let openKind) = outbox[1].expectedKind
			else {
				XCTFail(
					"expected the turn-holder's send to open a PQ round",
					file: file,
					line: line)
				throw TwoMLSError.notEstablished
			}

			_ = try responder.deliverDecrypted(try nextBlob(), file: file, line: line)
			_ = try responder.deliver(try nextBlob(), file: file, line: line)
			try restart(file: file, line: line)
			switch session.pqInflight {
			case .some(.initiating), .some(.rekeyInitiated): break
			default:
				XCTFail(
					"expected the initiator's in-flight round to survive a restart",
					file: file, line: line)
			}

			try responder.restart(file: file, line: line)
			switch responder.session.pqInflight {
			case .some(.responding), .some(.rekeyResponded): break
			default:
				XCTFail(
					"expected the responder's in-flight round to survive a restart",
					file: file, line: line)
			}

			_ = try deliver(try responder.nextBlob(), file: file, line: line)
			XCTAssertNotNil(session.owedBind, file: file, line: line)

			let discharge = try send(
				Data("pq-round-discharge".utf8), to: &responder, file: file,
				line: line)
			XCTAssertTrue(discharge.prepared.didCommit, file: file, line: line)
			_ = try responder.deliverDecrypted(try nextBlob(), file: file, line: line)
			XCTAssertNil(session.owedBind, file: file, line: line)
			XCTAssertNil(session.pqInflight, file: file, line: line)

			return openKind
		}
	}

	private enum Received {
		case message(IncomingResult)
		case sideBandResponseQueued
		case sideBandApplied
	}

	// MARK: - The lifecycle

	func testBookLifecycleFromCold() throws {
		// [1] Cold principals.
		let alicePrincipal = try Principal.generate(
			clientID: Data("alice".utf8),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		let bobPrincipal = try Principal.generate(
			clientID: Data("bob".utf8),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		// [2] §A.1 invitation-driven, born-dedicated establishment.
		var (bobInvitation, _) = try bobPrincipal.generateInvitation(lastResort: false)
		let bobCombinerKP = try XCTUnwrap(bobInvitation.combinerKeyPackage)

		let initiated = try TwoMLSSession.initiate(
			principal: alicePrincipal, their: bobCombinerKP)
		var alice = Host(initiated.session)
		alice.persist(initiated.baseline)

		// No recv group yet: the reply cannot carry an A.3 frame.
		XCTAssertThrowsError(try alice.session.pqBootstrapBegin()) { error in
			XCTAssertEqual(error as? TwoMLSError, .sessionNotReady)
		}

		let invitationClientID = Data("bob".utf8)
		let dedicatedClientID = Data("bob-dedicated".utf8)
		let spawnToken = SessionTestSupport.classicalProvider.randomBytes(16)
		let receivedResult = try bobInvitation.receive(
			welcome: initiated.welcome,
			theirClassicalKeyPackage: initiated.session.identity.keyPackage.classical,
			bootstrapKPCommitment: try initiated.session.bootstrapKPCommitment(),
			spawnToken: spawnToken, newClientID: dedicatedClientID)
		var bob = Host(receivedResult.session)
		bob.persist(receivedResult.baseline)

		// Book: every state-advancing call returns something persistable, so
		// the acceptor already holds a restorable checkpoint right after
		// `receive`.
		XCTAssertNotNil(bob.latestCheckpoint)
		if let checkpoint = bob.latestCheckpoint {
			XCTAssertNoThrow(
				try TwoMLSSession.restore(
					core: nil, checkpoint: checkpoint,
					classicalProvider: SessionTestSupport.classicalProvider,
					pqProvider: SessionTestSupport.pqProvider))
		}

		XCTAssertTrue(bob.session.owesEstablishmentEnvelope)
		XCTAssertEqual(bob.session.recvLeafPrincipal?.clientID, invitationClientID)

		let envelope = Data("fake-signed-handoff".utf8)
		bob.persist(try bob.session.installEstablishmentEnvelope(envelope))

		// b1: Bob's very first frame staples the 0x0B handoff directly
		// (nothing yet to fold/discharge, so his own staple never moves off
		// the just-installed handoff).
		let b1 = try bob.send(Data("bob-hello".utf8), to: &alice)
		XCTAssertEqual(b1.result.frame, bob.outbox.last?.bytes)
		XCTAssertEqual(bob.outbox.map(\.expectedKind), [.message])
		let b1Blob = try bob.nextBlob()

		// Unapproved: pauses.
		guard case .message(.pendingEstablishment(let pending)) = try alice.deliver(b1Blob)
		else {
			return XCTFail("expected a pause on the un-approved 0x0B")
		}
		XCTAssertFalse(alice.session.isEstablished)

		let (envelopeBytes, welcomeBytes) = try Frames.decodeEstablishmentHandoff(
			bob.session.currentStaple)
		XCTAssertEqual(pending.envelope, envelopeBytes)
		let approval = (
			envelopeDigest: try SessionTestSupport.classicalProvider.hash(
				envelopeBytes),
			welcomeDigest: try SessionTestSupport.classicalProvider.hash(welcomeBytes),
			expectedCreator: dedicatedClientID
		)
		// Approved re-feed of the SAME opened bytes: joins and decrypts.
		let b1Decrypted = try alice.deliverDecrypted(b1Blob, approval: approval)
		XCTAssertEqual(b1Decrypted.newSender, dedicatedClientID)
		XCTAssertEqual(b1Decrypted.applicationMessage, Data("bob-hello".utf8))

		XCTAssertTrue(alice.session.isEstablished)
		XCTAssertTrue(bob.session.isEstablished)
		XCTAssertFalse(bob.session.isFullyEstablished)
		XCTAssertTrue(alice.session.myPQTurn)
		XCTAssertFalse(bob.session.myPQTurn)
		XCTAssertEqual(bob.session.epochs.pqEpoch, 0)
		XCTAssertNil(bob.session.shouldListenOn().sendGroup.pq)

		// Alice restarts right after establishment — her baseline (from
		// `initiate`) plus the join's own `.core` already reconcile.
		try alice.restart()
		XCTAssertTrue(alice.session.isEstablished)

		// [3] §A.3 parallel pre-delivery: the initiator's pre-committed KP′
		// rides alongside the A.1 reply, and the acceptor's Welcome′
		// alongside its return welcome, so processing the acceptor's first
		// frame(s) is enough to fully establish both sides.
		XCTExpectFailure(
			"no parallel A.3 pre-delivery: the initiator has no bootstrap-envelope API"
		) {
			XCTAssertTrue(alice.session.isFullyEstablished)
		}

		// [4] Host obligation: with the A.3 auto-begin OFF, neither side's
		// send ever carries a side-band leg on its own — the engine never
		// self-starts A.3.
		let a1 = try alice.send(Data("a1".utf8), to: &bob, bootstrapRule: false)
		XCTAssertEqual(alice.outbox.map(\.expectedKind), [.message])
		XCTAssertNil(alice.session.pqPendingOutbound())
		_ = try bob.deliverDecrypted(alice.nextBlob())
		// Group_A is a FULL pair from `initiate` (both halves founded at
		// birth) — unlike Bob's Group_B, Alice's OWN send-PQ epoch is
		// already 1 here, well before §A.3 ever starts.
		XCTAssertEqual(alice.session.epochs.pqEpoch, 1)
		_ = a1

		let b2 = try bob.send(Data("b2".utf8), to: &alice, bootstrapRule: false)
		XCTAssertEqual(bob.outbox.map(\.expectedKind), [.message])
		XCTAssertNil(bob.session.pqPendingOutbound())
		XCTAssertEqual(bob.session.epochs.pqEpoch, 0)
		_ = b2
		let b2Decrypted = try alice.deliverDecrypted(bob.nextBlob())
		XCTAssertFalse(alice.session.isFullyEstablished)
		XCTAssertFalse(bob.session.isFullyEstablished)

		// [5] §A.2 fold: Alice queues Bob's b2 offer.
		alice.persist(
			try alice.session.queueProposal(digest: b2Decrypted.queuedProposal.digest))
		let groupAClassicalEpochBeforeA2 = try XCTUnwrap(
			alice.session.sendGroup?.classical.context.epoch)
		let a2 = try alice.send(Data("a2".utf8), to: &bob, bootstrapRule: false)
		XCTAssertTrue(a2.prepared.didCommit)
		XCTAssertEqual(a2.prepared.committedRemoteClientID, dedicatedClientID)
		XCTAssertEqual(
			alice.session.sendGroup?.classical.context.epoch,
			groupAClassicalEpochBeforeA2 + 1)
		let a2Decrypted = try bob.deliverDecrypted(alice.nextBlob())
		XCTAssertTrue(a2Decrypted.didApplyRemoteCommit)
		XCTAssertTrue(a2Decrypted.ownCredentialCanonicalized)
		XCTAssertEqual(
			bob.session.recvGroup?.classical.context.epoch,
			groupAClassicalEpochBeforeA2 + 1)

		// Bob replies b3 — licenses Alice fresh, at Group_A's new epoch.
		let b3 = try bob.send(Data("b3".utf8), to: &alice, bootstrapRule: false)
		_ = try alice.deliverDecrypted(bob.nextBlob())
		_ = b3

		// [6] §A.3 (the auto-begin rule is on from here).
		let a3 = try alice.send(Data("a3".utf8), to: &bob)
		XCTAssertEqual(
			alice.outbox.map(\.expectedKind), [.message, .pqSideBand(.bootstrapKP)])
		XCTAssertFalse(a3.prepared.didCommit)

		// Restart at `.bootstrapInitiated`, right after the begin — proves
		// the parked 0x13 and the round resume cleanly.
		try alice.restart()
		guard case .bootstrapInitiated = alice.session.pqInflight else {
			return XCTFail("expected alice to hold .bootstrapInitiated across restart")
		}

		_ = try bob.deliverDecrypted(alice.nextBlob())
		let a3KPBlob = try alice.nextBlob()
		// Retain the RAW opened 0x13 bytes now, before bob ever processes
		// it, for the stale-replay pin at step 7 below.
		let staleKP = try XCTUnwrap(bob.session.openIncoming(a3KPBlob.bytes)?.frame)
		_ = try bob.deliver(a3KPBlob)  // 0x13 -> welcome #1 queued, held

		// `pqBootstrapRespond` founds `sendGroup.pq` — the first checkpoint
		// carrying it, not Bob's very first (that's the acceptor baseline
		// from `receive`, persisted above). Restart him here and prove the
		// round still completes off THIS newer checkpoint.
		let bobRespondCheckpoint = try XCTUnwrap(bob.latestCheckpoint)
		let bobRespondCheckpointBody = try bobRespondCheckpoint.decode(SessionArchive.self)
		XCTAssertGreaterThan(
			bobRespondCheckpointBody.stateSeq, receivedResult.baseline.stateSeq)
		XCTAssertNotNil(bobRespondCheckpointBody.sendPQEpoch)
		try bob.restart()
		XCTAssertTrue(bob.session.isFullyEstablished)

		// a4: begin is idempotent — the SAME retained 0x13 re-rides.
		let a4 = try alice.send(Data("a4".utf8), to: &bob)
		XCTAssertEqual(
			alice.outbox.map(\.expectedKind), [.message, .pqSideBand(.bootstrapKP)])
		_ = try bob.deliverDecrypted(alice.nextBlob())
		// 0x13 re-delivery -> re-serve welcome #2.
		_ = try bob.deliver(alice.nextBlob())
		_ = a4

		XCTAssertTrue(bob.session.isFullyEstablished)
		XCTAssertNotNil(bob.session.shouldListenOn().sendGroup.pq)
		XCTAssertEqual(bob.outbox.count, 2)
		let welcome1 = try bob.nextBlob()
		let welcome2 = try bob.nextBlob()

		_ = try alice.deliver(welcome1)
		XCTAssertTrue(alice.session.isFullyEstablished)
		XCTAssertNotNil(alice.session.owedBind)

		XCTAssertThrowsError(try alice.deliver(welcome2)) { error in
			XCTAssertEqual(error as? TwoMLSError, .sessionNotReady)
		}

		// a5 discharges — already licensed by b3.
		let a5 = try alice.send(Data("a5".utf8), to: &bob)
		XCTAssertTrue(a5.prepared.didCommit)
		XCTAssertEqual(alice.outbox.map(\.expectedKind), [.message])

		// The A.3 bind lands on Alice's own side the moment she commits it
		// (turn already flipped locally) — restart right here, before Bob
		// has even seen it, and prove the frame still delivers cleanly.
		try alice.restart()
		XCTAssertNil(alice.session.owedBind)
		XCTAssertFalse(alice.session.myPQTurn)

		let a5Blob = try alice.nextBlob()
		let a5OpenedFrame = try XCTUnwrap(bob.session.openIncoming(a5Blob.bytes)?.frame)
		let (a5Staple, _, _) = try Frames.decodeMessageFrame(a5OpenedFrame)
		XCTAssertEqual(Frames.stapleKind(a5Staple.first!), .apqPrivateMessage)
		let a5Decrypted = try bob.deliverDecrypted(a5Blob)
		XCTAssertTrue(a5Decrypted.didApplyRemoteCommit)
		XCTAssertTrue(bob.session.myPQTurn)
		XCTAssertFalse(alice.session.myPQTurn)
		XCTAssertNil(bob.session.pendingSideBand)
		XCTAssertEqual(alice.session.sendGroup?.pq?.context.epoch, 2)
		XCTAssertEqual(bob.session.recvGroup?.pq?.context.epoch, 2)

		// [7] §A.4 Bob-initiated: ratchets Group_B.pq (bob's send-PQ /
		// alice's recv-PQ mirror) — Group_A.pq already moved by the A.3
		// bind above.
		let groupBPQEpochBeforeStep7 = bob.session.sendGroup?.pq?.context.epoch ?? 0
		let b4 = try bob.send(Data("b4".utf8), to: &alice)
		XCTAssertEqual(bob.session.epochs.pqEpoch, groupBPQEpochBeforeStep7)
		_ = b4
		XCTAssertEqual(bob.outbox.map(\.expectedKind), [.message, .pqSideBand(.ratchetEK)])
		try bob.restart()
		guard case .initiating = bob.session.pqInflight else {
			return XCTFail("expected bob to hold .initiating across restart")
		}

		// Book: a stale KP′ after the round closed is refused. Bob has since
		// moved on to A.4 (his parked leg is now the EK), so replaying the
		// long-stale a3 0x13 on a copy of his session should be refused.
		var probe = bob.session
		try XCTExpectFailure("stale bootstrap KP re-serves the parked frame") {
			XCTAssertThrowsError(try probe.pqBootstrapRespond(staleKP)) { error in
				XCTAssertEqual(error as? TwoMLSError, .duplicateSideBand)
			}
		}

		_ = try alice.deliverDecrypted(bob.nextBlob())
		_ = try alice.deliver(bob.nextBlob())  // 0x17 -> alice responds w/ CT
		try alice.restart()
		guard case .responding = alice.session.pqInflight else {
			return XCTFail("expected alice to hold .responding across restart")
		}

		// Bob's own EK is still parked (`.initiating`) — a further bob send
		// re-rides it; delivering it to alice while she is still
		// `.responding` is refused.
		let b4b = try bob.send(Data("b4b".utf8), to: &alice)
		_ = b4b
		_ = try alice.deliverDecrypted(bob.nextBlob())
		XCTAssertThrowsError(try alice.deliver(bob.nextBlob())) { error in
			XCTAssertEqual(error as? TwoMLSError, .duplicateSideBand)
		}

		XCTAssertEqual(alice.outbox.map(\.expectedKind), [.pqSideBand(.ratchetCT)])
		_ = try bob.deliver(alice.nextBlob())  // bob binds
		XCTAssertNotNil(bob.session.owedBind)
		XCTAssertEqual(
			bob.session.sendGroup?.pq?.context.epoch, groupBPQEpochBeforeStep7 + 1)

		let b5 = try bob.send(Data("b5".utf8), to: &alice)
		XCTAssertTrue(b5.prepared.didCommit)
		let b5Decrypted = try alice.deliverDecrypted(bob.nextBlob())
		XCTAssertTrue(b5Decrypted.didApplyRemoteCommit)
		XCTAssertTrue(alice.session.myPQTurn)
		XCTAssertFalse(bob.session.myPQTurn)
		XCTAssertEqual(
			alice.session.recvGroup?.pq?.context.epoch, groupBPQEpochBeforeStep7 + 1)

		// [8] §A.4 Alice-initiated: ratchets Group_A.pq (alice's own
		// send-PQ, already at epoch 2 from the A.3 bind).
		let groupAPQEpochBeforeStep8 = try XCTUnwrap(
			alice.session.sendGroup?.pq?.context.epoch)
		let a6 = try alice.send(Data("a6".utf8), to: &bob)
		XCTAssertEqual(
			alice.outbox.map(\.expectedKind), [.message, .pqSideBand(.ratchetEK)])
		_ = a6
		_ = try bob.deliverDecrypted(alice.nextBlob())
		_ = try bob.deliver(alice.nextBlob())  // bob responds w/ CT
		XCTAssertEqual(bob.outbox.map(\.expectedKind), [.pqSideBand(.ratchetCT)])
		_ = try alice.deliver(bob.nextBlob())  // alice binds
		XCTAssertNotNil(alice.session.owedBind)
		XCTAssertEqual(
			alice.session.sendGroup?.pq?.context.epoch, groupAPQEpochBeforeStep8 + 1)

		let a7 = try alice.send(Data("a7".utf8), to: &bob)
		XCTAssertTrue(a7.prepared.didCommit)
		let a7Decrypted = try bob.deliverDecrypted(alice.nextBlob())
		XCTAssertTrue(a7Decrypted.didApplyRemoteCommit)
		XCTAssertTrue(bob.session.myPQTurn)
		XCTAssertFalse(alice.session.myPQTurn)
		XCTAssertEqual(
			bob.session.recvGroup?.pq?.context.epoch, groupAPQEpochBeforeStep8 + 1)

		// A turn-holder round to bring the turn back to Alice for the fold ∘
		// A.4 composition below — any completed PQ round does this; the
		// generic driver already built for the book's §A.5 catch-up (below)
		// works just as well here, today, as a plain A.4.
		_ = try bob.drivePQRoundToCompletion(responder: &alice)

		// [9] Fold ∘ A.4 composition: the turn-holder's idle `encrypt`
		// self-opens an A.4 round on top of a fold.
		let b8 = try bob.send(Data("b8".utf8), to: &alice)
		// Not bob's PQ turn: no leg.
		XCTAssertEqual(bob.outbox.map(\.expectedKind), [.message])
		_ = b8
		let b8Decrypted = try alice.deliverDecrypted(bob.nextBlob())
		alice.persist(
			try alice.session.queueProposal(digest: b8Decrypted.queuedProposal.digest))

		let groupAClassicalEpochBeforeA8 = try XCTUnwrap(
			alice.session.sendGroup?.classical.context.epoch)
		let groupAPQEpochBeforeStep9 = try XCTUnwrap(
			alice.session.sendGroup?.pq?.context.epoch)
		let a8 = try alice.send(Data("a8".utf8), to: &bob)
		XCTAssertTrue(a8.prepared.didCommit)
		XCTAssertEqual(
			alice.outbox.map(\.expectedKind), [.message, .pqSideBand(.ratchetEK)])
		XCTAssertEqual(
			alice.session.sendGroup?.classical.context.epoch,
			groupAClassicalEpochBeforeA8 + 1)

		let a8Decrypted = try bob.deliverDecrypted(alice.nextBlob())
		XCTAssertTrue(a8Decrypted.didApplyRemoteCommit)
		_ = try bob.deliver(alice.nextBlob())  // bob responds w/ CT
		XCTAssertEqual(bob.outbox.map(\.expectedKind), [.pqSideBand(.ratchetCT)])

		_ = try alice.deliver(bob.nextBlob())  // alice binds — unlicensed
		XCTAssertNotNil(alice.session.owedBind)
		XCTAssertEqual(
			alice.session.sendGroup?.pq?.context.epoch, groupAPQEpochBeforeStep9 + 1)

		// Restart with a bind owed but not yet dischargeable — proves the
		// owed state itself, not just an in-flight round, survives.
		try alice.restart()
		XCTAssertNotNil(alice.session.owedBind)

		// Unlicensed: alice's own fold (a8) moved Group_A past whatever
		// evidence b8 supplied — a9 has nothing to commit.
		let a9 = try alice.send(Data("a9".utf8), to: &bob)
		XCTAssertFalse(a9.prepared.didCommit)
		XCTAssertEqual(alice.outbox.map(\.expectedKind), [.message])
		_ = try bob.deliverDecrypted(alice.nextBlob())

		// b9 re-rides bob's still-parked CT — his own responder state isn't
		// cleared until he sees alice's discharge — a redelivery on
		// alice's side, refused.
		let b9 = try bob.send(Data("b9".utf8), to: &alice)
		XCTAssertEqual(bob.outbox.map(\.expectedKind), [.message, .pqSideBand(.ratchetCT)])
		_ = b9
		_ = try alice.deliverDecrypted(bob.nextBlob())
		XCTAssertThrowsError(try alice.deliver(bob.nextBlob())) { error in
			XCTAssertEqual(error as? TwoMLSError, .sessionNotReady)
		}

		// a10 discharges — licensed by b9.
		let a10 = try alice.send(Data("a10".utf8), to: &bob)
		XCTAssertTrue(a10.prepared.didCommit)
		let a10Decrypted = try bob.deliverDecrypted(alice.nextBlob())
		XCTAssertTrue(a10Decrypted.didApplyRemoteCommit)
		XCTAssertTrue(bob.session.myPQTurn)
		XCTAssertFalse(alice.session.myPQTurn)
		XCTAssertEqual(
			bob.session.recvGroup?.pq?.context.epoch, groupAPQEpochBeforeStep9 + 1)
		XCTAssertNil(bob.session.pendingSideBand)

		// [10] Rotation ∘ A.4 composition.
		let aliceOldID = alice.session.identity.clientID
		let alice2ID = Data("alice2".utf8)
		let a11 = try alice.send(Data("a11".utf8), to: &bob, rotating: alice2ID)
		// Not alice's PQ turn: no leg.
		XCTAssertEqual(alice.outbox.map(\.expectedKind), [.message])
		XCTAssertEqual(
			alice.session.myPrincipalState, .pending(old: aliceOldID, new: alice2ID))
		_ = a11

		let a11Decrypted = try bob.deliverDecrypted(alice.nextBlob())
		XCTAssertEqual(a11Decrypted.queuedProposal.proposing, alice2ID)
		bob.persist(
			try bob.session.queueProposal(digest: a11Decrypted.queuedProposal.digest))

		let b10 = try bob.send(Data("b10".utf8), to: &alice)
		XCTAssertTrue(b10.prepared.didCommit)
		XCTAssertEqual(b10.prepared.committedRemoteClientID, alice2ID)
		XCTAssertEqual(bob.outbox.map(\.expectedKind), [.message, .pqSideBand(.ratchetEK)])

		let b10Decrypted = try alice.deliverDecrypted(bob.nextBlob())
		XCTAssertTrue(b10Decrypted.didApplyRemoteCommit)
		XCTAssertTrue(b10Decrypted.ownCredentialCanonicalized)
		XCTAssertEqual(alice.session.myPrincipalState, .sync(alice2ID))

		let groupBPQEpochBeforeStep10 = try XCTUnwrap(
			bob.session.sendGroup?.pq?.context.epoch)
		_ = try alice.deliver(bob.nextBlob())  // alice responds w/ CT
		XCTAssertEqual(alice.outbox.map(\.expectedKind), [.pqSideBand(.ratchetCT)])
		_ = try bob.deliver(alice.nextBlob())  // bob binds — unlicensed
		XCTAssertNotNil(bob.session.owedBind)
		XCTAssertEqual(
			bob.session.sendGroup?.pq?.context.epoch, groupBPQEpochBeforeStep10 + 1)

		// Alice queues Bob's b10 offer — a12 both folds it AND catches up
		// her own send-leaf (Group_A), already licensed by that same b10.
		alice.persist(
			try alice.session.queueProposal(digest: b10Decrypted.queuedProposal.digest))
		let a12 = try alice.send(Data("a12".utf8), to: &bob)
		XCTAssertTrue(a12.prepared.didCommit)
		// Alice's still-parked CT (unresolved from her side until Bob's
		// discharge lands) is stale relative to a12's own fold — re-minted
		// and re-rides.
		XCTAssertEqual(
			alice.outbox.map(\.expectedKind), [.message, .pqSideBand(.ratchetCT)])

		let a12Decrypted = try bob.deliverDecrypted(alice.nextBlob())
		XCTAssertTrue(a12Decrypted.didApplyRemoteCommit)
		XCTAssertEqual(a12Decrypted.newSender, alice2ID)
		XCTAssertThrowsError(try bob.deliver(alice.nextBlob())) { error in
			XCTAssertEqual(error as? TwoMLSError, .sessionNotReady)
		}

		let b11 = try bob.send(Data("b11".utf8), to: &alice)
		XCTAssertTrue(b11.prepared.didCommit)
		let b11Decrypted = try alice.deliverDecrypted(bob.nextBlob())
		XCTAssertTrue(b11Decrypted.didApplyRemoteCommit)
		XCTAssertTrue(alice.session.myPQTurn)
		XCTAssertFalse(bob.session.myPQTurn)
		XCTAssertEqual(
			alice.session.recvGroup?.pq?.context.epoch, groupBPQEpochBeforeStep10 + 1)

		// [11] Post-rotation credential catch-up. Right after the rotation
		// lands, alice's send-PQ leaf still presents her pre-rotation
		// credential — a round she opens moves only her RECV-PQ leaf; her
		// send-PQ leaf moves only when she responds to a peer-opened A.5
		// (protocol-flows.md:56, :696-708 — TwoMLSPQ `69a9f0e`), so it
		// stays on `aliceOldID` through this whole step.
		XCTAssertNil(alice.session.pqInflight)
		XCTAssertNil(alice.session.owedBind)
		XCTAssertTrue(alice.session.myPQTurn)
		let aliceSendPQLeafBeforeCatchup = try TwoMLSSession.ownLeaf(
			of: try XCTUnwrap(alice.session.sendGroup?.pq))
		XCTAssertEqual(
			try basicIdentifier(aliceSendPQLeafBeforeCatchup.credential), aliceOldID)
		let aliceRecvPQKeyBeforeCatchup = try TwoMLSSession.ownLeaf(
			of: try XCTUnwrap(alice.session.recvGroup?.pq)
		).signatureKey

		// Book: the SESSION self-drives §A.5 — alice's own next PQ round
		// should open as a re-key, carrying the new credential onto her
		// recv-PQ leaf, with no host call. Drive whatever round actually
		// opens (an A.4 ratchet today) to completion with the generic
		// driver, which works unchanged for either shape.
		let openKind = try alice.drivePQRoundToCompletion(responder: &bob)

		XCTExpectFailure(
			"no self-driven A.5 once alice's recv-PQ leaf lags a rotation (protocol-flows.md:56)"
		) {
			XCTAssertEqual(openKind, .rekeyUpd)
		}

		// This round's own outcome (protocol-flows.md:696-708): unaffected
		// by whatever round actually opened above, alice's send-PQ own
		// leaf still presents her PRE-rotation credential.
		let aliceSendPQLeafAfterRound = try TwoMLSSession.ownLeaf(
			of: try XCTUnwrap(alice.session.sendGroup?.pq))
		XCTAssertEqual(
			try basicIdentifier(aliceSendPQLeafAfterRound.credential), aliceOldID)

		let aliceRecvPQLeaf = try TwoMLSSession.ownLeaf(
			of: try XCTUnwrap(alice.session.recvGroup?.pq))
		// A PQ key is never equal to a classical key, so these hold today
		// regardless of D3's gap.
		XCTAssertNotEqual(
			aliceRecvPQLeaf.signatureKey,
			try TwoMLSSession.ownLeaf(
				of: try XCTUnwrap(alice.session.sendGroup?.classical)
			).signatureKey)
		XCTAssertNotEqual(
			aliceRecvPQLeaf.signatureKey,
			try TwoMLSSession.ownLeaf(
				of: try XCTUnwrap(alice.session.recvGroup?.classical)
			).signatureKey)

		// D1: recv-PQ (KP′) is always distinct from send-PQ (a fresh A.3
		// founding leaf) by construction.
		XCTAssertNotEqual(
			aliceRecvPQLeaf.signatureKey,
			try TwoMLSSession.ownLeaf(
				of: try XCTUnwrap(alice.session.sendGroup?.pq)
			).signatureKey)

		try XCTExpectFailure(
			"protocol-flows.md:56, :704-708 / D3: no A.5 credential catch-up after rotation"
		) {
			XCTAssertEqual(try basicIdentifier(aliceRecvPQLeaf.credential), alice2ID)

			// Bob's own copy of the SAME group (Group_B.pq — his sendGroup,
			// alice's recvGroup mirror): his view of alice's leaf must agree.
			let bobsGroupBPQ = try XCTUnwrap(bob.session.sendGroup?.pq)
			let aliceLeafEntry = try XCTUnwrap(
				bobsGroupBPQ.tree.nonBlankLeaves().first {
					$0.index != bobsGroupBPQ.myLeafIndex
				})
			let aliceLeafAtBob = try MLS.RFC9420.LeafNode(
				mlsEncoded: aliceLeafEntry.record.encoded)
			XCTAssertEqual(try basicIdentifier(aliceLeafAtBob.credential), alice2ID)

			// D3: the catch-up mints a fresh key for THAT group only.
			XCTAssertNotEqual(aliceRecvPQLeaf.signatureKey, aliceRecvPQKeyBeforeCatchup)
		}

		// [12] Idle invariants: the non-turn side never has anything
		// parked; the turn side is nil until its next send, non-nil right
		// after.
		XCTAssertNil(alice.session.pqPendingOutbound())
		XCTAssertNil(bob.session.pqPendingOutbound())

		let finalFromBob = try bob.send(Data("final-from-bob".utf8), to: &alice)
		XCTAssertNotNil(bob.session.pqPendingOutbound())
		_ = finalFromBob
		let finalFromBobDecrypted = try alice.deliverDecrypted(bob.nextBlob())
		XCTAssertEqual(
			finalFromBobDecrypted.applicationMessage, Data("final-from-bob".utf8))
		bob.outbox.removeAll()  // discard the self-staged EK; this round need not complete

		let finalFromAlice = try alice.send(Data("final-from-alice".utf8), to: &bob)
		_ = finalFromAlice
		let finalFromAliceDecrypted = try bob.deliverDecrypted(alice.nextBlob())
		XCTAssertEqual(
			finalFromAliceDecrypted.applicationMessage, Data("final-from-alice".utf8))
	}
}
