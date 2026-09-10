import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes
import TwoMLSPQCrypto
import XCTest

@testable import TwoMLSPQSession

/// §A.5 mechanical re-key (Chunk 1 — no credential rotation): a standalone
/// `updatePath` Commit′ on ONE PQ group, ending in the reused A.4/A.3 bind.
/// Cast by turn: INITIATOR = the turn-holder, COMMITTER = the peer; the
/// re-keyed group is the committer's send-PQ (= the initiator's recv-PQ
/// mirror). Reuses `RatchetTests.fullyEstablishedTurnOnBob()`, which lands
/// with the turn on Bob — so round 1 here is **Bob-initiated**, re-keying
/// Group_A.pq (`alice.sendGroup.pq` / `bob.recvGroup.pq`), the group Alice
/// founded — not Group_B.pq, which A.3's bind already advanced.
@available(iOS 26, macOS 26, *)
final class RekeyTests: XCTestCase {
	/// Drive one full mechanical §A.5 round to completion: `initiator`
	/// proposes, `committer` folds + commits, `initiator` applies + owes the
	/// bind, and the ack rides `initiator`'s next classical commit —
	/// mirroring `RatchetTests`'s own bob-initiated round.
	@discardableResult
	private func driveMechanicalRekeyRound(
		initiator: inout TwoMLSSession, committer: inout TwoMLSSession
	) throws -> Bool {
		let updFrame = try initiator.pqRekeyBegin()
		let commitFrame = try committer.pqRekeyRespond(updFrame)
		try initiator.pqRekeyApply(commitFrame)
		let prepared = try initiator.prepareToEncrypt()
		let boundFrame = try initiator.encrypt(Data("rekey-bound".utf8))
		_ = try committer.processIncoming(boundFrame)
		return prepared.didCommit
	}

	// MARK: - The full mechanical round

	/// The full round: Bob proposes Upd′ into his recv mirror, Alice folds
	/// it into a Commit′ on her own send-PQ (the group actually re-keyed),
	/// Bob applies it and owes the bind, Bob discharges (already licensed
	/// per §11 #8), and Alice applies the ack — landing the re-keyed group
	/// at the same new epoch on both sides and passing the turn back to
	/// Alice. Also proves the round-trip: an app message still works each
	/// direction afterward.
	func testMechanicalRekeyRoundAdvancesRekeyedGroupOnBothSidesAndReturnsTurn() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		XCTAssertTrue(bob.myPQTurn)
		XCTAssertFalse(alice.myPQTurn)

		let rekeyedEpochBefore = try XCTUnwrap(alice.sendGroup?.pq?.context.epoch)
		XCTAssertEqual(bob.recvGroup?.pq?.context.epoch, rekeyedEpochBefore)

		// 1: Bob (initiator) proposes Upd′ into his recv mirror.
		let updFrame = try bob.pqRekeyBegin()
		XCTAssertEqual(updFrame.first, Frames.pqRekeyUpdTag)
		guard case .rekeyInitiated = bob.pqInflight else {
			XCTFail("expected bob to hold .rekeyInitiated after pqRekeyBegin")
			return
		}
		XCTAssertEqual(bob.pqPendingOutbound(), updFrame)

		// 2: Alice (committer) folds it into a Commit′ on her own send-PQ —
		// the group actually being re-keyed.
		let commitFrame = try alice.pqRekeyRespond(updFrame)
		XCTAssertEqual(commitFrame.first, Frames.pqRekeyCommitTag)
		guard case .rekeyResponded = alice.pqInflight else {
			XCTFail("expected alice to hold .rekeyResponded after pqRekeyRespond")
			return
		}
		XCTAssertNil(alice.owedBind)
		XCTAssertEqual(alice.sendGroup?.pq?.context.epoch, rekeyedEpochBefore + 1)

		// 3: Bob applies the Commit′, exports `S` off the rekeyed mirror,
		// and owes the classical bind.
		try bob.pqRekeyApply(commitFrame)
		XCTAssertNotNil(bob.owedBind)
		XCTAssertNil(bob.pqInflight)
		XCTAssertNil(bob.pqPendingOutbound())
		XCTAssertEqual(bob.recvGroup?.pq?.context.epoch, rekeyedEpochBefore + 1)

		// A bind is now owed: a further `pqRekeyBegin` must refuse.
		XCTAssertThrowsError(try bob.pqRekeyBegin()) { error in
			XCTAssertEqual(error as? TwoMLSError, .sessionNotReady)
		}

		// 4: Bob discharges (already licensed by Alice's earlier "bound"
		// frame from the A.3 fixture, per §11 #8) and Alice applies the
		// `0x05` ack — re-exporting `S` off her OWN rekeyed send-PQ (the
		// `.rekeyResponded` re-export arm, §3d).
		let prepared = try bob.prepareToEncrypt()
		XCTAssertTrue(prepared.didCommit)
		let boundFrame = try bob.encrypt(Data("bound".utf8))
		let decrypted = try alice.processIncoming(boundFrame)
		XCTAssertEqual(decrypted.applicationMessage, Data("bound".utf8))

		XCTAssertTrue(alice.myPQTurn)
		XCTAssertFalse(bob.myPQTurn)
		XCTAssertNil(alice.pqInflight)
		XCTAssertNil(alice.pqPendingOutbound())
		XCTAssertEqual(alice.sendGroup?.pq?.context.epoch, rekeyedEpochBefore + 1)
		XCTAssertEqual(bob.recvGroup?.pq?.context.epoch, rekeyedEpochBefore + 1)
		XCTAssertEqual(
			bob.sendGroup?.classical.context.epoch,
			alice.recvGroup?.classical.context.epoch)

		// 5: round-trip app messages both directions still work post-rekey.
		_ = try alice.prepareToEncrypt()
		let aliceMsg = try alice.encrypt(Data("post-rekey-alice".utf8))
		let fromAlice = try bob.processIncoming(aliceMsg)
		XCTAssertEqual(fromAlice.applicationMessage, Data("post-rekey-alice".utf8))

		_ = try bob.prepareToEncrypt()
		let bobMsg = try bob.encrypt(Data("post-rekey-bob".utf8))
		let fromBob = try alice.processIncoming(bobMsg)
		XCTAssertEqual(fromBob.applicationMessage, Data("post-rekey-bob".utf8))
	}

	// MARK: - Watermark lockstep (the A.5-specific correctness test)

	/// Two back-to-back mechanical rounds with roles swapped and no
	/// intervening peer PQ commit on either mirror: round 2's committer
	/// (Bob) must skip re-exporting the cross-party PSK off the group round
	/// 1's initiator (Bob) already consumed it from at that exact epoch —
	/// and round 2's initiator (Alice) must symmetrically skip her own
	/// pre-register off the group she herself already exported from as
	/// round 1's committer. Without the `lastCrossInjectedPQ`/
	/// `lastSendPQExported` watermarks gating those exports, either side
	/// would hit `ExporterTree.ExportError.componentSecretConsumed` — this
	/// pins the SKIP (consumed-leaf) half of that correctness property; the
	/// INJECT half — the watermark correctly firing a fresh export instead
	/// of skipping — is covered separately by
	/// `testInjectRoundCompletesWithLockstepWatermarks` and
	/// `testInjectConfigTamperedApplyThenGenuineRetrySucceeds` (§13 A1/F3).
	func testSecondRoundWithSwappedRolesSkipsAlreadyConsumedCrossInjection() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()

		// Round 1: Bob initiates (re-keys Group_A.pq, alice's send-PQ).
		XCTAssertTrue(try driveMechanicalRekeyRound(initiator: &bob, committer: &alice))
		XCTAssertTrue(alice.myPQTurn)
		XCTAssertFalse(bob.myPQTurn)

		// Round 1's `owePQBind` (inside bob's `pqRekeyApply`) committed onto
		// bob's OWN send-PQ (Group_B.pq), and bob's `pqRekeyApply` stamped
		// `lastCrossInjectedPQ` for HIS recv mirror (Group_A.pq, the group
		// just re-keyed) at its new epoch. `applyBind`'s re-export arm
		// stamped alice's `lastSendPQExported` for HER send-PQ (Group_A.pq,
		// the same group) at that same new epoch.
		let bobLastCrossInjectedAfterRound1 = bob.lastCrossInjectedPQ
		let aliceLastSendPQExportedAfterRound1 = alice.lastSendPQExported
		XCTAssertNotNil(bobLastCrossInjectedAfterRound1)
		XCTAssertNotNil(aliceLastSendPQExportedAfterRound1)

		// Round 2: roles swapped — Alice initiates, re-keying Group_B.pq
		// (bob's send-PQ). Bob (now committer) mirrors Group_A.pq as HIS
		// recv-PQ — untouched since round 1 — and Alice (now initiator)
		// reads her OWN Group_A.pq (her send-PQ) for the pre-register — also
		// untouched since round 1. Neither watermark has moved, so both
		// sides must skip re-exporting rather than throw
		// `componentSecretConsumed` on the already-consumed leaf.
		XCTAssertTrue(try driveMechanicalRekeyRound(initiator: &alice, committer: &bob))

		XCTAssertEqual(bob.lastCrossInjectedPQ, bobLastCrossInjectedAfterRound1)
		XCTAssertEqual(alice.lastSendPQExported, aliceLastSendPQExportedAfterRound1)

		// The round still completed via the updatePath alone: turn flips
		// back, and app traffic round-trips.
		XCTAssertTrue(bob.myPQTurn)
		XCTAssertFalse(alice.myPQTurn)
		_ = try bob.prepareToEncrypt()
		let msg = try bob.encrypt(Data("post-round-2".utf8))
		let decrypted = try alice.processIncoming(msg)
		XCTAssertEqual(decrypted.applicationMessage, Data("post-round-2".utf8))
	}

	// MARK: - `pqRekeyBegin` guards

	func testRekeyBeginGuardsRejectWrongState() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()

		// Not my turn: alice must not stage an Upd′.
		XCTAssertThrowsError(try alice.pqRekeyBegin()) { error in
			XCTAssertEqual(error as? TwoMLSError, .sessionNotReady)
		}
		XCTAssertNil(alice.pendingSideBand)

		// A different round is already in flight (an A.4 EK self-staged on
		// `encrypt`): `pqRekeyBegin` must not stage a second round on top.
		_ = try bob.prepareToEncrypt()
		_ = try bob.encrypt(Data("m".utf8))
		guard case .initiating = bob.pqInflight else {
			XCTFail("expected bob to hold .initiating after the A.4 self-drive")
			return
		}
		XCTAssertThrowsError(try bob.pqRekeyBegin()) { error in
			XCTAssertEqual(error as? TwoMLSError, .sessionNotReady)
		}
	}

	// MARK: - Mutation-verify

	/// A wire-tampered Commit′ is rejected as the non-fatal
	/// `.decryptionFailed` and burns no durable state: the initiator keeps
	/// `.rekeyInitiated` and the rekeyed group's epoch is untouched. The
	/// genuine Commit′ still applies cleanly afterward.
	func testTamperedRekeyCommitThrowsAndBurnsNoState() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		let updFrame = try bob.pqRekeyBegin()
		let commitFrame = try alice.pqRekeyRespond(updFrame)

		var tampered = commitFrame
		tampered[tampered.index(before: tampered.endIndex)] ^= 0xFF

		let recvPQEpochBefore = bob.recvGroup?.pq?.context.epoch
		XCTAssertThrowsError(try bob.pqRekeyApply(tampered)) { error in
			XCTAssertEqual(error as? TwoMLSError, .decryptionFailed)
		}
		XCTAssertNil(bob.owedBind)
		XCTAssertEqual(bob.recvGroup?.pq?.context.epoch, recvPQEpochBefore)
		guard case .rekeyInitiated = bob.pqInflight else {
			XCTFail("expected bob to still hold .rekeyInitiated after a rejected apply")
			return
		}

		try bob.pqRekeyApply(commitFrame)
		XCTAssertNotNil(bob.owedBind)
	}

	/// A `0x1B` carrying a commit behind the tag (rather than a proposal) is
	/// rejected before any `committing` — `verifying(proposal:)` itself
	/// refuses non-proposal content, remapped to `.decryptionFailed` (§13
	/// M5) — and the committer's own send-PQ epoch is untouched.
	func testRekeyRespondRejectsCommitBehindTheTag() throws {
		let (fixtureAlice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		var alice = fixtureAlice

		let sneakyPQ = try XCTUnwrap(bob.recvGroup?.pq)
		let transition = try sneakyPQ.committing(
			SessionTestSupport.pqProvider, proposals: [],
			signingKey: bob.identity.signingKey,
			randomness: try .generate(SessionTestSupport.pqProvider),
			includePath: true, framing: .publicMessage)
		let commitBytes = try transition.takeOutput().message.mlsEncoded()
		let sneakyFrame = Frames.encodePQRekeyUpd(commitBytes)

		let sendPQEpochBefore = alice.sendGroup?.pq?.context.epoch
		XCTAssertThrowsError(try alice.pqRekeyRespond(sneakyFrame)) { error in
			XCTAssertEqual(error as? TwoMLSError, .decryptionFailed)
		}
		XCTAssertEqual(alice.sendGroup?.pq?.context.epoch, sendPQEpochBefore)
		XCTAssertNil(alice.pqInflight)
	}

	/// A Commit′ that folds the peer's Update AND an extra Add is rejected
	/// as `.invalidRekeyEffects` — `CommitEffects` has no public initializer
	/// (it is `internal` to swift-mls), so this drives a real over-broad
	/// commit through swift-mls rather than hand-building the effects value.
	func testRekeyApplyRejectsCommitWithExtraAddEffect() throws {
		let (alice, fixtureBob) = try RatchetTests.fullyEstablishedTurnOnBob()
		var bob = fixtureBob
		let updFrame = try bob.pqRekeyBegin()

		let mallory = try SessionTestSupport.identity("mallory-rekey")
		let updBytes = try Frames.decodePQRekeyUpd(updFrame)
		guard
			case .publicMessage(let updPub) = try MLS.RFC9420.Message(
				mlsEncoded: updBytes)
		else {
			XCTFail("expected a publicMessage-framed Upd′")
			return
		}
		let sendPQ = try XCTUnwrap(alice.sendGroup?.pq)
		let verified = try sendPQ.verifying(SessionTestSupport.pqProvider, proposal: updPub)
		var proposalStore = MLS.RFC9420.ProposalStore()
		let ref = try proposalStore.insert(verified, SessionTestSupport.pqProvider)

		let transition = try sendPQ.committing(
			SessionTestSupport.pqProvider,
			proposals: [.reference(ref), .proposal(.add(mallory.keyPackage.pq))],
			proposalStore: proposalStore, signingKey: alice.identity.signingKey,
			randomness: try .generate(SessionTestSupport.pqProvider), includePath: true,
			framing: .publicMessage)
		let commitBytes = try transition.takeOutput().message.mlsEncoded()
		let badFrame = Frames.encodePQRekeyCommit(commitBytes)

		let recvPQEpochBefore = bob.recvGroup?.pq?.context.epoch
		XCTAssertThrowsError(try bob.pqRekeyApply(badFrame)) { error in
			XCTAssertEqual(error as? TwoMLSError, .invalidRekeyEffects)
		}
		XCTAssertEqual(bob.recvGroup?.pq?.context.epoch, recvPQEpochBefore)
		XCTAssertNil(bob.owedBind)
		guard case .rekeyInitiated = bob.pqInflight else {
			XCTFail("expected bob to still hold .rekeyInitiated after a rejected apply")
			return
		}
	}

	/// A `0x1B`/`0x1D` re-delivered after the round has fully closed (turn
	/// flipped, both sides' inflight/parked state spent) is refused as
	/// `.sessionNotReady` rather than reprocessed.
	func testDuplicateLegsAfterRoundClosedThrowSessionNotReady() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		let updFrame = try bob.pqRekeyBegin()
		let commitFrame = try alice.pqRekeyRespond(updFrame)
		try bob.pqRekeyApply(commitFrame)
		let prepared = try bob.prepareToEncrypt()
		XCTAssertTrue(prepared.didCommit)
		let boundFrame = try bob.encrypt(Data("bound".utf8))
		_ = try alice.processIncoming(boundFrame)

		XCTAssertThrowsError(try alice.pqRekeyRespond(updFrame)) { error in
			XCTAssertEqual(error as? TwoMLSError, .sessionNotReady)
		}
		XCTAssertThrowsError(try bob.pqRekeyApply(commitFrame)) { error in
			XCTAssertEqual(error as? TwoMLSError, .sessionNotReady)
		}
	}

	// MARK: - Cross-PSK INJECT path

	/// Reach the §A.5 INJECT configuration. Pure A.5 alternation never
	/// injects: each round's committer exports the cross-party PSK off its
	/// OWN recv-PQ mirror, and that mirror only ever advances via this same
	/// session later playing initiator (`pqRekeyApply`'s post-round `S`
	/// export syncs `lastCrossInjectedPQ` to the exact epoch it just left
	/// the group at) — so the watermark and the mirror's live epoch never
	/// drift apart. An §A.4 ratchet round breaks that lockstep: its bind
	/// applies via `applyBind`'s held-`S` `.responding` arm, which exports
	/// nothing and stamps no watermark, yet still advances whichever mirror
	/// it targets. One such round (bob-initiated, advancing Group_B.pq)
	/// flips the turn to Alice without moving `bob.lastCrossInjectedPQ` —
	/// so when Alice then initiates an §A.5 round re-keying Group_B.pq,
	/// Bob's very first turn as an §A.5 committer finds his watermark for
	/// the OPPOSITE group (Group_A.pq, his fixed recv mirror) stale
	/// (`nil` vs. Group_A.pq's live epoch), and injects a fresh cross-party
	/// PSK into the Commit′ rather than skipping. Returns the pair plus
	/// Bob's resulting `0x1D` Commit′ — `pqRekeyApply` not yet called.
	private func reachInjectConfig() throws -> (
		alice: TwoMLSSession, bob: TwoMLSSession, commitFrame: Data
	) {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()

		_ = try bob.prepareToEncrypt()
		_ = try bob.encrypt(Data("m".utf8))
		let ekFrame = try XCTUnwrap(bob.pqPendingOutbound())
		let ctFrame = try alice.pqRatchetRespond(ekFrame)
		try bob.pqRatchetBind(ctFrame)
		let preparedA4 = try bob.prepareToEncrypt()
		XCTAssertTrue(preparedA4.didCommit)
		let boundFrameA4 = try bob.encrypt(Data("bound-a4".utf8))
		_ = try alice.processIncoming(boundFrameA4)
		XCTAssertTrue(alice.myPQTurn)
		XCTAssertNil(bob.lastCrossInjectedPQ)

		let updFrame = try alice.pqRekeyBegin()
		let commitFrame = try bob.pqRekeyRespond(updFrame)
		return (alice: alice, bob: bob, commitFrame: commitFrame)
	}

	/// `commitFrame`'s proposal count, decoded at the deployed wire width (its
	/// injected PSK, when present, carries a `ComponentID`, §11 #6).
	private func rekeyCommitProposalCount(_ commitFrame: Data) throws -> Int {
		let commitBytes = try Frames.decodePQRekeyCommit(commitFrame)
		return try withDeployedWireConventions {
			guard
				case .publicMessage(let commitPub) = try MLS.RFC9420.Message(
					mlsEncoded: commitBytes),
				case .commit(let commit) = commitPub.content.content
			else {
				XCTFail("expected a publicMessage commit")
				return 0
			}
			return commit.proposals.count
		}
	}

	/// The inject config's Commit′ carries the reference plus the injected
	/// `0xFF02` PreSharedKey (2 proposals, vs. 1 for a skip round); applying
	/// it stamps `bob.lastCrossInjectedPQ` (the committer) and
	/// `alice.lastSendPQExported` (the initiator's pre-register) to the SAME
	/// epoch — Group_A.pq's live epoch, the opposite group both sides read
	/// off — in lockstep. The round still completes end to end
	/// (apply → bind → discharge → applyBind) and app traffic round-trips.
	func testInjectRoundCompletesWithLockstepWatermarks() throws {
		var (alice, bob, commitFrame) = try reachInjectConfig()

		XCTAssertEqual(try rekeyCommitProposalCount(commitFrame), 2)

		let groupAEpoch = try XCTUnwrap(bob.recvGroup?.pq?.context.epoch)
		XCTAssertEqual(bob.lastCrossInjectedPQ, groupAEpoch)

		try alice.pqRekeyApply(commitFrame)
		XCTAssertEqual(alice.lastSendPQExported, groupAEpoch)
		XCTAssertEqual(bob.lastCrossInjectedPQ, alice.lastSendPQExported)

		XCTAssertNotNil(alice.owedBind)
		let prepared = try alice.prepareToEncrypt()
		XCTAssertTrue(prepared.didCommit)
		let boundFrame = try alice.encrypt(Data("inject-bound".utf8))
		_ = try bob.processIncoming(boundFrame)

		XCTAssertTrue(bob.myPQTurn)
		XCTAssertFalse(alice.myPQTurn)
		XCTAssertNil(alice.pqInflight)
		XCTAssertNil(bob.pqInflight)

		_ = try alice.prepareToEncrypt()
		let msg = try alice.encrypt(Data("post-inject".utf8))
		let decrypted = try bob.processIncoming(msg)
		XCTAssertEqual(decrypted.applicationMessage, Data("post-inject".utf8))
	}

	/// In the same inject config, a tampered Commit′ throws
	/// `.decryptionFailed` and leaves `alice.lastSendPQExported` and
	/// `alice.sendGroup.pq`'s epoch untouched — proving the pre-register's
	/// export ran against a throwaway copy, never written back to the real
	/// `sendGroup.pq`, and that the watermark stamp is deferred until after
	/// `apply` succeeds. The genuine Commit′ then applies cleanly: if the
	/// pre-register had instead written back to the real group, or
	/// `lastSendPQExported` had been stamped before `validating`, this retry
	/// would fail `componentSecretConsumed` on the already-burned leaf, or
	/// skip the pre-register the retry still needs.
	func testInjectConfigTamperedApplyThenGenuineRetrySucceeds() throws {
		var (alice, _, commitFrame) = try reachInjectConfig()
		XCTAssertEqual(try rekeyCommitProposalCount(commitFrame), 2)

		XCTAssertNil(alice.lastSendPQExported)
		let sendGroupAEpochBefore = try XCTUnwrap(alice.sendGroup?.pq?.context.epoch)

		var tampered = commitFrame
		tampered[tampered.index(before: tampered.endIndex)] ^= 0xFF

		XCTAssertThrowsError(try alice.pqRekeyApply(tampered)) { error in
			XCTAssertEqual(error as? TwoMLSError, .decryptionFailed)
		}
		XCTAssertNil(alice.lastSendPQExported)
		XCTAssertEqual(alice.sendGroup?.pq?.context.epoch, sendGroupAEpochBefore)
		XCTAssertNil(alice.owedBind)
		guard case .rekeyInitiated = alice.pqInflight else {
			XCTFail(
				"expected alice to still hold .rekeyInitiated after a rejected apply"
			)
			return
		}

		try alice.pqRekeyApply(commitFrame)
		XCTAssertEqual(alice.lastSendPQExported, sendGroupAEpochBefore)
		XCTAssertNotNil(alice.owedBind)
	}
}
