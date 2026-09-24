import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes
import TwoMLSPQCrypto
import XCTest

@testable import TwoMLSPQSession

/// Step 3 runtime behavior: the own-offer window's detection/load/drain
/// path (A.5), the PQ wedge doors (A.6), and the no-custody guards (A.6) —
/// driven directly on live (non-migrated) sessions via internal field
/// manipulation (`@testable import`), which is exactly equivalent to what a
/// migrated session's restored state presents to this same runtime code
/// (`pqWedge`/`noCustody`/`ownOfferWindow` are ordinary session fields,
/// however they got there).
@available(iOS 26, macOS 26, *)
final class DeployedStateTests: XCTestCase {

	// MARK: - Own-offer window: detection, load, drain (A.5)

	/// Hand-builds a genuinely-signed, unframed own-Update offer against
	/// `session.recvGroup.classical` (mirrors `RotationTests.
	/// authorRotatingUpd`) — a fresh keypair, so the test knows its full
	/// identity — WITHOUT appending it to `session.stagedUpdates`,
	/// simulating a migrated session whose framed store doesn't carry this
	/// offer (only its own-offer window does).
	private func handBuiltUnframedOwnOffer(in session: inout TwoMLSSession) throws -> (
		framedMessage: Data, ref: Data, bareProposal: Data, epoch: UInt64, groupID: Data,
		senderLeafIndex: UInt32
	) {
		var mirror = try XCTUnwrap(session.recvGroup)
		let (freshSigningKey, freshSignatureKey) = try TwoMLSIdentity.mintSignatureKeypair()
		let (message, _) = try mirror.classical.proposeUpdate(
			SessionTestSupport.classicalProvider,
			sign: MLS.RFC9420.signingClosure(
				SessionTestSupport.classicalProvider,
				current: try session.recvClassicalSigningKey(), new: freshSigningKey
			),
			framing: .publicMessage,
			newIdentity: MLS.RFC9420.NewSigningIdentity(
				credential: .basic(identity: session.identity.clientID),
				signatureKey: freshSignatureKey))
		session.recvGroup = mirror
		// This hand-built Update bypasses `prepareToEncrypt`, which never
		// stages the fresh key itself — stage it so a later fold's
		// `promoted()` can find it (mirrors `RotationTests.
		// authorRotatingUpd`'s own PQ analogue,
		// `SigningKeyProtocolTests.handBuildPQLeafMoveUpd`).
		try session.leafKeys.recvClassical.stage(
			LeafKey(signingKey: freshSigningKey, signatureKey: freshSignatureKey),
			for: session.identity.clientID)
		guard case .publicMessage(let updatePub) = message else {
			XCTFail("expected a publicMessage-framed Update")
			throw TwoMLSError.malformedSideBandMessage
		}
		var scratchStore = MLS.RFC9420.ProposalStore()
		let verified = try mirror.classical.verifying(
			SessionTestSupport.classicalProvider, proposal: updatePub)
		let ref = try scratchStore.insert(verified, SessionTestSupport.classicalProvider)
		guard case .proposal(let bareProposal) = updatePub.content.content else {
			XCTFail("expected a proposal-carrying PublicMessage")
			throw TwoMLSError.malformedSideBandMessage
		}
		return (
			framedMessage: try message.mlsEncoded(), ref: ref.data,
			bareProposal: try bareProposal.mlsEncoded(),
			epoch: mirror.classical.context.epoch,
			groupID: mirror.classical.context.groupID,
			senderLeafIndex: mirror.classical.myLeafIndex.value
		)
	}

	/// Bob offers (unframed, per above); Alice approves and folds it BY
	/// REFERENCE into a real `0x00` commit — exactly the shape a migrated
	/// Bob would receive back naming a ref his own framed store never held.
	private func foldedButUnframedOwnOfferRound(
		proposer: inout TwoMLSSession, approver: inout TwoMLSSession
	) throws -> (
		foldFrame: Data, ref: Data, bareProposal: Data, epoch: UInt64, groupID: Data,
		senderLeafIndex: UInt32
	) {
		let built = try handBuiltUnframedOwnOffer(in: &proposer)
		let digest = try SessionTestSupport.classicalProvider.hash(built.framedMessage)
		proposer.pendingProposal = (
			proposing: proposer.identity.clientID, message: built.framedMessage,
			hash: digest
		)
		let offerFrame = try proposer.encrypt(Data("offer".utf8)).frame
		let decrypted = try approver.processIncomingDecrypted(offerFrame)
		try approver.queueProposal(digest: decrypted.queuedProposal.digest)
		_ = try approver.prepareToEncrypt()
		let foldFrame = try approver.encrypt(Data("fold".utf8)).frame
		return (
			foldFrame: foldFrame, ref: built.ref, bareProposal: built.bareProposal,
			epoch: built.epoch, groupID: built.groupID,
			senderLeafIndex: built.senderLeafIndex
		)
	}

	private func windowFixture(
		ref: Data, bareProposal: Data, epoch: UInt64, groupID: Data, senderLeafIndex: UInt32
	) throws -> (record: OwnOfferWindowRecord, blob: SecretArchive) {
		let offer = MigratedOwnOffer(
			ref: ref, proposal: bareProposal,
			leafSecret: SecretBytes(randomByteCount: 32))
		let sorted = try OwnOfferWindow.canonicalOrder([offer])
		let id = OwnOfferWindow.id(
			epoch: epoch, groupID: groupID, senderLeafIndex: senderLeafIndex,
			sorted: sorted)
		let record = OwnOfferWindowRecord(
			id: id, epoch: epoch, groupID: groupID, senderLeafIndex: senderLeafIndex,
			count: 1)
		let body = try OwnOfferWindowArchive(
			epoch: epoch, groupID: groupID, senderLeafIndex: senderLeafIndex,
			sorted: sorted)
		let blob = try SecretArchive(encoding: body)
		return (record, blob)
	}

	/// The core A.5 round trip: a missing ref with no window supplied is
	/// retryable and burns no state; supplying the window resolves it,
	/// applies the fold, and drains the record.
	func testMissingOwnOfferRefRequiresThenResolvesFromTheWindowAndDrains() throws {
		// The hand-built offer stages a fresh key directly into
		// `leafKeys.recvClassical.pending` (bypassing `prepareToEncrypt`),
		// which the oracle's pre-step-3 resolvers can never explain.
		OracleCheck.allow([.recvClassical])
		defer { OracleCheck.allow([]) }
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let round = try foldedButUnframedOwnOfferRound(proposer: &bob, approver: &alice)
		let fixture = try windowFixture(
			ref: round.ref, bareProposal: round.bareProposal, epoch: round.epoch,
			groupID: round.groupID, senderLeafIndex: round.senderLeafIndex)

		var bobNoWindow = bob
		bobNoWindow.ownOfferWindow = fixture.record
		let stateSeqBefore = bobNoWindow.stateSeq
		XCTAssertThrowsError(try bobNoWindow.processIncoming(round.foldFrame)) { error in
			XCTAssertEqual(error as? TwoMLSError, .ownOfferWindowRequired)
		}
		XCTAssertEqual(bobNoWindow.stateSeq, stateSeqBefore, "retryable: nothing changed")
		XCTAssertEqual(
			bobNoWindow.ownOfferWindow?.id, fixture.record.id,
			"the record itself is untouched")

		var bobWithWindow = bob
		bobWithWindow.ownOfferWindow = fixture.record
		let result = try bobWithWindow.processIncoming(
			round.foldFrame, ownOfferWindow: fixture.blob)
		guard case .decrypted(let decrypted) = result else {
			XCTFail("expected the fold to apply and decrypt")
			return
		}
		XCTAssertTrue(decrypted.didApplyRemoteCommit)
		XCTAssertNil(
			bobWithWindow.ownOfferWindow, "drained once recvGroup.classical advanced")
	}

	/// A window that doesn't name the missing ref is terminal
	/// (`.ownOfferUnavailable`), not retryable.
	func testWindowLackingTheNamedRefIsTerminal() throws {
		// The hand-built offer stages a fresh key directly into
		// `leafKeys.recvClassical.pending` (bypassing `prepareToEncrypt`),
		// which the oracle's pre-step-3 resolvers can never explain.
		OracleCheck.allow([.recvClassical])
		defer { OracleCheck.allow([]) }
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let round = try foldedButUnframedOwnOfferRound(proposer: &bob, approver: &alice)
		// A window shaped for the RIGHT epoch/group/leaf, but naming some
		// OTHER ref — never the one the fold commit actually references.
		let wrongRef = try SessionTestSupport.classicalProvider.hash(Data("not-it".utf8))
		let fixture = try windowFixture(
			ref: wrongRef, bareProposal: round.bareProposal, epoch: round.epoch,
			groupID: round.groupID, senderLeafIndex: round.senderLeafIndex)
		bob.ownOfferWindow = fixture.record
		XCTAssertThrowsError(
			try bob.processIncoming(round.foldFrame, ownOfferWindow: fixture.blob)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .ownOfferUnavailable)
		}
	}

	/// B-1: a commit whose framing signature/membership tag fails to
	/// verify must never reach `.ownOfferWindowRequired`/
	/// `.ownOfferUnavailable` — authentication runs first, always.
	func testForgedCommitSignatureNeverDemandsTheWindow() throws {
		// The hand-built offer stages a fresh key directly into
		// `leafKeys.recvClassical.pending` (bypassing `prepareToEncrypt`),
		// which the oracle's pre-step-3 resolvers can never explain.
		OracleCheck.allow([.recvClassical])
		defer { OracleCheck.allow([]) }
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let round = try foldedButUnframedOwnOfferRound(proposer: &bob, approver: &alice)

		let opened = bob.openOrRaw(round.foldFrame)
		var (staple, proposalSection, appSection) = try Frames.decodeMessageFrame(opened)
		// Flip the staple's LAST byte — RFC 9420's PublicMessage puts the
		// signature/membership tag at the end of the encoding, so this
		// almost certainly breaks authentication rather than anything
		// benign.
		staple[staple.index(before: staple.endIndex)] ^= 0xFF
		let tamperedFrame = Frames.encodeMessageFrame(
			staple: staple, proposal: proposalSection, app: appSection)

		var bobTampered = bob
		let fixture = try windowFixture(
			ref: round.ref, bareProposal: round.bareProposal, epoch: round.epoch,
			groupID: round.groupID, senderLeafIndex: round.senderLeafIndex)
		bobTampered.ownOfferWindow = fixture.record
		XCTAssertThrowsError(try bobTampered.processIncoming(tamperedFrame)) { error in
			XCTAssertNotEqual(error as? TwoMLSError, .ownOfferWindowRequired)
			XCTAssertNotEqual(error as? TwoMLSError, .ownOfferUnavailable)
		}
	}

	/// A tampered window blob (its recomputed id no longer matches the
	/// session's own record) is `.archiveInvalid` — not silently accepted.
	func testTamperedWindowBlobFailsTheIDCheck() throws {
		// The hand-built offer stages a fresh key directly into
		// `leafKeys.recvClassical.pending` (bypassing `prepareToEncrypt`),
		// which the oracle's pre-step-3 resolvers can never explain.
		OracleCheck.allow([.recvClassical])
		defer { OracleCheck.allow([]) }
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let round = try foldedButUnframedOwnOfferRound(proposer: &bob, approver: &alice)
		let fixture = try windowFixture(
			ref: round.ref, bareProposal: round.bareProposal, epoch: round.epoch,
			groupID: round.groupID, senderLeafIndex: round.senderLeafIndex)

		// A DIFFERENT (but validly-shaped) window blob than the one the
		// record's id actually names — the load-time id recompute must
		// reject the mismatch.
		let otherOffer = MigratedOwnOffer(
			ref: round.ref, proposal: round.bareProposal,
			leafSecret: SecretBytes(randomByteCount: 32))
		let otherSorted = try OwnOfferWindow.canonicalOrder([otherOffer])
		let otherBody = try OwnOfferWindowArchive(
			epoch: round.epoch, groupID: round.groupID,
			senderLeafIndex: round.senderLeafIndex + 1, sorted: otherSorted)
		let otherBlob = try SecretArchive(encoding: otherBody)

		bob.ownOfferWindow = fixture.record
		XCTAssertThrowsError(
			try bob.processIncoming(round.foldFrame, ownOfferWindow: otherBlob)
		) {
			error in
			XCTAssertEqual(error as? TwoMLSError, .archiveInvalid)
		}
	}

	// MARK: - PQ side-band wedge (A.6)

	/// The three wedge doors — `pqBootstrapJoin`, `pqRatchetBind`,
	/// `pqRekeyApply` — throw `.pqSideBandWedged` with no state change.
	/// Exercised concretely for `pqRekeyApply`; the other two doors gate
	/// with the identical `guard pqWedge == nil else { throw
	/// .pqSideBandWedged }` placed right after their own decode (S-2), so
	/// the same proof generalizes.
	func testWedgedSessionRejectsPQRekeyApplyWithNoStateChange() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		let updFrame = try bob.pqRekeyBegin().frame
		let commitFrame = try alice.pqRekeyRespond(updFrame).frame

		bob.pqWedge = .rekey
		let stateSeqBefore = bob.stateSeq
		XCTAssertThrowsError(try bob.pqRekeyApply(commitFrame)) { error in
			XCTAssertEqual(error as? TwoMLSError, .pqSideBandWedged)
		}
		XCTAssertEqual(bob.stateSeq, stateSeqBefore)
		XCTAssertNil(bob.owedBind)
		guard case .rekeyInitiated = bob.pqInflight else {
			XCTFail("pqInflight must be untouched by the wedged attempt")
			return
		}
	}

	/// The wedge never blocks an owed-bind discharge or ordinary classical
	/// messaging — only the three PQ doors above.
	func testWedgeNeverBlocksTheOwedBindDischargeOrClassicalMessaging() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		let updFrame = try bob.pqRekeyBegin().frame
		let commitFrame = try alice.pqRekeyRespond(updFrame).frame
		_ = try bob.pqRekeyApply(commitFrame)
		XCTAssertNotNil(bob.owedBind)

		bob.pqWedge = .rekey
		let prepared = try bob.prepareToEncrypt()
		XCTAssertTrue(
			prepared.didCommit, "the owed-bind discharge is never gated on the wedge")
		XCTAssertNoThrow(try bob.encrypt(Data("still-works".utf8)))
	}

	/// Self-drive (`maybeStageNextRound`, run from `encrypt`) stays idle
	/// while wedged — never opens a round it cannot complete.
	func testWedgeSkipsSelfDriveWithNoChange() throws {
		var (_, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		XCTAssertTrue(bob.myPQTurn)
		_ = try bob.prepareToEncrypt()
		bob.pqWedge = .ratchet
		XCTAssertNoThrow(try bob.encrypt(Data("msg".utf8)))
		XCTAssertNil(bob.pendingSideBand, "self-drive must not stage a round while wedged")
		XCTAssertNil(bob.pqInflight)
	}

	// MARK: - No-custody guards (A.6)

	/// The signing-key accessors: a nil `current` maps to
	/// `.leafCustodyUnavailable` when the role is flagged `noCustody`, else
	/// to the pre-step-3 `.credentialUnknown` (an unexpected/corrupt
	/// state). Exercised for `sendClassicalSigningKey`; the other three
	/// accessors follow the identical pattern.
	func testSigningKeyAccessorDistinguishesNoCustodyFromCredentialUnknown() throws {
		var (_, bob) = try SessionTestSupport.establishedAndExchanged()
		bob.leafKeys.sendClassical.current = nil

		XCTAssertThrowsError(try bob.sendClassicalSigningKey()) { error in
			XCTAssertEqual(error as? TwoMLSError, .credentialUnknown)
		}

		bob.noCustody = [.sendClassical]
		XCTAssertThrowsError(try bob.sendClassicalSigningKey()) { error in
			XCTAssertEqual(error as? TwoMLSError, .leafCustodyUnavailable)
		}
	}

	/// `prepareToEncrypt`'s own pre-check: refuses BEFORE `committingRound`
	/// ever runs (it writes `recvGroup` even for a bare catch-up-only
	/// round), independent of what `leafKeys` itself holds.
	func testPrepareToEncryptRefusesWhenEitherClassicalRoleHasNoCustody() throws {
		var (_, bobSend) = try SessionTestSupport.establishedAndExchanged()
		bobSend.noCustody = [.sendClassical]
		XCTAssertThrowsError(try bobSend.prepareToEncrypt()) { error in
			XCTAssertEqual(error as? TwoMLSError, .leafCustodyUnavailable)
		}

		var (_, bobRecv) = try SessionTestSupport.establishedAndExchanged()
		bobRecv.noCustody = [.recvClassical]
		XCTAssertThrowsError(try bobRecv.prepareToEncrypt()) { error in
			XCTAssertEqual(error as? TwoMLSError, .leafCustodyUnavailable)
		}
	}

	/// The PQ doors' own pre-checks: `pqRekeyBegin` (recv-PQ) and
	/// `pqRekeyRespond`/`pqBootstrapJoin`/`pqRatchetBind`/`pqRekeyApply`
	/// (send-PQ) all refuse before consuming anything. Exercised for
	/// `pqRekeyBegin`/`pqRekeyRespond`; the others follow the identical
	/// `guard !noCustody.contains(...)` placement.
	func testPQDoorsRefuseWhenTheirGroupHasNoCustody() throws {
		var (_, bobBegin) = try RatchetTests.fullyEstablishedTurnOnBob()
		bobBegin.noCustody = [.recvPQ]
		XCTAssertThrowsError(try bobBegin.pqRekeyBegin()) { error in
			XCTAssertEqual(error as? TwoMLSError, .leafCustodyUnavailable)
		}

		var (aliceRespond, bobRespond) = try RatchetTests.fullyEstablishedTurnOnBob()
		let updFrame = try bobRespond.pqRekeyBegin().frame
		aliceRespond.noCustody = [.sendPQ]
		XCTAssertThrowsError(try aliceRespond.pqRekeyRespond(updFrame)) { error in
			XCTAssertEqual(error as? TwoMLSError, .leafCustodyUnavailable)
		}
	}

	/// Self-drive also skips while either send role has no custody
	/// (`stageRatchet` would fail on `sendClassical` anyway, but the guard
	/// is explicit so the auto-driver never even attempts it).
	func testSelfDriveSkipsWhenASendRoleHasNoCustody() throws {
		var (_, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		_ = try bob.prepareToEncrypt()
		bob.noCustody = [.sendPQ]
		XCTAssertNoThrow(try bob.encrypt(Data("msg".utf8)))
		XCTAssertNil(bob.pendingSideBand)
	}

	/// The choke point's monotone drain: once a group's own leaf key set
	/// genuinely has a `current` again, the NEXT `stateUpdate`-driven check
	/// (`assertLeafKeysPresented`) drops it from `noCustody` — without
	/// touching every promotion call site individually.
	func testNoCustodyDrainsOnceTheGroupGenuinelyHasACurrentKey() throws {
		var (_, bob) = try SessionTestSupport.establishedAndExchanged()
		let realCurrent = bob.leafKeys.sendClassical.current
		bob.leafKeys.sendClassical.current = nil
		bob.noCustody = [.sendClassical]
		XCTAssertThrowsError(try bob.prepareToEncrypt())

		bob.leafKeys.sendClassical.current = realCurrent
		try bob.assertLeafKeysPresented()
		XCTAssertFalse(
			bob.noCustody.contains(.sendClassical),
			"drained once current is genuinely present")
	}

	// MARK: - Read-only queries (C.1)

	func testCanSendReflectsBothClassicalRolesAndEstablishment() throws {
		var (_, bob) = try SessionTestSupport.establishedAndExchanged()
		XCTAssertTrue(bob.canSend)
		bob.noCustody = [.recvClassical]
		XCTAssertFalse(bob.canSend)
	}

	func testPQSideBandWedgedReflectsTheStoredWedge() throws {
		var (_, bob) = try SessionTestSupport.establishedAndExchanged()
		XCTAssertFalse(bob.pqSideBandWedged)
		bob.pqWedge = .bootstrap
		XCTAssertTrue(bob.pqSideBandWedged)
	}
}
