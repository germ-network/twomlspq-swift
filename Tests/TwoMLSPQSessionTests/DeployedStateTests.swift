import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes
import Testing
import TwoMLSPQCrypto

@testable import TwoMLSPQSession

/// The migrated deployed-state runtime behavior: the own-offer window's
/// detection/load/drain path, the PQ wedge doors, and the
/// no-custody guards —
/// driven directly on live (non-migrated) sessions via internal field
/// manipulation (`@testable import`), which is exactly equivalent to what a
/// migrated session's restored state presents to this same runtime code
/// (`pqWedge`/`noCustody`/`ownOfferWindow` are ordinary session fields,
/// however they got there).
@Suite struct DeployedStateTests {

	// MARK: - Own-offer window: detection, load, drain

	/// Hand-builds a genuinely-signed, unframed own-Update offer against
	/// `session.recvGroup.classical` (mirrors `RotationTests.
	/// authorRotatingUpd`) — a fresh keypair, so the test knows its full
	/// identity — WITHOUT appending it to `session.stagedUpdates`,
	/// simulating a migrated session whose framed store doesn't carry this
	/// offer (only its own-offer window does).
	@available(iOS 26, macOS 26, *)
	private func handBuiltUnframedOwnOffer(in session: inout TwoMLSSession) throws -> (
		framedMessage: Data, ref: Data, bareProposal: Data, epoch: UInt64, groupID: Data,
		senderLeafIndex: UInt32
	) {
		var mirror = try #require(session.recvGroup)
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
		// `SigningKeyProtocolTests.handBuildPQLeafMoveUpd`). Assigned
		// directly, not via `stage`: a routine offer now mints fresh too
		// (D3), so an earlier real offer from establishment may already
		// hold a DIFFERENT key at this same target, and this hand-built
		// offer's key must replace it, not collide with it.
		session.leafKeys.recvClassical.pending[session.identity.clientID] =
			LeafKey(signingKey: freshSigningKey, signatureKey: freshSignatureKey)
		guard case .publicMessage(let updatePub) = message else {
			Issue.record("expected a publicMessage-framed Update")
			throw TwoMLSError.malformedSideBandMessage
		}
		var scratchStore = MLS.RFC9420.ProposalStore()
		let verified = try mirror.classical.verifying(
			SessionTestSupport.classicalProvider, proposal: updatePub)
		let ref = try scratchStore.insert(verified, SessionTestSupport.classicalProvider)
		guard case .proposal(let bareProposal) = updatePub.content.content else {
			Issue.record("expected a proposal-carrying PublicMessage")
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
	@available(iOS 26, macOS 26, *)
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

	@available(iOS 26, macOS 26, *)
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

	/// The core own-offer window round trip: a missing ref with no window supplied is
	/// retryable and burns no state; supplying the window resolves it,
	/// applies the fold, and drains the record.
	@available(iOS 26, macOS 26, *)
	@Test func missingOwnOfferRefRequiresThenResolvesFromTheWindowAndDrains() throws {
		// The hand-built offer stages a fresh key directly into
		// `leafKeys.recvClassical.pending` (bypassing `prepareToEncrypt`),
		// which the oracle's pre-existing resolvers can never explain.
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let round = try foldedButUnframedOwnOfferRound(proposer: &bob, approver: &alice)
		let fixture = try windowFixture(
			ref: round.ref, bareProposal: round.bareProposal, epoch: round.epoch,
			groupID: round.groupID, senderLeafIndex: round.senderLeafIndex)

		var bobNoWindow = bob
		bobNoWindow.ownOfferWindow = fixture.record
		let stateSeqBefore = bobNoWindow.stateSeq
		#expect(throws: TwoMLSError.ownOfferWindowRequired) {
			try bobNoWindow.processIncoming(round.foldFrame)
		}
		#expect(bobNoWindow.stateSeq == stateSeqBefore, "retryable: nothing changed")
		#expect(
			bobNoWindow.ownOfferWindow?.id == fixture.record.id,
			"the record itself is untouched")

		var bobWithWindow = bob
		bobWithWindow.ownOfferWindow = fixture.record
		let result = try bobWithWindow.processIncoming(
			round.foldFrame, ownOfferWindow: fixture.blob)
		guard case .decrypted(let decrypted) = result else {
			Issue.record("expected the fold to apply and decrypt")
			return
		}
		#expect(decrypted.didApplyRemoteCommit)
		#expect(
			bobWithWindow.ownOfferWindow == nil,
			"drained once recvGroup.classical advanced")
	}

	/// `OwnOfferWindow.canonicalOrder`'s sort is what makes runtime
	/// resolution correct regardless of a window's INPUT order, not
	/// incidental array position. A two-offer window whose input order
	/// places a decoy ref BEFORE the fold's actual missing ref — and whose
	/// input order is deliberately NOT already ascending by ref — still
	/// resolves that ref and drains, because both the mint side
	/// (`canonicalOrder`) and the load side (`OwnOfferWindowArchive.
	/// sortedOffers`'s ascending check) agree on the sorted order, never
	/// the caller's own array order.
	@available(iOS 26, macOS 26, *)
	@Test func aMultiOfferWindowResolvesARefThatIsNotFirstInInputOrder() throws {
		// The hand-built offer stages a fresh key directly into
		// `leafKeys.recvClassical.pending` (bypassing `prepareToEncrypt`),
		// which the oracle's pre-existing resolvers can never explain.
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let round = try foldedButUnframedOwnOfferRound(proposer: &bob, approver: &alice)
		let targetRef = round.ref

		// Build a single decoy against bob's own (still pre-round) recv
		// group, then place [decoy, target] in whichever order is the
		// REVERSE of their actual ref sort — so the input array is
		// deliberately NOT already in ascending order (by construction,
		// not by chance: ref comparison isn't a fair coin, so looping for a
		// decoy that happens to sort a particular way is flaky), and only
		// the real sort (not the array's own order) can make resolution
		// work.
		let decoy = try SessionTestSupport.knownSecretOwnOffer(in: bob)
		let decoyOffer = MigratedOwnOffer(
			ref: decoy.ref, proposal: decoy.bareProposal, leafSecret: decoy.leafSecret)
		let targetOffer = MigratedOwnOffer(
			ref: targetRef, proposal: round.bareProposal,
			leafSecret: SecretBytes(randomByteCount: 32))
		let offers =
			targetRef.lexicographicallyPrecedes(decoy.ref)
			? [decoyOffer, targetOffer]
			: [targetOffer, decoyOffer]
		#expect(
			offers.map(\.ref)
				!= offers.map(\.ref).sorted(by: { $0.lexicographicallyPrecedes($1) }
				),
			"input order must deliberately not already be ascending by ref")
		let sorted = try OwnOfferWindow.canonicalOrder(offers)
		let id = OwnOfferWindow.id(
			epoch: round.epoch, groupID: round.groupID,
			senderLeafIndex: round.senderLeafIndex, sorted: sorted)
		let record = OwnOfferWindowRecord(
			id: id, epoch: round.epoch, groupID: round.groupID,
			senderLeafIndex: round.senderLeafIndex, count: UInt32(offers.count))
		let body = try OwnOfferWindowArchive(
			epoch: round.epoch, groupID: round.groupID,
			senderLeafIndex: round.senderLeafIndex, sorted: sorted)
		let blob = try SecretArchive(encoding: body)

		var bobWithWindow = bob
		bobWithWindow.ownOfferWindow = record
		let result = try bobWithWindow.processIncoming(
			round.foldFrame, ownOfferWindow: blob)
		guard case .decrypted(let decrypted) = result else {
			Issue.record("expected the fold to apply and decrypt")
			return
		}
		#expect(decrypted.didApplyRemoteCommit)
		#expect(
			bobWithWindow.ownOfferWindow == nil,
			"drained once recvGroup.classical advanced")
	}

	/// The own-offer window record is drained at exactly the two sites
	/// `recvGroup.classical`'s epoch advances (`applyFoldCommit`,
	/// `applyBind`) — a send-side round (`committingRound`'s own
	/// write-back, which only ever touches `sendGroup`) must never drain
	/// it too. Sets the record, drives a REAL send-side fold round (Alice's
	/// own routine rotation, which Bob approves and folds into his next
	/// commit — only a round that actually commits reaches
	/// `committingRound`'s own write-back; a round with nothing to
	/// fold/discharge/catch up returns before ever getting there), confirms
	/// the record is still there, then resolves a later peer fold naming
	/// the missing ref from the (still-present) window.
	@available(iOS 26, macOS 26, *)
	@Test func committingRoundsSendSideWriteBackNeverDrainsTheWindow() throws {
		// The hand-built offer stages a fresh key directly into
		// `leafKeys.recvClassical.pending` (bypassing `prepareToEncrypt`),
		// which the oracle's pre-existing resolvers can never explain.
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let built = try handBuiltUnframedOwnOffer(in: &bob)
		let fixture = try windowFixture(
			ref: built.ref, bareProposal: built.bareProposal, epoch: built.epoch,
			groupID: built.groupID, senderLeafIndex: built.senderLeafIndex)

		bob.ownOfferWindow = fixture.record

		// Alice authors a routine rotation; Bob approves and folds it into
		// his OWN next commit — a genuine `committingRound` write-back on
		// `sendGroup`, entirely unrelated to (and untouched by) Bob's
		// `recvGroup`-side window record.
		let aliceNewID = Data("alice-rotated".utf8)
		_ = try alice.prepareToEncrypt(rotating: aliceNewID)
		let rotateOfferFrame = try alice.encrypt(Data("rotate-offer".utf8)).frame
		let bobSawRotation = try bob.processIncomingDecrypted(rotateOfferFrame)
		try bob.queueProposal(digest: bobSawRotation.queuedProposal.digest)
		let prepared = try bob.prepareToEncrypt()
		#expect(prepared.didCommit, "bob folded alice's rotation into a real commit")
		_ = try bob.encrypt(Data("bob-send-round".utf8))
		#expect(
			bob.ownOfferWindow == fixture.record,
			"a send-side round must never drain the recv-side window record")

		// Now deliver the actual offer and let alice fold it by reference.
		let digest = try SessionTestSupport.classicalProvider.hash(built.framedMessage)
		bob.pendingProposal = (
			proposing: bob.identity.clientID, message: built.framedMessage, hash: digest
		)
		let offerFrame = try bob.encrypt(Data("offer".utf8)).frame
		let aliceDecrypted = try alice.processIncomingDecrypted(offerFrame)
		try alice.queueProposal(digest: aliceDecrypted.queuedProposal.digest)
		_ = try alice.prepareToEncrypt()
		let foldFrame = try alice.encrypt(Data("fold".utf8)).frame

		var bobWithWindow = bob
		let result = try bobWithWindow.processIncoming(
			foldFrame, ownOfferWindow: fixture.blob)
		guard case .decrypted(let decrypted) = result else {
			Issue.record("expected the fold to apply and decrypt")
			return
		}
		#expect(decrypted.didApplyRemoteCommit)
		#expect(
			bobWithWindow.ownOfferWindow == nil,
			"drained once recvGroup.classical advanced")
	}

	/// A window that doesn't name the missing ref is terminal
	/// (`.ownOfferUnavailable`), not retryable.
	@available(iOS 26, macOS 26, *)
	@Test func windowLackingTheNamedRefIsTerminal() throws {
		// The hand-built offer stages a fresh key directly into
		// `leafKeys.recvClassical.pending` (bypassing `prepareToEncrypt`),
		// which the oracle's pre-existing resolvers can never explain.
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let round = try foldedButUnframedOwnOfferRound(proposer: &bob, approver: &alice)
		// A window shaped for the RIGHT epoch/group/leaf, but naming some
		// OTHER ref — never the one the fold commit actually references.
		let wrongRef = try SessionTestSupport.classicalProvider.hash(Data("not-it".utf8))
		let fixture = try windowFixture(
			ref: wrongRef, bareProposal: round.bareProposal, epoch: round.epoch,
			groupID: round.groupID, senderLeafIndex: round.senderLeafIndex)
		bob.ownOfferWindow = fixture.record
		#expect(throws: TwoMLSError.ownOfferUnavailable) {
			try bob.processIncoming(round.foldFrame, ownOfferWindow: fixture.blob)
		}
	}

	/// A commit whose framing signature/membership tag fails to
	/// verify must never reach `.ownOfferWindowRequired`/
	/// `.ownOfferUnavailable` — authentication runs first, always.
	@available(iOS 26, macOS 26, *)
	@Test func forgedCommitSignatureNeverDemandsTheWindow() throws {
		// The hand-built offer stages a fresh key directly into
		// `leafKeys.recvClassical.pending` (bypassing `prepareToEncrypt`),
		// which the oracle's pre-existing resolvers can never explain.
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
		do {
			_ = try bobTampered.processIncoming(tamperedFrame)
			Issue.record("expected processIncoming to throw")
		} catch {
			#expect(error as? TwoMLSError != .ownOfferWindowRequired)
			#expect(error as? TwoMLSError != .ownOfferUnavailable)
		}
	}

	/// A tampered window blob (its recomputed id no longer matches the
	/// session's own record) is `.archiveInvalid` — not silently accepted.
	@available(iOS 26, macOS 26, *)
	@Test func tamperedWindowBlobFailsTheIDCheck() throws {
		// The hand-built offer stages a fresh key directly into
		// `leafKeys.recvClassical.pending` (bypassing `prepareToEncrypt`),
		// which the oracle's pre-existing resolvers can never explain.
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
		#expect(throws: TwoMLSError.archiveInvalid) {
			try bob.processIncoming(round.foldFrame, ownOfferWindow: otherBlob)
		}
	}

	// MARK: - PQ side-band wedge

	/// The three wedge doors — `pqBootstrapJoin`, `pqRatchetBind`,
	/// `pqRekeyApply` — throw `.pqSideBandWedged` with no state change.
	/// Exercised concretely for `pqRekeyApply`; the other two doors gate
	/// with the identical `guard pqWedge == nil else { throw
	/// .pqSideBandWedged }` placed right after their own decode, so
	/// the same proof generalizes.
	@available(iOS 26, macOS 26, *)
	@Test func wedgedSessionRejectsPQRekeyApplyWithNoStateChange() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		let updFrame = try bob.pqRekeyBegin().frame
		let commitFrame = try alice.pqRekeyRespond(updFrame).frame

		bob.pqWedge = .rekey
		let stateSeqBefore = bob.stateSeq
		#expect(throws: TwoMLSError.pqSideBandWedged) {
			try bob.pqRekeyApply(commitFrame)
		}
		#expect(bob.stateSeq == stateSeqBefore)
		#expect(bob.owedBind == nil)
		guard case .rekeyInitiated = bob.pqInflight else {
			Issue.record("pqInflight must be untouched by the wedged attempt")
			return
		}
	}

	/// The wedge never blocks an owed-bind discharge or ordinary classical
	/// messaging — only the three PQ doors above.
	@available(iOS 26, macOS 26, *)
	@Test func wedgeNeverBlocksTheOwedBindDischargeOrClassicalMessaging() throws {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		let updFrame = try bob.pqRekeyBegin().frame
		let commitFrame = try alice.pqRekeyRespond(updFrame).frame
		_ = try bob.pqRekeyApply(commitFrame)
		#expect(bob.owedBind != nil)

		bob.pqWedge = .rekey
		let prepared = try bob.prepareToEncrypt()
		#expect(
			prepared.didCommit, "the owed-bind discharge is never gated on the wedge")
		#expect(throws: Never.self) { try bob.encrypt(Data("still-works".utf8)) }
	}

	/// Self-drive (`maybeStageNextRound`, run from `encrypt`) stays idle
	/// while wedged — never opens a round it cannot complete.
	@available(iOS 26, macOS 26, *)
	@Test func wedgeSkipsSelfDriveWithNoChange() throws {
		var (_, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		#expect(bob.myPQTurn)
		_ = try bob.prepareToEncrypt()
		bob.pqWedge = .ratchet
		#expect(throws: Never.self) { try bob.encrypt(Data("msg".utf8)) }
		#expect(
			bob.pendingSideBand == nil, "self-drive must not stage a round while wedged"
		)
		#expect(bob.pqInflight == nil)
	}

	/// A pair where `bob` holds the PQ turn and his own recv-PQ leaf
	/// genuinely lags his current canonical id, with the peer already
	/// having folded it (his own leaf in `recvGroup.classical` — alice's
	/// view of him — already presents the new id) — the ordinary trigger
	/// fixture the tests below need, built with a real classical rotation
	/// and fold rather than hand-set bookkeeping.
	@available(iOS 26, macOS 26, *)
	private func establishedWithBobsRecvPQLagging() throws -> (
		alice: TwoMLSSession, bob: TwoMLSSession
	) {
		var (alice, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		#expect(bob.myPQTurn)
		let bobNewID = Data("bob-lagging-recv-pq".utf8)
		_ = try bob.prepareToEncrypt(rotating: bobNewID)
		let offerFrame = try bob.encrypt(Data("offer".utf8)).frame
		// Bob holds the PQ turn, so his own offer's `encrypt` self-drives
		// an incidental A.4 (nothing lags yet — the rotation hasn't folded)
		// — discard it so the tests below see a clean idle turn.
		if case .initiating = bob.pqInflight {
			bob.pqInflight = nil
			bob.pendingSideBand = nil
		}
		let offerDecrypted = try alice.processIncomingDecrypted(offerFrame)
		try alice.queueProposal(digest: offerDecrypted.queuedProposal.digest)
		let foldPrepared = try alice.prepareToEncrypt()
		#expect(foldPrepared.didCommit)
		let foldFrame = try alice.encrypt(Data("fold".utf8)).frame
		_ = try bob.processIncomingDecrypted(foldFrame)
		#expect(bob.myPrincipalState == .sync(bobNewID))
		#expect(bob.myPQTurn)
		return (alice, bob)
	}

	/// The A.5-arm twin of `testWedgeSkipsSelfDriveWithNoChange`: a genuinely
	/// lagging recv-PQ leaf, wedged, must still self-drive nothing. Kills a
	/// wedge guard moved into the A.4 arm only, or checked after the A.5 arm.
	@available(iOS 26, macOS 26, *)
	@Test func wedgeSkipsTheSelfDrivenCatchUp() throws {
		var (_, bob) = try establishedWithBobsRecvPQLagging()
		_ = try bob.prepareToEncrypt()
		bob.pqWedge = .rekey
		let pendingBefore = bob.leafKeys.recvPQ.pending
		#expect(throws: Never.self) { try bob.encrypt(Data("msg".utf8)) }
		#expect(
			bob.pendingSideBand == nil, "self-drive must not stage a round while wedged"
		)
		#expect(bob.pqInflight == nil)
		#expect(bob.leafKeys.recvPQ.pending.count == pendingBefore.count)
	}

	/// With no recv-PQ key, the trigger falls through to a plain A.4 even
	/// while the recv-PQ leaf genuinely lags — `stageRekey` would throw (it
	/// signs there), and the auto-driver must never even attempt an A.5 it
	/// cannot complete, or every future turn would silently stall.
	@available(iOS 26, macOS 26, *)
	@Test func recvPQWithoutCustodyKeepsRatchetingWhileItsLeafLags() throws {
		var (_, bob) = try establishedWithBobsRecvPQLagging()
		_ = try bob.prepareToEncrypt()
		bob.noCustody = [.recvPQ]
		#expect(throws: Never.self) { try bob.encrypt(Data("msg".utf8)) }
		guard case .initiating = bob.pqInflight else {
			Issue.record("expected a plain A.4 ratchet, not a stall")
			return
		}
		#expect(bob.pendingSideBand?.first == Frames.pqEKTag)
	}

	// MARK: - No-custody guards

	/// The signing-key accessors: a nil `current` maps to
	/// `.leafCustodyUnavailable` when the role is flagged `noCustody`, else
	/// to the original `.credentialUnknown` (an unexpected/corrupt
	/// state). Exercised for `sendClassicalSigningKey`; the other three
	/// accessors follow the identical pattern.
	@available(iOS 26, macOS 26, *)
	@Test func signingKeyAccessorDistinguishesNoCustodyFromCredentialUnknown() throws {
		var (_, bob) = try SessionTestSupport.establishedAndExchanged()
		bob.leafKeys.sendClassical.current = nil

		#expect(throws: TwoMLSError.credentialUnknown) {
			try bob.sendClassicalSigningKey()
		}

		bob.noCustody = [.sendClassical]
		#expect(throws: TwoMLSError.leafCustodyUnavailable) {
			try bob.sendClassicalSigningKey()
		}
	}

	/// `prepareToEncrypt`'s own pre-check: refuses BEFORE `committingRound`
	/// ever runs (it writes `recvGroup` even for a bare catch-up-only
	/// round), independent of what `leafKeys` itself holds.
	@available(iOS 26, macOS 26, *)
	@Test func prepareToEncryptRefusesWhenEitherClassicalRoleHasNoCustody() throws {
		var (_, bobSend) = try SessionTestSupport.establishedAndExchanged()
		bobSend.noCustody = [.sendClassical]
		#expect(throws: TwoMLSError.leafCustodyUnavailable) {
			try bobSend.prepareToEncrypt()
		}

		var (_, bobRecv) = try SessionTestSupport.establishedAndExchanged()
		bobRecv.noCustody = [.recvClassical]
		#expect(throws: TwoMLSError.leafCustodyUnavailable) {
			try bobRecv.prepareToEncrypt()
		}
	}

	/// The PQ doors' own pre-checks: `pqRekeyBegin` (recv-PQ) and
	/// `pqRekeyRespond`/`pqBootstrapJoin`/`pqRatchetBind`/`pqRekeyApply`
	/// (send-PQ) all refuse before consuming anything. Exercised for
	/// `pqRekeyBegin`/`pqRekeyRespond`; the others follow the identical
	/// `guard !noCustody.contains(...)` placement.
	@available(iOS 26, macOS 26, *)
	@Test func pqDoorsRefuseWhenTheirGroupHasNoCustody() throws {
		var (_, bobBegin) = try RatchetTests.fullyEstablishedTurnOnBob()
		bobBegin.noCustody = [.recvPQ]
		#expect(throws: TwoMLSError.leafCustodyUnavailable) {
			try bobBegin.pqRekeyBegin()
		}

		var (aliceRespond, bobRespond) = try RatchetTests.fullyEstablishedTurnOnBob()
		let updFrame = try bobRespond.pqRekeyBegin().frame
		aliceRespond.noCustody = [.sendPQ]
		#expect(throws: TwoMLSError.leafCustodyUnavailable) {
			try aliceRespond.pqRekeyRespond(updFrame)
		}
	}

	/// Self-drive also skips while either send role has no custody
	/// (`stageRatchet` would fail on `sendClassical` anyway, but the guard
	/// is explicit so the auto-driver never even attempts it).
	@available(iOS 26, macOS 26, *)
	@Test func selfDriveSkipsWhenASendRoleHasNoCustody() throws {
		var (_, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		_ = try bob.prepareToEncrypt()
		bob.noCustody = [.sendPQ]
		#expect(throws: Never.self) { try bob.encrypt(Data("msg".utf8)) }
		#expect(bob.pendingSideBand == nil)
	}

	/// The choke point's monotone drain: once a group's own leaf key set
	/// genuinely has a `current` again, the NEXT `stateUpdate`-driven check
	/// (`assertLeafKeysPresented`) drops it from `noCustody` — without
	/// touching every promotion call site individually.
	@available(iOS 26, macOS 26, *)
	@Test func noCustodyDrainsOnceTheGroupGenuinelyHasACurrentKey() throws {
		var (_, bob) = try SessionTestSupport.establishedAndExchanged()
		let realCurrent = bob.leafKeys.sendClassical.current
		bob.leafKeys.sendClassical.current = nil
		bob.noCustody = [.sendClassical]
		#expect(throws: (any Error).self) { try bob.prepareToEncrypt() }

		bob.leafKeys.sendClassical.current = realCurrent
		try bob.assertLeafKeysPresented()
		#expect(
			!bob.noCustody.contains(.sendClassical),
			"drained once current is genuinely present")
	}

	// MARK: - Read-only queries

	@available(iOS 26, macOS 26, *)
	@Test func canSendReflectsBothClassicalRolesAndEstablishment() throws {
		var (_, bob) = try SessionTestSupport.establishedAndExchanged()
		#expect(bob.canSend)
		bob.noCustody = [.recvClassical]
		#expect(!bob.canSend)
	}

	@available(iOS 26, macOS 26, *)
	@Test func pqSideBandWedgedReflectsTheStoredWedge() throws {
		var (_, bob) = try SessionTestSupport.establishedAndExchanged()
		#expect(!bob.pqSideBandWedged)
		bob.pqWedge = .bootstrap
		#expect(bob.pqSideBandWedged)
	}
}

// MARK: - Own-offer window mutation coverage

extension DeployedStateTests {
	@available(iOS 26, macOS 26, *)
	private func knownSecretWindowFixture(
		_ offer: (ref: Data, bareProposal: Data, leafSecret: SecretBytes), epoch: UInt64,
		groupID: Data, senderLeafIndex: UInt32
	) throws -> (record: OwnOfferWindowRecord, blob: SecretArchive) {
		let migrated = MigratedOwnOffer(
			ref: offer.ref, proposal: offer.bareProposal, leafSecret: offer.leafSecret)
		let sorted = try OwnOfferWindow.canonicalOrder([migrated])
		let id = OwnOfferWindow.id(
			epoch: epoch, groupID: groupID, senderLeafIndex: senderLeafIndex,
			sorted: sorted)
		let record = OwnOfferWindowRecord(
			id: id, epoch: epoch, groupID: groupID, senderLeafIndex: senderLeafIndex,
			count: 1)
		let body = try OwnOfferWindowArchive(
			epoch: epoch, groupID: groupID, senderLeafIndex: senderLeafIndex,
			sorted: sorted)
		return (record, try SecretArchive(encoding: body))
	}

	/// The caller-supplied `leafSecret` branch resolves end to end
	/// when no group-held pair exists for the offer at all
	/// (`knownSecretOwnOffer` never writes back to the group).
	@available(iOS 26, macOS 26, *)
	@Test func suppliedSecretResolvesAtRuntime() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let built = try SessionTestSupport.knownSecretOwnOffer(in: bob)
		let digest = try SessionTestSupport.classicalProvider.hash(built.framedMessage)
		bob.pendingProposal = (
			proposing: bob.identity.clientID, message: built.framedMessage, hash: digest
		)
		let offerFrame = try bob.encrypt(Data("offer".utf8)).frame
		let decrypted = try alice.processIncomingDecrypted(offerFrame)
		try alice.queueProposal(digest: decrypted.queuedProposal.digest)
		_ = try alice.prepareToEncrypt()
		let fold = try alice.encrypt(Data("fold".utf8)).frame
		let fixture = try knownSecretWindowFixture(
			(built.ref, built.bareProposal, built.leafSecret), epoch: built.epoch,
			groupID: built.groupID, senderLeafIndex: built.senderLeafIndex)
		bob.ownOfferWindow = fixture.record
		guard
			case .decrypted(let d) = try bob.processIncoming(
				fold, ownOfferWindow: fixture.blob)
		else {
			Issue.record("expected decrypted")
			return
		}
		#expect(d.didApplyRemoteCommit)
		#expect(bob.ownOfferWindow == nil)
	}

	/// A supplied `leafSecret` that doesn't match the offer's own
	/// HPKE public key is unusable — the caller-supplied branch actually
	/// runs, it isn't skipped.
	@available(iOS 26, macOS 26, *)
	@Test func wrongSuppliedSecretIsUnavailable() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let built = try SessionTestSupport.knownSecretOwnOffer(in: bob)
		let digest = try SessionTestSupport.classicalProvider.hash(built.framedMessage)
		bob.pendingProposal = (
			proposing: bob.identity.clientID, message: built.framedMessage, hash: digest
		)
		let offerFrame = try bob.encrypt(Data("offer".utf8)).frame
		let decrypted = try alice.processIncomingDecrypted(offerFrame)
		try alice.queueProposal(digest: decrypted.queuedProposal.digest)
		_ = try alice.prepareToEncrypt()
		let fold = try alice.encrypt(Data("fold".utf8)).frame
		let wrongSecret = try SessionTestSupport.classicalProvider.hpkeGenerateKeyPair().0
			.data
		let fixture = try knownSecretWindowFixture(
			(built.ref, built.bareProposal, wrongSecret), epoch: built.epoch,
			groupID: built.groupID, senderLeafIndex: built.senderLeafIndex)
		bob.ownOfferWindow = fixture.record
		#expect(throws: TwoMLSError.ownOfferUnavailable) {
			try bob.processIncoming(fold, ownOfferWindow: fixture.blob)
		}
	}

	/// A verified FRAMED copy of an own Update always wins over a
	/// window entry naming the SAME ref with a different (but validly
	/// shaped) proposal/secret — the framed store is never overwritten by
	/// the window's copy.
	@available(iOS 26, macOS 26, *)
	@Test func framedCopyWinsOverWindow() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		_ = try alice.prepareToEncrypt()
		_ = try bob.processIncomingDecrypted(try alice.encrypt(Data("a".utf8)).frame)
		_ = try bob.prepareToEncrypt()
		let framed = try #require(bob.stagedUpdates.last)
		let offerFrame = try bob.encrypt(Data("offer".utf8)).frame
		let decrypted = try alice.processIncomingDecrypted(offerFrame)
		try alice.queueProposal(digest: decrypted.queuedProposal.digest)
		_ = try alice.prepareToEncrypt()
		let fold = try alice.encrypt(Data("fold".utf8)).frame

		guard
			case .publicMessage(let framedPub) = try MLS.RFC9420.Message(
				mlsEncoded: framed.message)
		else {
			Issue.record("expected a publicMessage-framed Update")
			return
		}
		var scratch = MLS.RFC9420.ProposalStore()
		let recvGroup = try #require(bob.recvGroup)
		let framedRef = try scratch.insert(
			try recvGroup.classical.verifying(
				SessionTestSupport.classicalProvider, proposal: framedPub),
			SessionTestSupport.classicalProvider)
		// A different, but independently valid, own-offer under the SAME
		// ref: if the window's copy ever won, this would still resolve
		// (it's genuinely valid) — the assertion is that it DOESN'T get
		// the chance to.
		let other = try SessionTestSupport.knownSecretOwnOffer(in: bob)
		let fixture = try knownSecretWindowFixture(
			(framedRef.data, other.bareProposal, other.leafSecret), epoch: other.epoch,
			groupID: other.groupID, senderLeafIndex: other.senderLeafIndex)

		var noBlob = bob
		noBlob.ownOfferWindow = fixture.record
		guard case .decrypted(let d1) = try noBlob.processIncoming(fold) else {
			Issue.record("expected decrypted")
			return
		}
		#expect(d1.didApplyRemoteCommit)
		#expect(noBlob.ownOfferWindow == nil, "framed fold drains the record")

		var withBlob = bob
		withBlob.ownOfferWindow = fixture.record
		guard
			case .decrypted(let d2) = try withBlob.processIncoming(
				fold, ownOfferWindow: fixture.blob)
		else {
			Issue.record("expected decrypted")
			return
		}
		#expect(d2.didApplyRemoteCommit)
	}

	/// Items 3a/3d: on the `0x05` bind path, own-Update detection runs
	/// BEFORE the PQ half, not after and not skipped. A tampered PQ half
	/// with an otherwise-untampered classical half still demands/consumes
	/// the window first — a window-missing failure never gets masked by,
	/// or reordered after, the PQ half's own failure.
	@available(iOS 26, macOS 26, *)
	@Test func bindDetectionPrecedesPQHalf() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let kpFrame = try alice.pqBootstrapBegin().frame
		let welcomeFrame = try bob.pqBootstrapRespond(kpFrame).frame
		_ = try alice.pqBootstrapJoin(welcomeFrame)
		#expect(alice.owedBind != nil)
		let round = try foldedButUnframedOwnOfferRound(proposer: &bob, approver: &alice)
		let fixture = try knownSecretWindowFixture(
			(round.ref, round.bareProposal, SecretBytes(randomByteCount: 32)),
			epoch: round.epoch, groupID: round.groupID,
			senderLeafIndex: round.senderLeafIndex)
		let opened = bob.openOrRaw(round.foldFrame)
		let (staple, proposalSection, appSection) = try Frames.decodeMessageFrame(opened)
		#expect(staple.first == Frames.apqPrivateMessageTag)

		// (a) untampered: demand, then resolve through applyBind.
		var b0 = bob
		b0.ownOfferWindow = fixture.record
		#expect(throws: TwoMLSError.ownOfferWindowRequired) {
			try b0.processIncoming(round.foldFrame)
		}
		guard
			case .decrypted(let d) = try b0.processIncoming(
				round.foldFrame, ownOfferWindow: fixture.blob)
		else {
			Issue.record("expected decrypted")
			return
		}
		#expect(d.didApplyRemoteCommit)
		#expect(b0.ownOfferWindow == nil)

		// (b) PQ half tampered, classical half intact: still demands the
		// window rather than surfacing a PQ failure.
		var (t, pq) = try Frames.decodeAPQPrivateMessage(staple)
		pq[pq.index(before: pq.endIndex)] ^= 0xFF
		_ = t
		let tampered = Frames.encodeMessageFrame(
			staple: Frames.encodeAPQPrivateMessage(t: t, pq: pq),
			proposal: proposalSection,
			app: appSection)
		var b1 = bob
		b1.ownOfferWindow = fixture.record
		let seq = b1.stateSeq
		#expect(throws: TwoMLSError.ownOfferWindowRequired) {
			try b1.processIncoming(tampered)
		}
		#expect(b1.stateSeq == seq)
		// (c) with the window supplied, the PQ failure surfaces (proving
		// detection is not just a happy-path early return) and nothing
		// moved.
		do {
			_ = try b1.processIncoming(tampered, ownOfferWindow: fixture.blob)
			Issue.record("expected processIncoming to throw")
		} catch {
			#expect(error as? TwoMLSError != .ownOfferWindowRequired)
		}
		#expect(b1.ownOfferWindow == fixture.record)
		#expect(b1.stateSeq == seq)
	}

	/// On the fold-only `0x00` path, own-Update detection
	/// runs BEFORE the inline-proposal allow-list check
	/// (`TwoPartyRules.validateInlineProposals`), not after. A commit that
	/// is BOTH window-missing AND carries an inline proposal that allow-list
	/// would reject must still surface `.ownOfferWindowRequired` — not
	/// whatever error the allow-list would have thrown — proving detection
	/// isn't reachable only on the happy path where the rest of the commit
	/// is otherwise valid.
	@available(iOS 26, macOS 26, *)
	@Test func foldDetectionPrecedesInlineProposalValidation() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let built = try handBuiltUnframedOwnOffer(in: &bob)
		let digest = try SessionTestSupport.classicalProvider.hash(built.framedMessage)
		bob.pendingProposal = (
			proposing: bob.identity.clientID, message: built.framedMessage, hash: digest
		)
		let offerFrame = try bob.encrypt(Data("offer".utf8)).frame
		let decrypted = try alice.processIncomingDecrypted(offerFrame)
		try alice.queueProposal(digest: decrypted.queuedProposal.digest)
		// A record must exist for detection to engage at all — no blob is
		// ever supplied below, so this only proves the DEMAND still wins.
		let fixture = try knownSecretWindowFixture(
			(built.ref, built.bareProposal, SecretBytes(randomByteCount: 32)),
			epoch: built.epoch, groupID: built.groupID,
			senderLeafIndex: built.senderLeafIndex)
		bob.ownOfferWindow = fixture.record

		// Hand-build ALICE's fold commit (mirrors `FoldTests.
		// testFoldEffectsWithAnAddThrowsUnexpectedProposal`'s technique): the
		// approved-but-unframed Update folded by reference, PLUS an inline
		// external PSK proposal the fold-only allow-list never permits
		// (`expectedExternalPSKIDs: []`).
		let sendGroupA = try #require(alice.sendGroup)
		guard
			case .publicMessage(let updatePub) = try MLS.RFC9420.Message(
				mlsEncoded: built.framedMessage)
		else {
			Issue.record("expected a publicMessage-framed Update")
			return
		}
		let verified = try sendGroupA.classical.verifying(
			SessionTestSupport.classicalProvider, proposal: updatePub)
		var proposalStore = MLS.RFC9420.ProposalStore()
		let ref = try proposalStore.insert(verified, SessionTestSupport.classicalProvider)
		let badCommitBytes = try withDeployedWireConventions { () throws -> Data in
			let transition = try sendGroupA.classical.committing(
				SessionTestSupport.classicalProvider,
				proposals: [
					.reference(ref),
					.proposal(
						.preSharedKey(
							.external(
								pskID: Data(
									"unexpected-external-psk"
										.utf8),
								nonce: Data(repeating: 0, count: 32)
							))),
				],
				proposalStore: proposalStore,
				signingKey: try alice.sendClassicalSigningKey(),
				randomness: try .generate(SessionTestSupport.classicalProvider),
				includePath: true, framing: .publicMessage,
				psk: { _ in SecretBytes(randomByteCount: 32) })
			return try transition.takeOutput().message.mlsEncoded()
		}
		let badStaple = Frames.encodeMlsMessageStaple(badCommitBytes)
		// A throwaway carrier frame, only to get a genuine proposal/app
		// section shape to splice the hand-built staple into — `handleStaple`
		// never reaches either section before this test's own assertion.
		_ = try alice.prepareToEncrypt()
		let carrierFrame = try alice.encrypt(Data("carrier".utf8)).frame
		let (_, proposalSection, appSection) = try Frames.decodeMessageFrame(
			bob.openOrRaw(carrierFrame))
		let badFrame = Frames.encodeMessageFrame(
			staple: badStaple, proposal: proposalSection, app: appSection)

		// The framed store bob holds never carried this ref
		// (`handBuiltUnframedOwnOffer`'s whole point) — with no window
		// supplied, detection must win the race against the smuggled PSK.
		let seq = bob.stateSeq
		#expect(throws: TwoMLSError.ownOfferWindowRequired) {
			try bob.processIncoming(badFrame)
		}
		#expect(bob.stateSeq == seq, "retryable: nothing changed")
	}
}
