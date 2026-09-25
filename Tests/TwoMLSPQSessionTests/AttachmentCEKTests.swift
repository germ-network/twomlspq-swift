import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes
import Testing
import TwoMLSPQCrypto

@testable import TwoMLSPQSession

/// Attachment CEK export (value-engine parity): `exportAttachmentCEKSend`/
/// `exportAttachmentCEKRecv` (+Attachment.swift) derive
/// `ExpandWithLabel(SafeExportSecret_classical(0xFF03), "attachment", keyId,
/// 32)` off the eagerly-ledgered `0xFF03` component, mirroring the proven
/// `0xFF02` cross-party PSK ledger (`sendCrossPSKLedger`). Both exports are
/// PURE READS, so every session in these tests can stay a `let` unless a
/// test itself needs to drive a commit (`advanceEpochByFold`).
@Suite struct AttachmentCEKTests {
	private let sealKey = SecretBytes(randomByteCount: 32)
	private let sealAAD = Data("attachment-cek-tests".utf8)

	private func sealAndOpen(_ archive: SecretArchive) throws -> SecretArchive {
		let sealed = try archive.seal(with: sealKey, aad: sealAAD)
		return try SecretArchive.open(sealed, with: sealKey, aad: sealAAD)
	}

	/// One classical fold round (mirrors `FoldTests.surfaceOffer` +
	/// `queueProposal`/`prepareToEncrypt`/`encrypt`/`processIncoming`),
	/// used here only to advance a classical epoch on both sides —
	/// `proposer` stages an `Upd(self)` into `approver`'s send group,
	/// `approver` approves and folds it (advancing ITS OWN send-group
	/// epoch), and `proposer` applies the resulting staple (advancing ITS
	/// OWN recv-group epoch to match).
	@available(iOS 26, macOS 26, *)
	private func advanceEpochByFold(
		proposer: inout TwoMLSSession, approver: inout TwoMLSSession
	) throws {
		_ = try proposer.prepareToEncrypt()
		let offerFrame = try proposer.encrypt(Data("offer".utf8)).frame
		let offered = try approver.processIncomingDecrypted(offerFrame)
		_ = try approver.queueProposal(digest: offered.queuedProposal.digest)
		_ = try approver.prepareToEncrypt()
		let foldFrame = try approver.encrypt(Data("fold".utf8)).frame
		_ = try proposer.processIncomingDecrypted(foldFrame)
	}

	// MARK: - Cross-peer equality, determinism, keyId sensitivity

	/// Group_A (Alice's send group / Bob's recv group) is a full pair from
	/// `initiate`/`receive`'s own construction, both at epoch 1 — so this
	/// needs no fold round: `established()` alone already leaves both
	/// ledgers populated at epoch 1.
	@available(iOS 26, macOS 26, *)
	@Test func sendRecvCEKsMatchAcrossPeersAndAreDeterministicPerKeyId() throws {
		let (alice, bob, _, _, _, _) = try SessionTestSupport.established()
		let keyId = Data(repeating: 0x01, count: 32)

		let aliceCEK = try alice.exportAttachmentCEKSend(keyId: keyId)
		let bobCEK = try bob.exportAttachmentCEKRecv(keyId: keyId, epoch: 1)
		#expect(aliceCEK == bobCEK)
		#expect(aliceCEK.count == 32)

		// A pure read: repeating either direction is stable.
		#expect(try alice.exportAttachmentCEKSend(keyId: keyId) == aliceCEK)
		#expect(
			try bob.exportAttachmentCEKRecv(keyId: keyId, epoch: 1) == bobCEK)

		// A different keyId over the SAME epoch's component derives an
		// unrelated CEK.
		let otherKeyId = Data(repeating: 0x02, count: 32)
		#expect(try alice.exportAttachmentCEKSend(keyId: otherKeyId) != aliceCEK)
	}

	// MARK: - Recv at a past epoch (the reason recv is epoch-keyed)

	/// Bob sends (derives) an attachment CEK while Group_B (his send group /
	/// Alice's recv group) is still at epoch 1; a fold round then advances
	/// Group_B past that epoch on both sides. Alice's `exportAttachmentCEKRecv`
	/// at the now-past epoch 1 must still resolve — the ledger hit
	/// `recvAttachmentLedger` exists for.
	@available(iOS 26, macOS 26, *)
	@Test func recvAtPastEpochStillResolvesAfterRecvGroupAdvances() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let keyId = Data(repeating: 0x03, count: 32)

		#expect(bob.sendGroup!.classical.context.epoch == 1)
		let bobCEKAtEpoch1 = try bob.exportAttachmentCEKSend(keyId: keyId)

		try advanceEpochByFold(proposer: &alice, approver: &bob)
		#expect(bob.sendGroup!.classical.context.epoch > 1)
		#expect(alice.recvGroup!.classical.context.epoch > 1)

		let recvAtPastEpoch = try alice.exportAttachmentCEKRecv(keyId: keyId, epoch: 1)
		#expect(recvAtPastEpoch == bobCEKAtEpoch1)

		// The CURRENT epoch's own component is also ledgered (capture-on-
		// entry), and derives a DIFFERENT CEK than epoch 1's.
		let currentEpoch = alice.recvGroup!.classical.context.epoch
		let recvAtCurrentEpoch = try alice.exportAttachmentCEKRecv(
			keyId: keyId, epoch: currentEpoch)
		#expect(recvAtCurrentEpoch != recvAtPastEpoch)
	}

	// MARK: - Unavailable component

	/// An epoch this session's recv ledger never captured (never lived, in
	/// this pairing) throws `.attachmentComponentUnavailable` rather than
	/// deriving nonsense from an absent component.
	@available(iOS 26, macOS 26, *)
	@Test func recvAtNeverCapturedEpochThrowsAttachmentComponentUnavailable() throws {
		let (_, bob, _, _, _, _) = try SessionTestSupport.established()
		#expect(throws: TwoMLSError.attachmentComponentUnavailable) {
			try bob.exportAttachmentCEKRecv(
				keyId: Data(repeating: 0x04, count: 32), epoch: 999)
		}
	}

	// MARK: - Restore survival

	/// Archive Alice (whose recv group, Group_B, has been advanced past
	/// epoch 1 by a fold round) at Checkpoint, round-trip through the
	/// app-seal boundary (mirrors `SessionArchiveTests`), restore, and
	/// confirm `exportAttachmentCEKRecv` at the pre-restore epoch 1 still
	/// resolves to the SAME bytes the live session saw before archiving.
	@available(iOS 26, macOS 26, *)
	@Test func restoreSurvivesPastEpochRecvExport() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let keyId = Data(repeating: 0x05, count: 32)
		let bobCEKAtEpoch1 = try bob.exportAttachmentCEKSend(keyId: keyId)

		try advanceEpochByFold(proposer: &alice, approver: &bob)
		let aliceRecvCEKAtEpoch1BeforeArchive = try alice.exportAttachmentCEKRecv(
			keyId: keyId, epoch: 1)
		#expect(aliceRecvCEKAtEpoch1BeforeArchive == bobCEKAtEpoch1)

		let archive = try alice.makeSessionArchive(kind: .checkpoint)
		let opened = try sealAndOpen(archive)
		let restored = try TwoMLSSession.restore(
			core: nil, checkpoint: opened,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		let restoredRecvCEKAtEpoch1 = try restored.exportAttachmentCEKRecv(
			keyId: keyId, epoch: 1)
		#expect(restoredRecvCEKAtEpoch1 == bobCEKAtEpoch1)
	}

	// MARK: - Known-answer: independent recomputation (iOS byte-compat)

	/// The other tests in this file only prove the two Swift peers agree
	/// with EACH OTHER — a symmetric drift (renaming the `"attachment"`
	/// label, or the componentID/length, identically on both the send and
	/// recv sides) would still pass all of them while silently diverging
	/// from the deployed engine, which is the entire point of the faithful
	/// (byte-compat) path this ports. This test instead recomputes the CEK
	/// via a HAND-ROLLED RFC 9420 §8 `KDFLabel` encoding — hardcoded byte
	/// literals via `MLS.Writer` directly, never by calling
	/// `MLS.expandWithLabel` or the (private) `KDFLabel` type in
	/// Labels.swift, which is exactly what `exportAttachmentCEKSend` itself
	/// calls — so a drift in the label string, the length, or the field
	/// encoding is caught independently of that shared call.
	///
	/// `MLS.Writer.writeOpaque`'s own varint convention (MLSCodec's
	/// `Varint.swift`: any length `< 0x40` — both the 19-byte label and the
	/// 32-byte `keyId` here — encodes as a single length byte with the top
	/// two bits `00`, i.e. the raw byte count with no continuation marker)
	/// is reproduced here by calling that SAME low-level codec primitive
	/// directly (trusted, independently unit-tested elsewhere in swift-mls),
	/// rather than reimplementing HKDF/varint bit-twiddling by hand — what
	/// this test keeps independent is the LABEL/LENGTH/FIELD-ORDER choice,
	/// not the codec's own byte-packing.
	@available(iOS 26, macOS 26, *)
	@Test func attachmentCEKMatchesIndependentlyRecomputedKDFLabel() throws {
		#expect(TwoMLSSession.attachmentComponentID.rawValue == 0xFF03)

		let alice = try SessionTestSupport.established().alice
		let keyId = Data(repeating: 0x06, count: 32)
		let epoch = alice.sendGroup!.classical.context.epoch
		let component = try #require(alice.sendAttachmentLedger[epoch])

		// RFC 9420 §8 KDFLabel: struct { uint16 length; opaque label<V>;
		// opaque context<V>; } with label = "MLS 1.0 " + Label. Every literal
		// below is hardcoded, not read from prod's `Labels.swift`.
		var writer = MLS.Writer()
		writer.writeUInt16(32)
		try writer.writeOpaque(Data("MLS 1.0 attachment".utf8))
		try writer.writeOpaque(keyId)
		let info = writer.data

		let expected = try SessionTestSupport.classicalProvider.kdfExpand(
			prk: component, info: info, length: 32)
		#expect(try alice.exportAttachmentCEKSend(keyId: keyId) == expected)
	}

	// MARK: - Window eviction (optional, cheap)

	/// Drives the recv ledger past its retention window (`attachmentLedgerWindow`,
	/// 8) with 8 fold rounds — epoch 1's component, resolvable before the
	/// loop, is evicted once a 9th distinct epoch has been ledgered, and a
	/// later fetch at epoch 1 throws `.attachmentComponentUnavailable`. The
	/// current epoch's own component stays available throughout.
	@available(iOS 26, macOS 26, *)
	@Test func recvLedgerEvictsOldestEpochBeyondWindow() throws {
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let keyId = Data(repeating: 0x07, count: 32)

		#expect(throws: Never.self) {
			try alice.exportAttachmentCEKRecv(keyId: keyId, epoch: 1)
		}

		for _ in 0..<8 {
			try advanceEpochByFold(proposer: &alice, approver: &bob)
		}
		let currentEpoch = alice.recvGroup!.classical.context.epoch
		#expect(currentEpoch == 9)

		#expect(throws: TwoMLSError.attachmentComponentUnavailable) {
			try alice.exportAttachmentCEKRecv(keyId: keyId, epoch: 1)
		}
		#expect(throws: Never.self) {
			try alice.exportAttachmentCEKRecv(keyId: keyId, epoch: currentEpoch)
		}
	}

	// MARK: - Restore fail-closed on an inconsistent stripped ledger
	//
	// A literal "decode an archive, strip keys 37/38, re-seal, restore,
	// confirm SUCCESS" test (as one might expect to mirror
	// `listenRendezvous`/`recvHeaderKeys`'s own pre-existing-archive
	// tolerance) is not constructible against THIS session: `initiate`
	// eagerly captures `sendAttachmentLedger` at construction
	// (`captureSendAttachmentComponent`), which CONSUMES the group's
	// `0xFF03` leaf for that epoch there and then — the archived group
	// snapshot's exporter-tree frontier already reflects that consumption
	// (SafeExport.swift). Stripping the archived ledger afterward does not
	// recreate a genuine pre-feature archive (whose exporter tree would
	// still show the leaf UNCONSUMED); it manufactures exactly the
	// inconsistent state `TwoMLSSession+Restore.swift`'s new
	// `ExporterTree.ExportError` → `.archiveInvalid` mapping exists to
	// reject (an archived ledger claiming "never captured" for an epoch the
	// group itself already shows as spent). This test confirms that
	// fail-closed path instead, since it is otherwise uncovered.
	@available(iOS 26, macOS 26, *)
	@Test func strippedSendAttachmentLedgerOnAlreadyCapturedSessionFailsClosed() throws {
		let alice = try SessionTestSupport.established().alice
		let archive = try alice.makeSessionArchive(kind: .checkpoint)
		var body = try archive.decode(SessionArchive.self)

		body.sendAttachmentLedger = nil
		body.recvAttachmentLedger = nil

		#expect(throws: TwoMLSError.archiveInvalid) {
			try TwoMLSSession.restore(
				core: nil, checkpoint: try SecretArchive(encoding: body),
				classicalProvider: SessionTestSupport.classicalProvider,
				pqProvider: SessionTestSupport.pqProvider)
		}
	}
}
