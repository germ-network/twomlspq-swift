import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import Testing
import TwoMLSPQCrypto

@testable import TwoMLSPQSession

/// `APQGroup.checkAPQInfoDeferred`, the pure half of `verifyAPQInfoDeferred`:
/// a hand-built `APQInfo` against an observed group id/epoch and the expected
/// suite pair, with no real `Group` involved — mirrors the combiner's own
/// `checkAPQInfoConsistentPinsEachEpochClause` shape, one clause per test so a
/// single-field mismatch is independently pinned.
@Suite struct APQGroupTests {
	private static let classicalSuite = MLS.CipherSuite.curve25519ChaCha
	/// `MLKEM768CipherSuiteProvider.cipherSuiteID` is gated to iOS/macOS 26,
	/// so it cannot back a stored `static let` in this ungated suite —
	/// computed instead, mirroring `CombinerKeyPackageWireTests.makeIdentity()`'s
	/// stored-property-of-a-gated-value workaround.
	@available(iOS 26, macOS 26, *)
	private static var pqSuite: MLS.CipherSuite {
		MLS.CipherSuite(id: MLKEM768CipherSuiteProvider.cipherSuiteID)
	}
	private static let observedGroupID = Data([1, 2, 3])
	private static let observedEpoch: UInt64 = 1
	private static let pqGroupID = Data([4, 5, 6])

	@available(iOS 26, macOS 26, *)
	private func makeInfo(
		tSessionGroupID: Data = observedGroupID,
		pqSessionGroupID: Data = pqGroupID,
		tCipherSuite: MLS.CipherSuite = classicalSuite,
		pqCipherSuite: MLS.CipherSuite = pqSuite,
		tEpoch: UInt64 = observedEpoch,
		pqEpoch: UInt64 = epochUnbound
	) -> MLS.Combiner.APQInfo {
		MLS.Combiner.APQInfo(
			tSessionGroupID: tSessionGroupID, pqSessionGroupID: pqSessionGroupID,
			mode: 0, tCipherSuite: tCipherSuite, pqCipherSuite: pqCipherSuite,
			tEpoch: tEpoch, pqEpoch: pqEpoch)
	}

	@available(iOS 26, macOS 26, *)
	private func assertMismatch(_ info: MLS.Combiner.APQInfo) {
		#expect(throws: TwoMLSError.deferredApqInfoMismatch) {
			try APQGroup.checkAPQInfoDeferred(
				info: info, observedGroupID: Self.observedGroupID,
				observedEpoch: Self.observedEpoch,
				classicalSuite: Self.classicalSuite,
				pqSuite: Self.pqSuite)
		}
	}

	@available(iOS 26, macOS 26, *)
	@Test func validInfoPasses() throws {
		#expect(throws: Never.self) {
			try APQGroup.checkAPQInfoDeferred(
				info: makeInfo(), observedGroupID: Self.observedGroupID,
				observedEpoch: Self.observedEpoch,
				classicalSuite: Self.classicalSuite,
				pqSuite: Self.pqSuite)
		}
	}

	@available(iOS 26, macOS 26, *)
	@Test func rejectsBoundPqEpoch() {
		assertMismatch(makeInfo(pqEpoch: 1))
	}

	@available(iOS 26, macOS 26, *)
	@Test func rejectsUnboundTEpochEvenWithUnboundPqEpoch() {
		assertMismatch(makeInfo(tEpoch: epochUnbound, pqEpoch: epochUnbound))
	}

	@available(iOS 26, macOS 26, *)
	@Test func rejectsEmptyPqSessionGroupID() {
		assertMismatch(makeInfo(pqSessionGroupID: Data()))
	}

	@available(iOS 26, macOS 26, *)
	@Test func rejectsWrongTSessionGroupID() {
		assertMismatch(makeInfo(tSessionGroupID: Data([9, 9, 9])))
	}

	@available(iOS 26, macOS 26, *)
	@Test func rejectsTEpochNotMatchingObserved() {
		assertMismatch(makeInfo(tEpoch: 2))
	}

	@available(iOS 26, macOS 26, *)
	@Test func rejectsWrongTCipherSuite() {
		assertMismatch(makeInfo(tCipherSuite: MLS.CipherSuite(id: 0xFFFF)))
	}

	@available(iOS 26, macOS 26, *)
	@Test func rejectsWrongPqCipherSuite() {
		assertMismatch(makeInfo(pqCipherSuite: MLS.CipherSuite(id: 0xFFFF)))
	}
}
