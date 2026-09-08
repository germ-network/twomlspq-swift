import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import TwoMLSPQCrypto
import XCTest

@testable import TwoMLSPQSession

/// `APQGroup.checkAPQInfoDeferred`, the pure half of `verifyAPQInfoDeferred`:
/// a hand-built `APQInfo` against an observed group id/epoch and the expected
/// suite pair, with no real `Group` involved — mirrors the combiner's own
/// `checkAPQInfoConsistentPinsEachEpochClause` shape, one clause per test so a
/// single-field mismatch is independently pinned.
@available(iOS 26, macOS 26, *)
final class APQGroupTests: XCTestCase {
	private static let classicalSuite = MLS.CipherSuite.curve25519ChaCha
	private static let pqSuite = MLS.CipherSuite(id: MLKEM768CipherSuiteProvider.cipherSuiteID)
	private static let observedGroupID = Data([1, 2, 3])
	private static let observedEpoch: UInt64 = 1
	private static let pqGroupID = Data([4, 5, 6])

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

	private func assertMismatch(_ info: MLS.Combiner.APQInfo) {
		XCTAssertThrowsError(
			try APQGroup.checkAPQInfoDeferred(
				info: info, observedGroupID: Self.observedGroupID,
				observedEpoch: Self.observedEpoch,
				classicalSuite: Self.classicalSuite,
				pqSuite: Self.pqSuite)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .deferredApqInfoMismatch)
		}
	}

	func testValidInfoPasses() throws {
		XCTAssertNoThrow(
			try APQGroup.checkAPQInfoDeferred(
				info: makeInfo(), observedGroupID: Self.observedGroupID,
				observedEpoch: Self.observedEpoch,
				classicalSuite: Self.classicalSuite,
				pqSuite: Self.pqSuite))
	}

	func testRejectsBoundPqEpoch() {
		assertMismatch(makeInfo(pqEpoch: 1))
	}

	func testRejectsUnboundTEpochEvenWithUnboundPqEpoch() {
		assertMismatch(makeInfo(tEpoch: epochUnbound, pqEpoch: epochUnbound))
	}

	func testRejectsEmptyPqSessionGroupID() {
		assertMismatch(makeInfo(pqSessionGroupID: Data()))
	}

	func testRejectsWrongTSessionGroupID() {
		assertMismatch(makeInfo(tSessionGroupID: Data([9, 9, 9])))
	}

	func testRejectsTEpochNotMatchingObserved() {
		assertMismatch(makeInfo(tEpoch: 2))
	}

	func testRejectsWrongTCipherSuite() {
		assertMismatch(makeInfo(tCipherSuite: MLS.CipherSuite(id: 0xFFFF)))
	}

	func testRejectsWrongPqCipherSuite() {
		assertMismatch(makeInfo(pqCipherSuite: MLS.CipherSuite(id: 0xFFFF)))
	}
}
