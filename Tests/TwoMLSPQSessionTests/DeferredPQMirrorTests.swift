import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import TwoMLSPQCrypto
import XCTest

@testable import TwoMLSPQSession

/// `APQGroup.checkDeferredPQMirror`, the pure half of
/// `verifyDeferredPQMirrorInfo`: two hand-built `APQInfo`s against an
/// observed pq group id/epoch, with no real `Group` involved — the PQ-half
/// analogue of `APQGroupTests`' `checkAPQInfoDeferred` pinning, one clause per
/// test.
@available(iOS 26, macOS 26, *)
final class DeferredPQMirrorTests: XCTestCase {
	private static let classicalSuite = MLS.CipherSuite.curve25519ChaCha
	private static let pqSuite = MLS.CipherSuite(id: MLKEM768CipherSuiteProvider.cipherSuiteID)
	private static let tSessionGroupID = Data([1, 2, 3])
	private static let pqSessionGroupID = Data([4, 5, 6])
	private static let observedPQEpoch: UInt64 = 1

	private func makePQInfo(
		tSessionGroupID: Data = tSessionGroupID,
		pqSessionGroupID: Data = pqSessionGroupID,
		mode: UInt8 = 0,
		tCipherSuite: MLS.CipherSuite = classicalSuite,
		pqCipherSuite: MLS.CipherSuite = pqSuite,
		tEpoch: UInt64 = epochUnbound,
		pqEpoch: UInt64 = observedPQEpoch
	) -> MLS.Combiner.APQInfo {
		MLS.Combiner.APQInfo(
			tSessionGroupID: tSessionGroupID, pqSessionGroupID: pqSessionGroupID,
			mode: mode, tCipherSuite: tCipherSuite, pqCipherSuite: pqCipherSuite,
			tEpoch: tEpoch, pqEpoch: pqEpoch)
	}

	private func makeClassicalInfo(
		tSessionGroupID: Data = tSessionGroupID,
		pqSessionGroupID: Data = pqSessionGroupID,
		mode: UInt8 = 0,
		tCipherSuite: MLS.CipherSuite = classicalSuite,
		pqCipherSuite: MLS.CipherSuite = pqSuite
	) -> MLS.Combiner.APQInfo {
		MLS.Combiner.APQInfo(
			tSessionGroupID: tSessionGroupID, pqSessionGroupID: pqSessionGroupID,
			mode: mode, tCipherSuite: tCipherSuite, pqCipherSuite: pqCipherSuite,
			tEpoch: 1, pqEpoch: epochUnbound)
	}

	private func assertMismatch(
		pqInfo: MLS.Combiner.APQInfo, classicalInfo: MLS.Combiner.APQInfo
	) {
		XCTAssertThrowsError(
			try APQGroup.checkDeferredPQMirror(
				pqInfo: pqInfo, classicalInfo: classicalInfo,
				observedPQGroupID: Self.pqSessionGroupID,
				observedPQEpoch: Self.observedPQEpoch)
		) { error in
			XCTAssertEqual(error as? TwoMLSError, .deferredPQMirrorMismatch)
		}
	}

	func testValidPairPasses() throws {
		XCTAssertNoThrow(
			try APQGroup.checkDeferredPQMirror(
				pqInfo: makePQInfo(), classicalInfo: makeClassicalInfo(),
				observedPQGroupID: Self.pqSessionGroupID,
				observedPQEpoch: Self.observedPQEpoch))
	}

	func testRejectsBoundTEpoch() {
		assertMismatch(pqInfo: makePQInfo(tEpoch: 1), classicalInfo: makeClassicalInfo())
	}

	func testRejectsWrongPqEpoch() {
		assertMismatch(pqInfo: makePQInfo(pqEpoch: 2), classicalInfo: makeClassicalInfo())
	}

	func testRejectsPqSessionGroupIDNotMatchingObserved() {
		assertMismatch(
			pqInfo: makePQInfo(pqSessionGroupID: Data([9, 9, 9])),
			classicalInfo: makeClassicalInfo())
	}

	func testRejectsMismatchedIdentityFieldTSessionGroupID() {
		assertMismatch(
			pqInfo: makePQInfo(),
			classicalInfo: makeClassicalInfo(tSessionGroupID: Data([9, 9, 9])))
	}

	func testRejectsMismatchedIdentityFieldMode() {
		assertMismatch(pqInfo: makePQInfo(), classicalInfo: makeClassicalInfo(mode: 1))
	}

	func testRejectsWrongTCipherSuite() {
		assertMismatch(
			pqInfo: makePQInfo(tCipherSuite: MLS.CipherSuite(id: 0xFFFF)),
			classicalInfo: makeClassicalInfo())
	}

	func testRejectsWrongPqCipherSuite() {
		assertMismatch(
			pqInfo: makePQInfo(pqCipherSuite: MLS.CipherSuite(id: 0xFFFF)),
			classicalInfo: makeClassicalInfo(pqCipherSuite: MLS.CipherSuite(id: 0xFFFF))
		)
	}
}
