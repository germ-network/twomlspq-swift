import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import Testing
import TwoMLSPQCrypto

@testable import TwoMLSPQSession

/// `APQGroup.checkDeferredPQMirror`, the pure half of
/// `verifyDeferredPQMirrorInfo`: two hand-built `APQInfo`s against an
/// observed pq group id/epoch, with no real `Group` involved — the PQ-half
/// analogue of `APQGroupTests`' `checkAPQInfoDeferred` pinning, one clause per
/// test.
@Suite struct DeferredPQMirrorTests {
	private static let classicalSuite = MLS.CipherSuite.curve25519ChaCha
	/// A computed property, not a stored one: its initializer reaches a
	/// gated API (`MLKEM768CipherSuiteProvider`), and a stored `static let`
	/// of that shape would have to be valid unconditionally, which this
	/// ungated suite's own (lower) availability floor can't satisfy.
	@available(iOS 26, macOS 26, *)
	private static var pqSuite: MLS.CipherSuite {
		MLS.CipherSuite(id: MLKEM768CipherSuiteProvider.cipherSuiteID)
	}
	private static let tSessionGroupID = Data([1, 2, 3])
	private static let pqSessionGroupID = Data([4, 5, 6])
	private static let observedPQEpoch: UInt64 = 1

	@available(iOS 26, macOS 26, *)
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

	@available(iOS 26, macOS 26, *)
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

	@available(iOS 26, macOS 26, *)
	private func assertMismatch(
		pqInfo: MLS.Combiner.APQInfo, classicalInfo: MLS.Combiner.APQInfo
	) {
		#expect(throws: TwoMLSError.deferredPQMirrorMismatch) {
			try APQGroup.checkDeferredPQMirror(
				pqInfo: pqInfo, classicalInfo: classicalInfo,
				observedPQGroupID: Self.pqSessionGroupID,
				observedPQEpoch: Self.observedPQEpoch)
		}
	}

	@available(iOS 26, macOS 26, *)
	@Test func validPairPasses() throws {
		#expect(throws: Never.self) {
			try APQGroup.checkDeferredPQMirror(
				pqInfo: makePQInfo(), classicalInfo: makeClassicalInfo(),
				observedPQGroupID: Self.pqSessionGroupID,
				observedPQEpoch: Self.observedPQEpoch)
		}
	}

	@available(iOS 26, macOS 26, *)
	@Test func rejectsBoundTEpoch() {
		assertMismatch(pqInfo: makePQInfo(tEpoch: 1), classicalInfo: makeClassicalInfo())
	}

	@available(iOS 26, macOS 26, *)
	@Test func rejectsWrongPqEpoch() {
		assertMismatch(pqInfo: makePQInfo(pqEpoch: 2), classicalInfo: makeClassicalInfo())
	}

	@available(iOS 26, macOS 26, *)
	@Test func rejectsPqSessionGroupIDNotMatchingObserved() {
		assertMismatch(
			pqInfo: makePQInfo(pqSessionGroupID: Data([9, 9, 9])),
			classicalInfo: makeClassicalInfo())
	}

	@available(iOS 26, macOS 26, *)
	@Test func rejectsMismatchedIdentityFieldTSessionGroupID() {
		assertMismatch(
			pqInfo: makePQInfo(),
			classicalInfo: makeClassicalInfo(tSessionGroupID: Data([9, 9, 9])))
	}

	@available(iOS 26, macOS 26, *)
	@Test func rejectsMismatchedIdentityFieldMode() {
		assertMismatch(pqInfo: makePQInfo(), classicalInfo: makeClassicalInfo(mode: 1))
	}

	@available(iOS 26, macOS 26, *)
	@Test func rejectsWrongTCipherSuite() {
		assertMismatch(
			pqInfo: makePQInfo(tCipherSuite: MLS.CipherSuite(id: 0xFFFF)),
			classicalInfo: makeClassicalInfo())
	}

	@available(iOS 26, macOS 26, *)
	@Test func rejectsWrongPqCipherSuite() {
		assertMismatch(
			pqInfo: makePQInfo(pqCipherSuite: MLS.CipherSuite(id: 0xFFFF)),
			classicalInfo: makeClassicalInfo(pqCipherSuite: MLS.CipherSuite(id: 0xFFFF))
		)
	}
}
