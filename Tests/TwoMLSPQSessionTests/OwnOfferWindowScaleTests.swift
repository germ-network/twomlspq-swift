import Foundation
import MLSCodec
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes
import TwoMLSPQCrypto
import XCTest

@testable import TwoMLSPQSession

/// Scale at N = 102,400 offers. A manual/pre-merge gate, NEVER CI —
/// env-gated (`TWOMLSPQ_SCALE_TEST=1`) and run in DEBUG. Run with:
///
///   TWOMLSPQ_SCALE_TEST=1 swift test --filter OwnOfferWindowScaleTests
///
/// `TWOMLSPQ_SCALE_TEST_N` optionally overrides the offer count (default
/// `MigratedOwnOfferWindow.maximumOfferCount`, 102,400) — every offer needs
/// a genuinely group-verifying leaf signature, so a full run's GENERATION
/// phase is slow; that phase is excluded from every budget below, but a
/// smaller N is useful for a quick local sanity check before the one full
/// run this gate actually requires.
///
/// PRODUCTION-SHAPED: every offer is built via `SessionTestSupport.
/// knownSecretOwnOffer` — a self-signed `LeafNode` whose fresh HPKE pair the
/// test KNOWS and supplies as the offer's own `leafSecret`, and which is
/// NEVER written back into `bob.recvGroup` (so the group's `pendingUpdate`
/// never grows with N). `parts` is built from that untouched group BEFORE
/// the timed mint region.
///
/// ROOT CAUSE of an earlier version of this harness's quadratic mint
/// (measured 2026-09-23, DEBUG, this machine): that harness called
/// `proposeUpdate` N times on one LIVE group and wrote it back
/// (`bob.recvGroup = mirror`), so the group's own snapshot carried N
/// `pendingUpdate` entries — swift-mls's `insertMigratedOwnUpdate` prefers
/// a group-held pair over the caller-supplied `leafSecret`, so every one of
/// that harness's (fake) supplied secrets was masked and never actually
/// exercised. Restoring that N-entry snapshot is where the time went:
/// `IntegerKeyedMap.init(from:)` (swift-mls `SnapshotCoding.swift`) is
/// `allKeys × decode(forKey:)`, and each `decode(forKey:)` is itself a
/// LINEAR scan over swift-secret-bytes's `ArchiveKeyedDecodingContainer.
/// node(for:)` (`ArchiveDecoder.swift`) — an O(N) decode called N times,
/// i.e. O(N²) overall. That quadratic lives in swift-secret-bytes; this
/// harness works around it by never producing the bloated snapshot in the
/// first place, which is also what production's own restored-from-a-real-
/// snapshot path does (nothing in production ever holds N pending
/// `Update`s on one live group either).
///
/// MEASURED at N=102,400 (2026-09-23, DEBUG, this machine, on the
/// production-shaped harness): mint 2.58 s (generation 50.6 s, excluded;
/// blob ≈ 22.4 MB) — back to roughly linear. `mintBudgetSeconds` below is
/// set to just over 2x that observed number — a DEBUG regression gate, not
/// a release-equivalent claim.
@available(iOS 26, macOS 26, *)
final class OwnOfferWindowScaleTests: XCTestCase {
	func testMintLoadAndApplyAtScale() throws {
		guard ProcessInfo.processInfo.environment["TWOMLSPQ_SCALE_TEST"] == "1" else {
			throw XCTSkip("set TWOMLSPQ_SCALE_TEST=1 to run the scale gate")
		}
		let n =
			ProcessInfo.processInfo.environment["TWOMLSPQ_SCALE_TEST_N"].flatMap(
				Int.init)
			?? MigratedOwnOfferWindow.maximumOfferCount
		try Self.runProductionShapedMint(n: n, mintBudgetSeconds: 6.0, printTimings: true)
	}

	/// The same production-shaped path at a small, non-gated N — always
	/// runs in CI, so the caller-supplied-`leafSecret` branch stays
	/// exercised even when the full scale gate doesn't run. No timing
	/// budget: N=200 is too small and noisy for a stable regression
	/// signal — only the gated full-N run above asserts one.
	func testMintSuppliedSecretPathAtProductionShapedSmallScale() throws {
		try Self.runProductionShapedMint(
			n: 200, mintBudgetSeconds: nil, printTimings: false)
	}

	@discardableResult
	private static func runProductionShapedMint(
		n: Int, mintBudgetSeconds: Double?, printTimings: Bool
	) throws -> MintedOwnOfferWindow {
		let (_, bob) = try SessionTestSupport.establishedAndExchanged()

		// Generation excluded from every budget below. Each offer is
		// self-signed and independently verifiable, but NEVER written back
		// into `bob.recvGroup` — production-shaped (no pendingUpdate growth).
		let generationStart = Date()
		var offers: [MigratedOwnOffer] = []
		offers.reserveCapacity(n)
		var epoch: UInt64 = 0
		var groupID = Data()
		var senderLeafIndex: UInt32 = 0
		for _ in 0..<n {
			let built = try SessionTestSupport.knownSecretOwnOffer(in: bob)
			offers.append(
				MigratedOwnOffer(
					ref: built.ref, proposal: built.bareProposal,
					leafSecret: built.leafSecret))
			epoch = built.epoch
			groupID = built.groupID
			senderLeafIndex = built.senderLeafIndex
		}
		let generationSeconds = Date().timeIntervalSince(generationStart)

		let window = MigratedOwnOfferWindow(
			epoch: epoch, groupID: groupID, senderLeafIndex: senderLeafIndex,
			offers: offers)
		// `parts` is built from bob's UNTOUCHED recv group, before the
		// timed region — exactly what a migrator would read off a
		// genuinely-restored session, never a group that just lived
		// through N own-Update proposals.
		let parts = try migratedParts(bob)

		// "Each mint call <= budget."
		let mintStart = Date()
		let minted = try SessionMigration.mintOwnOfferWindow(
			window, parts: parts,
			classicalProvider: SessionTestSupport.classicalProvider)
		let mintSeconds = Date().timeIntervalSince(mintStart)

		// "Blob size <= 40 MB" — the columnar payload's own byte count
		// (refs + length-prefixes + proposals + secrets); the sealed
		// `SecretArchive`'s own CBOR framing adds a small, roughly
		// constant overhead on top, not measured here.
		let approximateBlobSize =
			offers.reduce(0) { $0 + $1.proposal.count } + offers.count * (32 + 4 + 32)

		if printTimings {
			let budgetDescription =
				mintBudgetSeconds.map { "<= \($0) s, calibrated 2026-09-23" }
				?? "none"
			print(
				"""
				[scale] N=\(n)
				  generation: \(generationSeconds) s (excluded from budget)
				  mint: \(mintSeconds) s (budget: \(budgetDescription))
				  blob (approx, columnar payload only): \(approximateBlobSize) bytes (budget: <= 40 MB)
				""")
		}

		if let mintBudgetSeconds {
			XCTAssertLessThanOrEqual(
				mintSeconds, mintBudgetSeconds, "mint call exceeded its budget")
		}
		XCTAssertLessThanOrEqual(
			approximateBlobSize, 40 * 1024 * 1024, "blob size exceeded its budget")
		return minted
	}

	private static func migratedParts(_ session: TwoMLSSession) throws -> MigratedSession {
		let send = try XCTUnwrap(session.sendGroup)
		return try MigratedSession(
			stateSeq: session.stateSeq, initiated: session.initiated,
			identity: MigratedSessionIdentity(
				clientID: session.identity.clientID,
				signingKey: session.identity.signingKey.data,
				signatureKey: session.identity.signatureKey.data,
				pqSigningKey: session.identity.pqSigningKey.data,
				pqSignatureKey: session.identity.pqSignatureKey.data,
				classicalLeafSecretKey: session.identity.classicalLeafSecretKey
					.data,
				classicalInitSecretKey: session.identity.classicalInitSecretKey?
					.data,
				pqLeafSecretKey: session.identity.pqLeafSecretKey.data,
				pqInitSecretKey: session.identity.pqInitSecretKey?.data,
				classicalKeyPackage: try session.identity.keyPackage.classical
					.mlsEncoded(),
				pqKeyPackage: try session.identity.keyPackage.pq.mlsEncoded()),
			auth: MigratedAuth(
				mine: MigratedPartySequence(
					history: session.auth.mine.history,
					authorizedNext: session.auth.mine.authorizedNext,
					pinned: session.auth.mine.pinned),
				theirs: MigratedPartySequence(
					history: session.auth.theirs.history,
					authorizedNext: session.auth.theirs.authorizedNext,
					pinned: session.auth.theirs.pinned)),
			sendGroup: MigratedGroupHalf(
				classical: try send.classical.archive(), pq: try send.pq?.archive()),
			recvGroup: try session.recvGroup.map {
				MigratedGroupHalf(
					classical: try $0.classical.archive(),
					pq: try $0.pq?.archive())
			},
			currentStaple: session.currentStaple)
	}
}
