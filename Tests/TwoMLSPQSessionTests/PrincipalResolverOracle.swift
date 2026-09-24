import Foundation
import MLSCodec
import MLSCrypto
import MLSProfileRFC9420
import XCTest

@testable import TwoMLSPQSession

// MARK: - The differential oracle
//
// `PrincipalResolverOracle` is a VERBATIM, test-only copy of the two
// resolvers this PR deletes from the library
// (`TwoMLSSession.classicalSigningKey(presenting:)`/`pqSigningKey
// (presenting:)`, as they read at `origin/main` 9f6f9a7) — "today"'s
// signing behavior, kept alive here so every existing test can still prove
// "no signing change" against it. `OracleCheck` is the comparison harness:
// installed once (`SessionTestSupport`'s provider initializer) as the
// library's `TwoMLSSessionTestHooks.observer`, it runs after every
// `StateUpdate` in every test, still on that same test's own thread and
// call stack — so a mismatch calls `XCTFail` DIRECTLY and synchronously,
// the same way any other in-test assertion would, rather than trying to
// record a failure retroactively against a test that has already finished
// (that path exists — `XCTestObservation.testCaseDidFinish` — but recording
// through it crashed the process outright: `libc++abi: terminate_handler
// unexpectedly threw an exception`, so it is not used here).
// A test that expects a miss opts in for exactly the groups it needs, via
// `OracleCheck.allow([...])` at its start and `defer { OracleCheck.allow([]) }`
// to reset — thread-local state, not a shared table keyed by test name, so
// this stays correct even when `swift test --parallel` runs different tests
// concurrently in the same process (the state-advancing call that triggers
// `run(_:)` below always executes synchronously on the calling test's own
// thread, since this library makes no async dispatch of its own, so
// `Thread.current` still identifies the right test).

/// Verbatim copy of the pre-existing custody resolvers (`TwoMLSSession.swift`,
/// deleted by this PR). Any edit here must be a deliberate widening of the
/// oracle, never a "fix" to make a test pass — see the type's own doc above.
@available(iOS 26, macOS 26, *)
enum PrincipalResolverOracle {
	static func classicalSigningKey(
		presenting signatureKey: MLS.SignaturePublicKey, in session: TwoMLSSession
	) throws -> MLS.SignatureSecretKey {
		if signatureKey == session.identity.signatureKey {
			return session.identity.signingKey
		}
		if let candidate = session.rotationCandidate, candidate.signatureKey == signatureKey
		{
			return candidate.signingKey
		}
		if let recvLeafPrincipal = session.recvLeafPrincipal,
			recvLeafPrincipal.signatureKey == signatureKey
		{
			return recvLeafPrincipal.signingKey
		}
		throw TwoMLSError.credentialUnknown
	}

	static func pqSigningKey(
		presenting signatureKey: MLS.SignaturePublicKey, in session: TwoMLSSession
	) throws -> MLS.SignatureSecretKey {
		if signatureKey == session.identity.pqSignatureKey {
			return session.identity.pqSigningKey
		}
		if let recvLeafPrincipal = session.recvLeafPrincipal,
			recvLeafPrincipal.pqSignatureKey == signatureKey
		{
			return recvLeafPrincipal.pqSigningKey
		}
		throw TwoMLSError.credentialUnknown
	}
}

/// The comparison harness — a process-wide fixture (multiple `XCTestCase`s
/// run in the same process), guarded by a lock like the library's own
/// `TwoMLSSessionTestHooks`. Unlike a miss ledger drained later, a mismatch
/// here fails IMMEDIATELY, synchronously, on the calling test's own thread.
@available(iOS 26, macOS 26, *)
enum OracleCheck {
	/// The four slots a miss can be scoped to — see `allow(_:)`.
	enum Group: String {
		case sendClassical, recvClassical, sendPQ, recvPQ
	}

	// Tests allowed to carry an oracle miss call `allow(_:)` with exactly
	// the groups each needs, at the start of the test body, and reset with
	// `defer { allow([]) }` — an allowance never blankets a test's whole
	// session, only the slots the reason below actually explains. Reasons:
	// - PQ hand-builds (`handBuildPQLeafMoveUpd`/`pqRekeyApply`): the PQ
	//   resolver has no rotation-candidate arm (PQ leaf moves are not a
	//   rotation), so a store-only key the test itself mints can never
	//   resolve there by construction.
	// - `authorBobCredentialRotation` hand-builds a SAME-id, fresh-key
	//   rotation directly on bob's recv-classical leaf, bypassing
	//   `prepareToEncrypt(rotating:)` (and so `rotationCandidate`) entirely
	//   — the pre-existing resolver could never have signed with this key
	//   either (it has no arm for a same-id key-only rotation outside the
	//   ring), so the fold-acceptance behavior these tests check was never
	//   something the old resolver covered in the first place.
	// - The identity-swap test deliberately replaces `identity` with a
	//   bogus one to prove signing never reads it. Every group's `current`
	//   still traces back to the ORIGINAL identity until each group's own
	//   next mechanism (a classical rotation's `rotationCandidate`, a
	//   mechanical PQ re-key) replaces it, so the oracle — which still
	//   reads `identity` — is EXPECTED to miss on all four groups for the
	//   rest of that test; that
	//   miss is the point, not a bug.

	private static let lock = NSLock()
	private nonisolated(unsafe) static var _ignoreMisses = false
	private nonisolated(unsafe) static var _runCount = 0
	private static let allowedGroupsKey = "OracleCheck.allowedGroups"

	/// Sets the calling THREAD's allowance for the rest of the current test
	/// — thread-local (`Thread.current.threadDictionary`), not a shared
	/// process-wide table, so two tests running concurrently on different
	/// threads (as `swift test --parallel` can do within one process) never
	/// see each other's allowance. Every allowlisted test calls this at its
	/// start with the exact groups it needs, then `defer { allow([]) }` to
	/// clear it before the thread might pick up an unrelated test.
	static func allow(_ groups: Set<Group>) {
		Thread.current.threadDictionary[allowedGroupsKey] = groups
	}

	private static var allowedGroups: Set<Group> {
		(Thread.current.threadDictionary[allowedGroupsKey] as? Set<Group>) ?? []
	}

	/// How many times `run(_:)` has executed in this process — installed as
	/// `TwoMLSSessionTestHooks.observer`, so this tracks 1:1 with
	/// `observerRunCount` from the moment of install, but is its own
	/// counter: it proves the ORACLE itself ran, not merely the funnel it
	/// rides.
	static var runCount: Int {
		lock.lock()
		defer { lock.unlock() }
		return _runCount
	}

	/// Test-only escape hatch for the mutation-testing pass ("make the
	/// oracle ignore misses" is one of the required mutations). Also used by
	/// tests that need to silence the INSTALLED observer's automatic
	/// `XCTFail` around one deliberate corruption while still making their
	/// own, unsuppressed assertion directly against `mismatches(in:)` or the
	/// call's own return value (`LeafKeysTests.swift`,
	/// `testPQKeySetChangeAloneTriggersTheStickyCheckpointUpgrade` and
	/// `testOracleCatchesAMismatchedStoredKeyNothingElseInThisCallWouldNotice`).
	static func withMissesIgnored<T>(_ body: () throws -> T) rethrows -> T {
		lock.lock()
		_ignoreMisses = true
		lock.unlock()
		defer {
			lock.lock()
			_ignoreMisses = false
			lock.unlock()
		}
		return try body()
	}

	private static var ignoreMisses: Bool {
		lock.lock()
		defer { lock.unlock() }
		return _ignoreMisses
	}

	/// Every "no signing change" mismatch `session`'s CURRENT state would
	/// produce, with no side effects — no allowlist, no `XCTFail`, no
	/// counter. `[]` means clean. For each EXISTING group, resolution is
	/// checked against the key the TREE actually presents right now
	/// (`ownLeaf(of:).signatureKey`), exactly what a real signing site
	/// reads — not `current.signatureKey`, which is this session's OWN
	/// stored claim and so would make the comparison partly circular for
	/// that slot. A group that doesn't exist yet has no leaf to ask, so its
	/// `current` is instead checked as a reservation, EXACTLY against
	/// `identity`'s own classical or PQ secret (the only value main's
	/// resolvers could ever have produced for a group with no leaf at all).
	/// A LIVE pending entry — the outstanding `rotationCandidate` plus
	/// (recv-classical only) the rule-4 target `identity.clientID` — is
	/// still checked directly against its own stored secret; a dead
	/// `pending[C_old]` a candidate replacement may leave behind is
	/// deliberately out of scope (no signing site reads it).
	static func mismatches(in session: TwoMLSSession) -> [String] {
		var liveClassicalTargets: Set<Data> = []
		if let candidate = session.rotationCandidate {
			liveClassicalTargets.insert(candidate.clientID)
		}

		var found: [String] = []
		if let send = session.sendGroup {
			// sendClassical.current is always a freshly minted founding
			// leaf now — never `identity`'s own key — so the frozen
			// resolver can never resolve it; only the stored-vs-presented
			// half still applies.
			found += checkExisting(
				session.leafKeys.sendClassical, group: "sendClassical",
				presented: try? TwoMLSSession.ownLeaf(of: send.classical)
					.signatureKey,
				resolve: {
					try PrincipalResolverOracle.classicalSigningKey(
						presenting: $0, in: session)
				}, liveTargets: liveClassicalTargets, skipCurrentResolve: true)
		} else {
			found += checkReservation(
				session.leafKeys.sendClassical, group: "sendClassical",
				identitySignatureKey: session.identity.signatureKey,
				identitySigningKey: session.identity.signingKey)
		}
		// The rule-4 catch-up target is `auth.mine.current` (D, once a
		// dedicated session has one) rather than `session.identity.clientID`
		// (always the invitation identity now) — its fresh key, pending or
		// already promoted into `current`, is never something the frozen
		// resolver (which only ever reads `identity`/`recvLeafPrincipal`)
		// can resolve.
		let mineCurrent = session.auth.mine.current
		let catchUpTarget = mineCurrent.map { Set([$0]) } ?? []
		if let recv = session.recvGroup {
			// Skip the resolve half only for the rule-4 catch-up key once it's
			// promoted into `current`: it differs from BOTH `identity`'s key and
			// `rotationCandidate`'s, so the frozen resolver has no arm for it.
			// A converged rotation's promoted key also differs from `identity`,
			// but the resolver's candidate arm still resolves it (`rotationCandidate`
			// hasn't been cleared yet) — that key must keep its resolve check.
			let recvClassicalSkipCurrent =
				session.leafKeys.recvClassical.current?.signatureKey
				!= session.identity.signatureKey
				&& session.leafKeys.recvClassical.current?.signatureKey
					!= session.rotationCandidate?.signatureKey
			found += checkExisting(
				session.leafKeys.recvClassical, group: "recvClassical",
				presented: try? TwoMLSSession.ownLeaf(of: recv.classical)
					.signatureKey,
				resolve: {
					try PrincipalResolverOracle.classicalSigningKey(
						presenting: $0, in: session)
				},
				liveTargets: liveClassicalTargets.union(catchUpTarget),
				skipCurrentResolve: recvClassicalSkipCurrent,
				noResolveTargets: catchUpTarget)
		} else {
			found += checkReservation(
				session.leafKeys.recvClassical, group: "recvClassical",
				identitySignatureKey: session.identity.signatureKey,
				identitySigningKey: session.identity.signingKey)
		}
		if let sendPQGroup = session.sendGroup?.pq {
			// sendPQ.current is always a freshly minted A.3 founding leaf —
			// same reasoning as sendClassical above.
			found += checkExisting(
				session.leafKeys.sendPQ, group: "sendPQ",
				presented: try? TwoMLSSession.ownLeaf(of: sendPQGroup).signatureKey,
				resolve: {
					try PrincipalResolverOracle.pqSigningKey(
						presenting: $0, in: session)
				}, liveTargets: Set(session.leafKeys.sendPQ.pending.keys),
				skipCurrentResolve: true)
		}
		// No `else` arm: a not-yet-founded send-PQ holds no reservation to
		// check against — nothing is stored ahead of A.3 founding.
		if let recvPQGroup = session.recvGroup?.pq {
			found += checkExisting(
				session.leafKeys.recvPQ, group: "recvPQ",
				presented: try? TwoMLSSession.ownLeaf(of: recvPQGroup).signatureKey,
				resolve: {
					try PrincipalResolverOracle.pqSigningKey(
						presenting: $0, in: session)
				}, liveTargets: Set(session.leafKeys.recvPQ.pending.keys))
		} else {
			found += checkReservation(
				session.leafKeys.recvPQ, group: "recvPQ",
				identitySignatureKey: session.identity.pqSignatureKey,
				identitySigningKey: session.identity.pqSigningKey)
		}
		return found
	}

	/// Pure: `misses` filtered down to whatever `allowed` doesn't cover — no
	/// side effects, no lock, no `XCTFail`. A miss is covered by `allowed`
	/// when it names one of `allowed`'s groups (`"\(group).")` prefix,
	/// matching `mismatches(in:)`'s own `"\(group).slot: reason"` shape).
	/// `run` below is the only thing that turns this into a failure.
	static func unexpectedMisses(in misses: [String], allowed: Set<Group>) -> [String] {
		misses.filter { miss in
			!allowed.contains { miss.hasPrefix("\($0.rawValue).") }
		}
	}

	/// Applies `mismatches(in:)`, then the calling thread's own allowance
	/// (`allow(_:)`) via `unexpectedMisses(in:allowed:)`, then `XCTFail`s on
	/// whatever remains — the side-effecting half `mismatches` deliberately
	/// has none of.
	static func run(
		_ session: TwoMLSSession, file: StaticString = #filePath, line: UInt = #line
	) {
		lock.lock()
		_runCount += 1
		lock.unlock()
		guard !ignoreMisses else { return }
		let misses = mismatches(in: session)
		guard !misses.isEmpty else { return }
		let unexpected = unexpectedMisses(in: misses, allowed: allowedGroups)
		guard !unexpected.isEmpty else { return }
		XCTFail(
			"oracle miss (no signing change): \(unexpected.joined(separator: "; "))",
			file: file, line: line)
	}

	/// `skipCurrentResolve` and `noResolveTargets` narrow the oracle: the
	/// "stored key == presented leaf key" half always runs for `current`
	/// (and, for every live pending entry, membership in `set.pending`
	/// itself is exactly that stored value); only the RESOLVE half — asking
	/// the frozen oracle to independently derive the same key — is skipped
	/// for a slot named here, because a fresh founding/catch-up key is
	/// never something `PrincipalResolverOracle` (which only ever reads
	/// `identity`/`rotationCandidate`/`recvLeafPrincipal`) could resolve.
	private static func checkExisting(
		_ set: GroupKeySet, group: String, presented: MLS.SignaturePublicKey?,
		resolve: (MLS.SignaturePublicKey) throws -> MLS.SignatureSecretKey,
		liveTargets: Set<Data>,
		skipCurrentResolve: Bool = false,
		noResolveTargets: Set<Data> = []
	) -> [String] {
		var found: [String] = []
		if let presented {
			if set.current?.signatureKey != presented {
				found.append(
					"\(group).current: stored key does not match the presented leaf key"
				)
			} else if !skipCurrentResolve,
				let currentSigningKey = set.current?.signingKey
			{
				do {
					let resolved = try resolve(presented)
					if resolved.data != currentSigningKey.data {
						found.append("\(group).current: byte mismatch")
					}
				} catch {
					found.append(
						"\(group).current: oracle did not resolve: \(error)"
					)
				}
			}
		} else {
			found.append("\(group).current: own leaf unreadable")
		}
		for (target, key) in set.pending where liveTargets.contains(target) {
			guard !noResolveTargets.contains(target) else { continue }
			do {
				let resolved = try resolve(key.signatureKey)
				if resolved.data != key.signingKey.data {
					found.append(
						"\(group).pending[\(target.hexPrefix)]: byte mismatch"
					)
				}
			} catch {
				found.append(
					"\(group).pending[\(target.hexPrefix)]: oracle did not resolve: \(error)"
				)
			}
		}
		return found
	}

	private static func checkReservation(
		_ set: GroupKeySet, group: String, identitySignatureKey: MLS.SignaturePublicKey,
		identitySigningKey: MLS.SignatureSecretKey
	) -> [String] {
		guard let current = set.current else {
			return ["\(group).reservation: missing"]
		}
		guard current.signatureKey == identitySignatureKey,
			current.signingKey.data == identitySigningKey.data
		else {
			return ["\(group).reservation: does not match identity"]
		}
		return []
	}
}

extension Data {
	fileprivate var hexPrefix: String {
		prefix(4).map { String(format: "%02x", $0) }.joined()
	}
}

/// Proves the observer actually ran across the suite, not merely that it
/// exists and compiles. `establishedAndExchanged` alone mints several
/// `StateUpdate`s (the baseline, the join, the exchange), so both counts
/// must have grown by at least that many since this test's own start.
@available(iOS 26, macOS 26, *)
final class PrincipalResolverOracleTests: XCTestCase {
	#if DEBUG
		func testObserverRanAcrossAStateAdvancingCall() throws {
			let before = TwoMLSSessionTestHooks.observerRunCount
			_ = try SessionTestSupport.establishedAndExchanged()
			let after = TwoMLSSessionTestHooks.observerRunCount
			XCTAssertGreaterThan(
				after, before,
				"the differential-oracle observer must run on every StateUpdate")
		}

		// `OracleCheck.runCount` only grows because `installOracleObserverOnce`
		// wires `OracleCheck.run` up as `TwoMLSSessionTestHooks.observer` —
		// itself `#if DEBUG`-gated in Sources, so a release build never
		// installs it and this count would stay at zero.
		func testOracleRunCountGrowsAcrossAStateAdvancingCall() throws {
			let before = OracleCheck.runCount
			_ = try SessionTestSupport.establishedAndExchanged()
			let after = OracleCheck.runCount
			XCTAssertGreaterThan(
				after, before,
				"OracleCheck.run must itself run on every StateUpdate")
		}
	#endif

	func testMismatchesIsEmptyOnACleanEstablishedSession() throws {
		let (alice, _) = try SessionTestSupport.establishedAndExchanged()
		XCTAssertEqual(OracleCheck.mismatches(in: alice), [])
	}

	/// sendClassical/sendPQ.current are always fresh founding leaves now
	/// (their RESOLVE half is skipped — the frozen oracle could never
	/// derive a fresh key from `identity` anyway), so a byte-level
	/// signing-key corruption there is no longer something `mismatches`
	/// catches; recvPQ (KP′, still `identity`'s own PQ half) is unaffected
	/// and still proves the resolver's byte-compare arm works.
	func testMismatchesReportsACorruptedRecvPQCurrentKey() throws {
		var (alice, _) = try RatchetTests.fullyEstablishedTurnOnBob()
		let wrongKey = try TwoMLSIdentity.generate(
			clientID: Data("wrong-key".utf8),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider
		).signingKey
		alice.leafKeys.recvPQ.current = LeafKey(
			signingKey: wrongKey,
			signatureKey: try XCTUnwrap(alice.leafKeys.recvPQ.current)
				.signatureKey)
		XCTAssertEqual(
			OracleCheck.mismatches(in: alice), ["recvPQ.current: byte mismatch"])
	}

	/// Once Alice's own rotation has FULLY CONVERGED (both her classical
	/// leaves present the new credential — `RotationTests.
	/// testSecondRotationAfterFullConvergenceIsRotationInFlightAndSessionNotBricked`'s
	/// setup), `recvClassical.current` presents `rotationCandidate`'s key,
	/// not `identity`'s. The oracle's resolve half must still cover that
	/// slot — the frozen resolver's candidate arm can derive it — so a byte
	/// mismatch there is still reported, not silently skipped.
	func testMismatchesReportsACorruptedRecvClassicalCurrentKeyAfterAConvergedRotation()
		throws
	{
		var (alice, bob) = try SessionTestSupport.establishedAndExchanged()
		let aliceNewID = Data("alice-converged-v2".utf8)

		_ = try alice.prepareToEncrypt(rotating: aliceNewID)
		let offerFrame = try alice.encrypt(Data("offer".utf8)).frame
		let decryptedOffer = try bob.processIncomingDecrypted(offerFrame)
		_ = try bob.queueProposal(digest: decryptedOffer.queuedProposal.digest)
		_ = try bob.prepareToEncrypt()
		let foldFrame = try bob.encrypt(Data("fold".utf8)).frame
		_ = try alice.processIncomingDecrypted(foldFrame)

		// Alice's own-leaf catch-up: both her classical leaves now present
		// `aliceNewID` — the rotation has fully converged, and
		// `rotationCandidate` is still live (untouched by convergence).
		_ = try alice.prepareToEncrypt()
		let catchUpFrame = try alice.encrypt(Data("catchup".utf8)).frame
		_ = try bob.processIncomingDecrypted(catchUpFrame)
		XCTAssertEqual(alice.myPrincipalState, .sync(aliceNewID))
		XCTAssertNotNil(alice.rotationCandidate)
		XCTAssertEqual(
			alice.leafKeys.recvClassical.current?.signatureKey,
			alice.rotationCandidate?.signatureKey)

		let wrongKey = try TwoMLSIdentity.generate(
			clientID: Data("wrong-key".utf8),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider
		).signingKey
		alice.leafKeys.recvClassical.current = LeafKey(
			signingKey: wrongKey,
			signatureKey: try XCTUnwrap(alice.leafKeys.recvClassical.current)
				.signatureKey)
		XCTAssertEqual(
			OracleCheck.mismatches(in: alice), ["recvClassical.current: byte mismatch"])
	}

	/// Pins `checkExisting`'s "stored key == presented leaf key" half, which
	/// `skipCurrentResolve` never touches — it still runs for `sendPQ.current`
	/// even though the resolve half is skipped there (a fresh A.3 founding
	/// leaf, never something the frozen resolver could derive). Corrupting
	/// the STORED signature key (not merely the signing key) makes it
	/// disagree with what the tree actually presents, which only that first
	/// half can catch.
	func testMismatchesReportsAStoredSendPQCurrentKeyThatDoesNotMatchThePresentedLeaf()
		throws
	{
		let (_, bob) = try RatchetTests.fullyEstablishedTurnOnBob()
		var mutableBob = bob
		let wrongIdentity = try TwoMLSIdentity.generate(
			clientID: Data("wrong-key".utf8),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
		mutableBob.leafKeys.sendPQ.current = LeafKey(
			signingKey: wrongIdentity.pqSigningKey,
			signatureKey: wrongIdentity.pqSignatureKey)
		XCTAssertEqual(
			OracleCheck.mismatches(in: mutableBob),
			["sendPQ.current: stored key does not match the presented leaf key"])
	}

	// MARK: - `unexpectedMisses(in:allowed:)` — the pure filter `run` fails on

	/// A genuine miss with an EMPTY allowance passes straight through —
	/// nothing filters it, matching what `run` would then `XCTFail` on.
	func testUnexpectedMissesPassesThroughAGenuineMismatchWithNoAllowance() {
		let misses = ["sendClassical.current: byte mismatch"]
		XCTAssertEqual(OracleCheck.unexpectedMisses(in: misses, allowed: []), misses)
	}

	/// Allowance filtering: a miss naming an ALLOWED group is dropped, one
	/// naming an unrelated group survives — the allowlisted test's own scope
	/// (`OracleCheck.allow([.recvPQ])`, say) never blankets misses outside it.
	func testUnexpectedMissesFiltersOnlyMissesTheAllowanceCovers() {
		let misses = [
			"recvPQ.current: oracle did not resolve: credentialUnknown",
			"sendClassical.current: byte mismatch",
		]
		XCTAssertEqual(
			OracleCheck.unexpectedMisses(in: misses, allowed: [.recvPQ]),
			["sendClassical.current: byte mismatch"])
	}
}
