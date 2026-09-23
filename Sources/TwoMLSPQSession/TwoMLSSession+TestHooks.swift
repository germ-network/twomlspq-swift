#if DEBUG
	import Foundation

	/// Thrown by a named fault point once armed (`TwoMLSSessionTestHooks.
	/// armFault`) — never a case on the public `TwoMLSError`, since this
	/// exists only to let a test simulate an otherwise-unreachable failure
	/// at a specific line.
	struct InjectedTestFault: Error, Sendable {
		let name: String
	}

	// MARK: - Test-only hooks — compiled out of release builds
	//
	// Two independent facilities, both no-ops until a test installs a
	// handler:
	//  - A state-update observer, invoked at the end of every `stateUpdate
	//    (kind:)` call — the funnel every `StateUpdate`-returning method
	//    passes through. The differential oracle (`PrincipalResolverOracle`,
	//    test target) is the one thing wired here today.
	//  - Named fault points, for fault-injection tests: a call site that
	//    supports injection asks `TwoMLSSessionTestHooks.shouldFault
	//    (name:)` and throws its own error when it answers `true` (armed,
	//    fires once). Several library call sites already do — one just
	//    before and one just after each write-back that moves a stored
	//    signing key, so a test can prove atomicity from both directions.
	//
	// This whole type compiles out of a release build, so a release build
	// also compiles out the differential oracle and every fault-point test
	// that touches it — each such test in the test target must itself be
	// `#if DEBUG`-gated, or `swift test -c release` fails to build.
	//
	// `nonisolated(unsafe)` + a plain lock, not an `actor`: these are
	// process-wide test fixtures touched from many parallel `XCTestCase`
	// instances, and a synchronous, non-`async` API is what every call site
	// (itself synchronous) needs.
	@available(iOS 26, macOS 26, *)
	enum TwoMLSSessionTestHooks {
		private static let lock = NSLock()
		private nonisolated(unsafe) static var _observer:
			(@Sendable (TwoMLSSession) -> Void)?
		private nonisolated(unsafe) static var _observerRunCount: Int = 0
		private nonisolated(unsafe) static var _armedFaults: Set<String> = []

		private static func withLock<T>(_ body: () -> T) -> T {
			lock.lock()
			defer { lock.unlock() }
			return body()
		}

		/// The installed state-update observer, if any. `nil` means "not
		/// installed" — every call to `notifyStateUpdate` still counts
		/// toward `observerRunCount` regardless, so the counter test proves
		/// the funnel itself runs even before a suite installs a handler.
		static var observer: (@Sendable (TwoMLSSession) -> Void)? {
			get { withLock { _observer } }
			set { withLock { _observer = newValue } }
		}

		/// How many times `notifyStateUpdate` has run in this process — the
		/// counter test's own proof that the funnel actually fires.
		static var observerRunCount: Int { withLock { _observerRunCount } }

		/// Called once at the end of every `stateUpdate(kind:)` — see
		/// `TwoMLSSession+StateUpdate.swift`.
		static func notifyStateUpdate(_ session: TwoMLSSession) {
			withLock { _observerRunCount += 1 }
			observer?(session)
		}

		/// Arm `name` to fault exactly once: the next `shouldFault(name:)`
		/// call for the same name answers `true` and disarms it.
		static func armFault(_ name: String) {
			withLock { _ = _armedFaults.insert(name) }
		}

		static func disarmAllFaults() {
			withLock { _armedFaults.removeAll() }
		}

		static func shouldFault(_ name: String) -> Bool {
			withLock {
				guard _armedFaults.contains(name) else { return false }
				_armedFaults.remove(name)
				return true
			}
		}
	}
#endif
