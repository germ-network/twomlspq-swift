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
	// Named fault points, for fault-injection tests: a call site that
	// supports injection asks `TwoMLSSessionTestHooks.shouldFault(name:)`
	// and throws its own error when it answers `true` (armed, fires once).
	// Several library call sites already do — one just before and one just
	// after each write-back that moves a stored signing key, so a test can
	// prove atomicity from both directions.
	//
	// This whole type compiles out of a release build, so a release build
	// also compiles out every fault-point test that touches it — each such
	// test in the test target must itself be `#if DEBUG`-gated, or
	// `swift test -c release` fails to build.
	//
	// `nonisolated(unsafe)` + a plain lock, not an `actor`: these are
	// process-wide test fixtures touched from many parallel `XCTestCase`
	// instances, and a synchronous, non-`async` API is what every call site
	// (itself synchronous) needs.
	@available(iOS 26, macOS 26, *)
	enum TwoMLSSessionTestHooks {
		private static let lock = NSLock()
		private nonisolated(unsafe) static var _armedFaults: Set<String> = []

		private static func withLock<T>(_ body: () -> T) -> T {
			lock.lock()
			defer { lock.unlock() }
			return body()
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
