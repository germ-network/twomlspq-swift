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
	// prove atomicity from both directions. Current call sites: SessionArchive
	// (stateUpdate.beforeEncode), Bootstrap (pqBootstrapRespond.afterWriteBack),
	// ClassicalCommit (committingRound.beforeWriteBack,
	// committingRound.afterWriteBackBeforeRendezvous), Messaging
	// (prepareToEncrypt.afterWriteBackBeforeEncode,
	// encryptPreEstablishment.afterProtectBeforeWriteBack,
	// processMessageFrame.afterStapleBeforeDecrypt), and Rekey
	// (pqRekeyBegin.afterWriteBack, pqRekeyRespond.afterWriteBack,
	// pqRekeyApply.afterWriteBackBeforeBind). Every one of them is plain
	// synchronous engine code called directly from a test's own (also
	// synchronous) call chain — `shouldFault` reading the arming task's
	// task-local therefore assumes there is no `await`, no hop to a detached
	// `Task`, and no dispatch to another queue between `armFault` and the
	// trigger call. If a future call site or test introduces one, the read
	// would silently miss the armed fault (task-locals aren't inherited by
	// unstructured/detached tasks) — this file's design does not need to
	// handle that case unless one arises.
	//
	// This whole type compiles out of a release build, so a release build
	// also compiles out every fault-point test that touches it — each such
	// test in the test target must itself be `#if DEBUG`-gated, or
	// `swift test -c release` fails to build.
	//
	// Armed faults live in a task-local `FaultBox`, not a bare process-wide
	// set: Swift Testing runs tests concurrently by default (unlike XCTest,
	// which never ran two test methods in the same process at once), and a
	// named fault point (e.g. "pqBootstrapRespond.afterWriteBack") is
	// exercised by every test that calls that operation, not just the ones
	// doing fault injection. A bare global set let an unrelated, concurrently
	// -running test's ordinary call consume another test's armed fault
	// before its own trigger reached it — observed as "expected an error but
	// none was thrown" on the arming test. A task-local box is only visible
	// to the task that pushed it (`withIsolatedFaults`) and that task's
	// structured children, so a concurrently-running unrelated test never
	// sees it.
	//
	// There is deliberately no process-wide fallback: `armFault` outside a
	// `withIsolatedFaults` scope traps rather than silently arming some
	// shared default, so a test that forgets the wrapper fails loudly at the
	// call site instead of quietly reintroducing the exact race this exists
	// to prevent. `shouldFault` outside a scope is the ordinary case (nearly
	// every test never arms anything) and just answers `false`.
	@available(iOS 26, macOS 26, *)
	enum TwoMLSSessionTestHooks {
		private final class FaultBox: @unchecked Sendable {
			private let lock = NSLock()
			private var armed: Set<String> = []

			func arm(_ name: String) {
				lock.lock()
				defer { lock.unlock() }
				armed.insert(name)
			}

			/// True iff `name` was armed; consumes it either way (fires once).
			func consume(_ name: String) -> Bool {
				lock.lock()
				defer { lock.unlock() }
				return armed.remove(name) != nil
			}
		}

		/// `nil` until a test calls `withIsolatedFaults`; there is no default
		/// box to fall back to (see the file's doc comment on why).
		@TaskLocal private static var box: FaultBox?

		/// Runs `body` with its own fault-injection scope: faults armed
		/// inside are invisible to any other, concurrently-running test.
		static func withIsolatedFaults<R>(_ body: () throws -> R) rethrows -> R {
			try $box.withValue(FaultBox(), operation: body)
		}

		/// Arm `name` to fault exactly once: the next `shouldFault(name:)`
		/// call for the same name, within the same `withIsolatedFaults`
		/// scope, answers `true` and disarms it.
		///
		/// Traps outside a `withIsolatedFaults` scope — there is no
		/// process-wide fallback to arm instead, since that is exactly the
		/// race this type exists to prevent.
		static func armFault(_ name: String) {
			guard let box else {
				preconditionFailure(
					"TwoMLSSessionTestHooks.armFault(\"\(name)\") called outside "
						+ "withIsolatedFaults — wrap the arming test's body in "
						+ "TwoMLSSessionTestHooks.withIsolatedFaults { ... }"
				)
			}
			box.arm(name)
		}

		/// `false` with no active scope — the ordinary case, since almost
		/// every test never arms anything.
		static func shouldFault(_ name: String) -> Bool {
			box?.consume(name) ?? false
		}
	}
#endif
