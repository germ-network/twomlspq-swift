import Foundation
import MLSProfileRFC9420
import Testing

@testable import TwoMLSPQSession

/// RFC 9420 §7.3: a sender checks every KeyPackage it adds against the
/// host-supplied current time, and only creation commits add one.
@Suite struct KeyPackageLifetimeTests {
	/// A peer KeyPackage whose `notAfter` is before `now` cannot found a session.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func initiateRejectsPeerKeyPackagePastNotAfter() throws {}

	/// A peer KeyPackage whose `notBefore` is after `now` cannot found a session.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func initiateRejectsPeerKeyPackageBeforeNotBefore() throws {}

	/// The lifetime bounds are inclusive at whole-second resolution: `now` at
	/// `notAfter` plus a fraction of a second still founds a session.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func initiateAcceptsPeerKeyPackageWithinNotAfterSecond() throws
	{}

	/// An expired return KeyPackage is rejected before the invitation is
	/// claimed, so the same invitation still accepts a valid one afterwards.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending"))
	func invitationReceiveRejectsExpiredKeyPackageAndStaysUnclaimed() throws {}

	/// An expired bootstrap KeyPackage (KP′) founds no PQ half and leaves the
	/// session's state unchanged.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending"))
	func pqBootstrapRespondRejectsExpiredBootstrapKeyPackage() throws {}

	/// `now` maps to whole Unix seconds rounded down; times before 1970 map to
	/// 0, times beyond `UInt64.max` seconds clamp to it, and NaN and ±infinity
	/// clamp the same way instead of trapping.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func lifetimeCheckFromDateFloorsAndClamps() throws {}

	/// A non-creation commit skips the lifetime check only while it adds no
	/// KeyPackage: an inline Add is refused.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func lifetimeCheckWithoutAddsRefusesInlineAdd() throws {}

	/// The same holds for an Add the commit references from the proposal store.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func lifetimeCheckWithoutAddsRefusesAddByReference() throws {}

	/// Commits with no Add skip the check, which is vacuous for them.
	@available(iOS 26, macOS 26, *)
	@Test(.disabled("pending")) func lifetimeCheckWithoutAddsAllowsCommitsWithoutAdds() throws {
	}
}
