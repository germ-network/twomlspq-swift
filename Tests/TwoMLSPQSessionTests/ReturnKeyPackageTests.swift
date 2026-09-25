import Foundation
import MLSProfileRFC9420
import Testing

@testable import TwoMLSPQSession

@Suite struct ReturnKeyPackageTests {
	/// The establishment result's classical KeyPackage: equals the returned
	/// session's internal identity source, and satisfies the cross-side
	/// contract it exists for — acceptable as the peer's
	/// `theirClassicalKeyPackage` in `receive`.
	@available(iOS 26, macOS 26, *)
	@Test func establishResultCarriesTheSessionClassicalKeyPackage() throws {
		let alice = try SessionTestSupport.identity("alice")
		let bob = try SessionTestSupport.identity("bob")
		let initiated = try TwoMLSSession.initiate(
			identity: alice, their: bob.keyPackage,
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)

		#expect(
			initiated.returnKeyPackage
				== initiated.session.identity.keyPackage.classical)

		_ = try TwoMLSSession.receive(
			identity: bob, welcome: initiated.welcome,
			theirClassicalKeyPackage: initiated.returnKeyPackage,
			bootstrapKPCommitment: try initiated.session.bootstrapKPCommitment(),
			classicalProvider: SessionTestSupport.classicalProvider,
			pqProvider: SessionTestSupport.pqProvider)
	}
}
