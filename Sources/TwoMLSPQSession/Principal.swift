import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes

// MARK: - Principal
//
// The credential-scoped signer (book concepts.md's `TwoMlsPqPrincipal`): a
// `clientID` plus the provider config, minting fresh key packages and
// invitations — each with its own fresh, independent per-half signing keys
// (`TwoMLSIdentity`). Not a hub for group operations —
// `Session.initiate(principal:)` and `Invitation.receive` do the actual
// establishment work, each layered over the identity-based primitives in
// `TwoMLSSession+Establishment.swift`.

/// A credential-scoped signer: one `clientID` plus the provider config every
/// KP/session leaf/invitation it mints needs. Holds no signing key of its
/// own (book api-reference.md: "the MLS signing keys are generated
/// internally and are independent of it") — every `TwoMLSIdentity` it mints
/// gets its own two fresh per-half keys, never a key `Principal` shares
/// across mints.
@available(iOS 26, macOS 26, *)
public struct Principal: Sendable {
	let classicalProvider: any MLS.CipherSuiteProvider
	let pqProvider: any MLS.CipherSuiteProvider
	let codepoints: MLS.Combiner.Codepoints
	public let clientID: Data
	/// Opt-in, default off: every KeyPackage this principal mints advertises
	/// the correct session profile (book group-rules.md rule 9) once this is
	/// `true`. A session's profile is fixed at establishment from both
	/// KeyPackages, so a KeyPackage generated before opting in never
	/// advertises it, even after this is later flipped on. With the default
	/// `false`, behavior and wire bytes are unchanged from a session with no
	/// profile mechanism at all.
	public let advertisesCorrectProfile: Bool

	/// The session profiles every key package this principal mints
	/// advertises.
	var advertising: [SessionProfile] { advertisesCorrectProfile ? SessionProfile.recognized : [] }

	/// Validates the provider config for `clientID` — no key material is
	/// minted here; each `TwoMLSIdentity` this principal later produces
	/// mints its own, fresh. `advertisesCorrectProfile` sets this
	/// principal's opt-in (see the stored property's doc); default off.
	public static func generate(
		clientID: Data,
		classicalProvider: any MLS.CipherSuiteProvider,
		pqProvider: any MLS.CipherSuiteProvider,
		codepoints: MLS.Combiner.Codepoints = .deployed,
		advertisesCorrectProfile: Bool = false
	) throws -> Principal {
		guard classicalProvider.cipherSuite == TwoMLSSuite.classical,
			pqProvider.cipherSuite == TwoMLSSuite.pq
		else { throw TwoMLSError.cipherSuiteMismatch }
		return Principal(
			classicalProvider: classicalProvider, pqProvider: pqProvider,
			codepoints: codepoints, clientID: clientID,
			advertisesCorrectProfile: advertisesCorrectProfile)
	}

	/// Mint a fresh combiner key package under a fresh `TwoMLSIdentity`,
	/// capture its private material into a new `Invitation`, and return it
	/// with the invitation's initial (Swift-native v1) archive for the app
	/// to seal and save. `lastResort` picks the key package's lifetime
	/// (book concepts.md): `true` retains it across many accepted welcomes,
	/// `false` makes it single-use.
	///
	/// Purge: this principal never holds a minted KP's private material in
	/// the first place — the fresh identity is minted locally and moved
	/// straight into the returned `Invitation`, so there is nothing here to
	/// separately drop.
	public func generateInvitation(lastResort: Bool) throws -> (
		invitation: Invitation, archive: SecretArchive
	) {
		let mintedIdentity = try TwoMLSIdentity.generate(
			clientID: clientID, classicalProvider: classicalProvider,
			pqProvider: pqProvider, advertising: advertising)
		let invitation = Invitation(
			classicalProvider: classicalProvider, pqProvider: pqProvider,
			codepoints: codepoints, clientID: clientID, identity: mintedIdentity,
			lastResort: lastResort)
		return (invitation, try invitation.makeInvitationArchive())
	}
}
