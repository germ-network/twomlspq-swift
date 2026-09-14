import Foundation
import MLSCodec
import MLSCombiner
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes

// MARK: - Principal (slice 8b)
//
// The credential-scoped signer (book concepts.md's `TwoMlsPqPrincipal`): one
// signing identity plus the provider config, minting fresh key packages and
// invitations that all share its one signing key. Not a hub for group
// operations — `Session.initiate(principal:)` and `Invitation.receive` do
// the actual establishment work, each layered over the identity-based
// primitives in `TwoMLSSession+Establishment.swift`.

/// A credential-scoped signer: one `clientID` + one Ed25519 signing keypair,
/// plus the provider config every KP/session leaf/invitation it mints needs.
/// Every value `Principal` produces is signed by that same key — book
/// concepts.md: "its job is minting key packages and invitations and
/// holding their private material only until it is captured" (an invitation)
/// "or handed off" (a session leaf); `Principal` itself never retains a
/// minted KP's private material — each mint is fresh, local, and moved
/// straight into its result.
@available(iOS 26, macOS 26, *)
public struct Principal: Sendable {
	let classicalProvider: any MLS.CipherSuiteProvider
	let pqProvider: any MLS.CipherSuiteProvider
	let codepoints: MLS.Combiner.Codepoints
	public let clientID: Data
	let signingKey: MLS.SignatureSecretKey
	let signatureKey: MLS.SignaturePublicKey

	/// Mint a fresh principal identity for `clientID`: a fresh Ed25519
	/// signing keypair, independent of the id (book api-reference.md: "the
	/// MLS signing keys are generated internally and are independent of
	/// it").
	public static func generate(
		clientID: Data,
		classicalProvider: any MLS.CipherSuiteProvider,
		pqProvider: any MLS.CipherSuiteProvider,
		codepoints: MLS.Combiner.Codepoints = .deployed
	) throws -> Principal {
		guard classicalProvider.cipherSuite == TwoMLSSuite.classical,
			pqProvider.cipherSuite == TwoMLSSuite.pq
		else { throw TwoMLSError.cipherSuiteMismatch }
		let (signingKey, signatureKey) = try TwoMLSIdentity.mintSignatureKeypair()
		return Principal(
			classicalProvider: classicalProvider, pqProvider: pqProvider,
			codepoints: codepoints, clientID: clientID, signingKey: signingKey,
			signatureKey: signatureKey)
	}

	/// A fresh `{classical, pq}` key-package pair (fresh leaf/init secrets),
	/// signed by this principal's key. `Principal` retains none of the
	/// private material — the minted identity is local to this call and its
	/// secrets are dropped the moment only `.keyPackage` survives it.
	public func generateCombinerKeyPackage() throws -> CombinerKeyPackage {
		try TwoMLSIdentity.generate(
			clientID: clientID, signingKey: signingKey, signatureKey: signatureKey,
			classicalProvider: classicalProvider, pqProvider: pqProvider
		).keyPackage
	}

	/// Mint a fresh combiner key package, capture ITS private material plus
	/// a copy of this principal's signing identity into a new `Invitation`,
	/// and return it with the invitation's initial (Swift-native v1) archive
	/// for the app to seal and save. `lastResort` picks the key package's
	/// lifetime (book concepts.md): `true` retains it across many accepted
	/// welcomes, `false` makes it single-use.
	///
	/// Purge: this principal never held the minted KP's private material in
	/// the first place — the fresh identity is minted locally and moved
	/// straight into the returned `Invitation`, so there is nothing here to
	/// separately drop.
	public func generateInvitation(lastResort: Bool) throws -> (
		invitation: Invitation, archive: SecretArchive
	) {
		let mintedIdentity = try TwoMLSIdentity.generate(
			clientID: clientID, signingKey: signingKey, signatureKey: signatureKey,
			classicalProvider: classicalProvider, pqProvider: pqProvider)
		let invitation = Invitation(
			classicalProvider: classicalProvider, pqProvider: pqProvider,
			codepoints: codepoints, identity: mintedIdentity, lastResort: lastResort)
		return (invitation, try invitation.makeInvitationArchive())
	}
}
