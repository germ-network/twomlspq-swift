import Foundation
import MLSCodec
import MLSCrypto
import MLSProfileRFC9420
import SecretBytes
import TwoMLSPQCrypto

/// §A.4's fresh-entropy seal: a lightweight ML-KEM EK/CT exchange that injects
/// a random `S` into the PQ ratchet, authenticated by a repeatable PSK
/// (`ctSealPSK`) both sides can independently re-derive off the PQ group's
/// current epoch. `S` never comes from the KEM shared secret directly — the
/// KEM secret only keys the AEAD that seals a separately chosen random `S`.
@available(iOS 26, macOS 26, *)
enum CTSeal {
	static let pskLabel = "germ.network.twomlspq.a3.ctSeal.psk.v1"
	static let keyInfo = Data("germ.network.twomlspq.a3.ctSeal.key.v1".utf8)

	/// RFC 9420 §8.5 MLS-Exporter off the PQ group, reconstructed from public
	/// primitives (`exporterSecret` and the two labeled-KDF helpers are public;
	/// swift-mls keeps the exporter itself `package`-scoped, non-forward-secret
	/// and deliberately not exposed). A fixed function of the epoch's
	/// `exporterSecret` and the group id, so both peers — and a re-wrap at the
	/// same epoch — all derive the same value.
	static func ctSealPSK(group: MLS.RFC9420.Group, pqProvider: any MLS.CipherSuiteProvider)
		throws -> SecretBytes
	{
		try ctSealPSK(
			exporterSecret: group.epoch.exporterSecret,
			groupID: group.context.groupID, pqProvider: pqProvider)
	}

	/// The pure derivation behind `ctSealPSK(group:)` — the RFC 9420 §8.5
	/// exporter composition over an `exporterSecret`/`groupID` pair, taking no
	/// `Group` so the exact `pskLabel` / `"exported"` / `Hash(groupID)` / length
	/// composition is pinnable against a fixed vector. A drift in any of those
	/// (a relabel, an unhashed context) would still interoperate Swift↔Swift, so
	/// a cross-party equality test alone cannot catch it — a KAT here can.
	static func ctSealPSK(
		exporterSecret: some ContiguousBytes, groupID: Data,
		pqProvider: any MLS.CipherSuiteProvider
	) throws -> SecretBytes {
		let derived = try MLS.deriveSecretSecret(
			pqProvider, secret: exporterSecret, label: pskLabel)
		return try MLS.expandWithLabelSecret(
			pqProvider, secret: derived, label: "exported",
			context: try pqProvider.hash(groupID), length: 32)
	}

	/// `HKDF-Extract(salt: kemSS, ikm: ctSealPSK)` then a **plain**
	/// `kdfExpand(info: keyInfo)` — no `KDFLabel`/`"MLS 1.0 "` prefix, unlike
	/// every other derivation in this codebase. `aead` is always the classical
	/// provider; its `aeadKeySize` is read dynamically rather than hardcoded.
	static func ctSealKey(
		kemSS: SecretBytes, ctSealPSK: SecretBytes, aead: any MLS.CipherSuiteProvider
	) throws -> Data {
		let prk = try aead.kdfExtractSecret(salt: kemSS, ikm: ctSealPSK)
		return try aead.kdfExpand(prk: prk, info: keyInfo, length: aead.aeadKeySize)
	}

	/// Seal a fresh random 32-byte `S` to `ek`: encapsulate for a fresh KEM
	/// shared secret, derive the seal key from it plus `ctSealPSK`, and AEAD-seal
	/// `S` under an all-zero nonce (single-shot, unique key per seal — no aad).
	/// `wireCT = LE32(enc.count) ‖ enc ‖ sealed`.
	static func seal(ek: Data, ctSealPSK: SecretBytes, aead: any MLS.CipherSuiteProvider) throws
		-> (s: SecretBytes, wireCT: Data)
	{
		let s = SecretBytes(randomByteCount: 32)
		let (kemSS, enc) = try MLKEM768KEM.encapsulate(to: ek)
		let key = try ctSealKey(kemSS: kemSS, ctSealPSK: ctSealPSK, aead: aead)
		let nonce = Data(count: aead.aeadNonceSize)
		let plaintext = s.withUnsafeBytes { Data($0) }
		let sealed = try aead.aeadSeal(
			key: key, nonce: nonce, aad: nil, plaintext: plaintext)
		var wireCT = Data()
		Frames.pushSection(enc, into: &wireCT)
		wireCT.append(sealed)
		return (s, wireCT)
	}

	/// Recover `S` from a peer's `wireCT`. The AEAD open is the explicit reject:
	/// ML-KEM decapsulation never throws on a stale/misdirected `enc` (it always
	/// returns *some* 32 bytes), so a wrong `enc`/`ctSealPSK` only ever surfaces
	/// here, at the AEAD.
	static func open(
		wireCT: Data, secretKey: MLS.HpkeSecretKey, ctSealPSK: SecretBytes,
		aead: any MLS.CipherSuiteProvider
	) throws -> SecretBytes {
		guard wireCT.count >= 4 else { throw TwoMLSError.decryptionFailed }
		var index = wireCT.startIndex
		let b0 = Int(wireCT[index])
		let b1 = Int(wireCT[wireCT.index(index, offsetBy: 1)])
		let b2 = Int(wireCT[wireCT.index(index, offsetBy: 2)])
		let b3 = Int(wireCT[wireCT.index(index, offsetBy: 3)])
		let encLength = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
		index = wireCT.index(index, offsetBy: 4)
		guard wireCT.distance(from: index, to: wireCT.endIndex) >= encLength else {
			throw TwoMLSError.decryptionFailed
		}
		let encEnd = wireCT.index(index, offsetBy: encLength)
		let enc = Data(wireCT[index..<encEnd])
		let sealed = Data(wireCT[encEnd...])

		let kemSS = try MLKEM768KEM.decapsulate(enc, secretKey: secretKey)
		let key = try ctSealKey(kemSS: kemSS, ctSealPSK: ctSealPSK, aead: aead)
		let nonce = Data(count: aead.aeadNonceSize)
		// The AEAD open is the explicit reject (ML-KEM decapsulation never
		// errors on a stale/misdirected `enc`); a failure here is a non-fatal
		// leg reject, surfaced as `.decryptionFailed` rather than a raw `MLS.*`
		// crypto error, so a caller can distinguish it from a fault (§12).
		let opened: Data
		do {
			opened = try aead.aeadOpen(
				key: key, nonce: nonce, aad: nil, ciphertext: sealed)
		} catch {
			throw TwoMLSError.decryptionFailed
		}
		return try SecretBytes(bytes: opened)
	}
}
