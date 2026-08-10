package internal

import (
	"crypto"
	"encoding/asn1"
	"io"

	gost "github.com/tarantool/go-gostcrypto"
)

// Signer implements crypto.Signer for GOST private keys.
//
// It wraps a raw GOST private key (LE-encoded scalar) along with the curve
// OID so that the standard crypto.Signer interface can be used for GOST
// signing operations.
type Signer struct {
	// RawPrivateKey is the raw GOST private key bytes (little-endian scalar).
	RawPrivateKey []byte
	// CurveOID is the ASN.1 OID identifying the elliptic curve parameter set
	// (e.g. id-GostR3410-2001-CryptoPro-A-ParamSet).
	CurveOID asn1.ObjectIdentifier
}

// Public returns the raw GOST public key bytes derived from the private key.
//
// The returned value is LE(X) || LE(Y) — the concatenation of the X and Y
// coordinates in little-endian byte order, matching the GOST representation.
func (s *Signer) Public() crypto.PublicKey {
	// TODO: how pass errors and satisfy crypto.PublicKey iface?
	gostCurveOID, _ := gost.CurveByOID(s.CurveOID)
	rawPublicKey, _ := gost.PublicKeyRawFromPrivate(gostCurveOID, s.RawPrivateKey)
	return rawPublicKey
}

// Sign signs the given digest (already hashed and converted to little-endian
// byte order) using the GOST private key and the elliptic curve identified
// by CurveOID.
//
// The opts parameter is ignored; GOST signatures do not use the standard
// crypto.SignerOpts mechanism.
func (s *Signer) Sign(r io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	curve, err := gost.CurveByOID(s.CurveOID)
	if err != nil {
		return nil, err
	}
	return gost.SignDigestOnCurve(curve, s.RawPrivateKey, digest, r)
}
