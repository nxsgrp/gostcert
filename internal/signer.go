package internal

import (
	"crypto"
	"encoding/asn1"
	"fmt"
	"io"

	"github.com/tarantool/go-gostcrypto"
)

// Signer implements crypto.Signer for GOST private keys.
//
// It wraps a raw GOST private key (LE-encoded scalar) along with the curve
// OID so that the standard crypto.Signer interface can be used for GOST
// signing operations.
type Signer struct {
	// rawPrivateKey is the raw GOST private key bytes (little-endian scalar).
	rawPrivateKey []byte

	// rawPublicKey is the raw GOST public key bytes.
	rawPublicKey []byte

	// curveOID is the ASN.1 OID identifying the elliptic curve parameter set
	// (e.g. id-GostR3410-2001-CryptoPro-A-ParamSet).
	curveOID asn1.ObjectIdentifier

	// curve is the gostcrypt parsed curve oid.
	curve *gostcrypto.Curve
}

// BuildSigner the base constructor of Signer structure that provides necessary ability
// to wrap CurveOID to gostcrypt Curve object for further PublicKey generation with
// error throwing.
func BuildSigner(curveOID asn1.ObjectIdentifier, rawPrivateKey []byte) (*Signer, error) {
	curveObject, err := gostcrypto.CurveByOID(curveOID)
	if err != nil {
		return nil, fmt.Errorf("error building curve object: %w", err)
	}

	rawPublicKey, err := gostcrypto.PublicKeyRawFromPrivate(curveObject, rawPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("error building raw public key: %w", err)
	}

	signer := &Signer{
		curveOID:      curveOID,
		curve:         curveObject,
		rawPrivateKey: rawPrivateKey,
		rawPublicKey:  rawPublicKey,
	}

	return signer, nil
}

// Public returns the raw GOST public key bytes derived from the private key.
//
// The returned value is LE(X) || LE(Y) — the concatenation of the X and Y
// coordinates in little-endian byte order, matching the GOST representation.
func (s *Signer) Public() crypto.PublicKey {
	return s.rawPublicKey
}

// Sign signs the given digest (already hashed and converted to little-endian
// byte order) using the GOST private key and the elliptic curve identified
// by CurveOID.
//
// The opts parameter is ignored; GOST signatures do not use the standard
// crypto.SignerOpts mechanism.
func (s *Signer) Sign(r io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	signDigest, err := gostcrypto.SignDigestOnCurve(s.curve, s.rawPrivateKey, digest, r)
	if err != nil {
		return nil, fmt.Errorf("error signing digest: %w", err)
	}

	return signDigest, nil
}
