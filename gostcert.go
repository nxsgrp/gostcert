package gostcert

import (
	"crypto/x509"
	"encoding/asn1"

	"github.com/nxsgrp/gostcert/algorithm"
)

// Certificate is a GOST-aware X.509 certificate.
//
// It mirrors every field from x509gost.Certificate, keeping the underlying
// implementation (currently tarantool/go-gostcrypto) as an internal detail.
type Certificate struct {
	// Stdlib is always present. For GOST-signed certs SignatureAlgorithm
	// will be UnknownSignatureAlgorithm because the stdlib cannot verify
	// GOST signatures.
	Stdlib *x509.Certificate

	// Raw is the original DER encoding.
	Raw []byte

	// IsGOST is true when the signature algorithm is a GOST OID.
	IsGOST bool

	// HasGOSTPublicKey is true when SubjectPublicKeyInfo carries a GOST public
	// key OID — independent of signature algorithm.
	HasGOSTPublicKey bool

	// GOSTAlgorithm identifies the subject key algorithm.
	GOSTAlgorithm algorithm.GOSTAlgorithm

	// SigGOSTAlgorithm identifies the signature algorithm used to sign THIS
	// certificate's TBSCertificate.
	SigGOSTAlgorithm algorithm.GOSTAlgorithm

	// PublicKeyRaw contains the raw GOST public key bytes, LE(X)||LE(Y).
	PublicKeyRaw []byte

	// CurveOID is the curve parameter OID from SPKI AlgorithmIdentifier.Parameters.
	CurveOID asn1.ObjectIdentifier

	// SPKIAlgorithmDER is the full DER of the SPKI AlgorithmIdentifier SEQUENCE.
	SPKIAlgorithmDER []byte
}
