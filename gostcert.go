package gostcert

import (
	"crypto/x509"
	"encoding/asn1"
)

// GOSTAlgorithm identifies which GOST signature family is used.
type GOSTAlgorithm int

const (
	AlgoR341001     GOSTAlgorithm = iota + 1 // GOST R 34.10-2001
	AlgoR341012_256                          // GOST R 34.10-2012 / 256-bit
	AlgoR341012_512                          // GOST R 34.10-2012 / 512-bit
)

func (a GOSTAlgorithm) String() string {
	switch a {
	case AlgoR341001:
		return "GOST R 34.10-2001"
	case AlgoR341012_256:
		return "GOST R 34.10-2012/256"
	case AlgoR341012_512:
		return "GOST R 34.10-2012/512"
	default:
		return "GOSTAlgorithm(0)"
	}
}

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

	// HasGOSTPubKey is true when SubjectPublicKeyInfo carries a GOST public
	// key OID — independent of signature algorithm.
	HasGOSTPubKey bool

	// GOSTAlgo identifies the subject key algorithm.
	GOSTAlgo GOSTAlgorithm

	// SigGOSTAlgo identifies the signature algorithm used to sign THIS
	// certificate's TBSCertificate.
	SigGOSTAlgo GOSTAlgorithm

	// PubKeyRaw contains the raw GOST public key bytes, LE(X)||LE(Y).
	PubKeyRaw []byte

	// CurveOID is the curve parameter OID from SPKI AlgorithmIdentifier.Parameters.
	CurveOID asn1.ObjectIdentifier

	// SPKIAlgorithmDER is the full DER of the SPKI AlgorithmIdentifier SEQUENCE.
	SPKIAlgorithmDER []byte
}
