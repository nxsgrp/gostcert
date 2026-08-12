package options

import (
	"crypto"
	"encoding/asn1"
	"io"

	"github.com/tarantool/go-gostcrypto/x509gost"
)

// CryptoOptions is the necessary parameters to build GOST certificate.
type CryptoOptions struct {
	// CurveOID is the ASN.1 OID of the elliptic curve parameter set
	// (e.g. id-GostR3410-2001-CryptoPro-A-ParamSet).
	CurveOID asn1.ObjectIdentifier

	// RandReader is the entropy source used during signing.
	// Typically crypto/rand.Reader.
	RandReader io.Reader

	// Signer is the crypto.Signer that produces the GOST signature.
	// It may wrap a software key or a hardware token (PKCS#11, Rutoken).
	Signer crypto.Signer

	// Algorithm identifies the subject public key algorithm
	// (e.g. AlgoR341012_256 for GOST R 34.10-2012 with a 256-bit key).
	Algorithm x509gost.GOSTAlgorithm

	// SignAlgorithm identifies the signature algorithm used to sign
	// the TBSCertificate (e.g. AlgoR341012_256 for
	// GOST R 34.11-2012 with GOST R 34.10-2012).
	SignAlgorithm x509gost.GOSTAlgorithm
}
