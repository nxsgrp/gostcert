package internal

import (
	"encoding/asn1"
	"fmt"

	"github.com/tarantool/go-gostcrypto/x509gost"
)

// GostAlgorithmToOID returns the SubjectPublicKeyInfo algorithm OID for
// a given GOSTAlgorithm (e.g. OIDPublicKeyGOSTR341012_256).
//
// These OIDs identify the public key algorithm in the
// SubjectPublicKeyInfo.AlgorithmIdentifier.Algorithm field.
func GostAlgorithmToOID(algo x509gost.GOSTAlgorithm) (asn1.ObjectIdentifier, error) {
	switch algo {
	case x509gost.AlgoR341001:
		return x509gost.OIDPublicKeyGOSTR341001, nil
	case x509gost.AlgoR341012_256:
		return x509gost.OIDPublicKeyGOSTR341012_256, nil
	case x509gost.AlgoR341012_512:
		return x509gost.OIDPublicKeyGOSTR341012_512, nil
	default:
		return nil, fmt.Errorf("unknown GOST algorithm %d", int(algo))
	}
}

// GostSignatureAlgorithmToOID returns the signature algorithm OID for a
// given GOSTAlgorithm (e.g. OIDSignatureGOSTR341012_256).
//
// These OIDs identify the signature algorithm in both the
// TBSCertificate.signature and the outer SignedCertificate.signatureAlgorithm
// fields.
func GostSignatureAlgorithmToOID(algo x509gost.GOSTAlgorithm) (asn1.ObjectIdentifier, error) {
	switch algo {
	case x509gost.AlgoR341001:
		return x509gost.OIDSignatureGOSTR341001, nil
	case x509gost.AlgoR341012_256:
		return x509gost.OIDSignatureGOSTR341012_256, nil
	case x509gost.AlgoR341012_512:
		return x509gost.OIDSignatureGOSTR341012_512, nil
	default:
		return nil, fmt.Errorf("unknown GOST algorithm %d", int(algo))
	}
}
