package internal

import (
	"encoding/asn1"
	"fmt"

	"github.com/tarantool/go-gostcrypto"
	"github.com/tarantool/go-gostcrypto/x509gost"
)

// OIDPublicKeyByGostAlgorithm returns the SubjectPublicKeyInfo algorithm OID for
// a given GOST algorithm (e.g. OIDPublicKeyGOSTR341012_256).
//
// These OIDs identify the public key algorithm in the
// SubjectPublicKeyInfo.AlgorithmIdentifier.Algorithm field.
func OIDPublicKeyByGostAlgorithm(algo x509gost.GOSTAlgorithm) (asn1.ObjectIdentifier, error) {
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

// OIDSignatureAlgorithmByGostAlgorithm returns the signature algorithm OID for a
// given GOSTAlgorithm (e.g. OIDSignatureGOSTR341012_256).
//
// These OIDs identify the signature algorithm in both the
// TBSCertificate.signature and the outer
// SignedCertificate.signatureAlgorithm fields.
func OIDSignatureAlgorithmByGostAlgorithm(algo x509gost.GOSTAlgorithm) (asn1.ObjectIdentifier, error) {
	switch algo {
	case x509gost.AlgoR341001:
		return x509gost.OIDSignatureGOSTR341001, nil
	case x509gost.AlgoR341012_256:
		return x509gost.OIDSignatureGOSTR341012_256, nil
	case x509gost.AlgoR341012_512:
		return x509gost.OIDSignatureGOSTR341012_512, nil
	default:
		return nil, fmt.Errorf("unknown GOST signature algorithm %d", int(algo))
	}
}

// GostDigestAlgorithmToOID returns the hash algorithm OID actually used for the
// cryptographic digest of a GOST signature, given the GOST algorithm.
//
// Unlike GostDigestFromCurveOID, which decides what to write into the optional
// digestParamSet field of the SPKI parameters (and may return nil), this
// function always returns a concrete hash: GOST R 34.11-94 for GOST R
// 34.10-2001 keys, Streebog-256 for GOST R 34.10-2012 256-bit keys, and
// Streebog-512 for GOST R 34.10-2012 512-bit keys.
func GostDigestAlgorithmToOID(algo x509gost.GOSTAlgorithm) (asn1.ObjectIdentifier, error) {
	switch algo {
	case x509gost.AlgoR341001:
		return x509gost.OIDHashGOSTR341194, nil
	case x509gost.AlgoR341012_256:
		return x509gost.OIDHashStreebog256, nil
	case x509gost.AlgoR341012_512:
		return x509gost.OIDHashStreebog512, nil
	default:
		return nil, fmt.Errorf("unknown GOST algorithm for digest OID %d", int(algo))
	}
}

func GostAlgorithmToHash(algo x509gost.GOSTAlgorithm) (Hasher, error) {
	switch algo {
	case x509gost.AlgoR341001:
		return gostcrypto.NewGOSTR341194CryptoProHash(), nil
	case x509gost.AlgoR341012_256:
		return gostcrypto.NewStreebog256Hash(), nil
	case x509gost.AlgoR341012_512:
		return gostcrypto.NewStreebog512Hash(), nil
	default:
		return nil, fmt.Errorf("unknown GOST algorithm %d", algo)
	}
}
