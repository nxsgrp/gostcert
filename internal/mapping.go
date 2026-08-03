package internal

import (
	"encoding/asn1"
	"fmt"

	"github.com/nxsgrp/gostcert/internal/algorithm"
	"github.com/tarantool/go-gostcrypto/x509gost"
)

// MapAlgorithm converts x509gost.GOSTAlgorithm to gostcert.GOSTAlgorithm.
func MapAlgorithm(alg x509gost.GOSTAlgorithm) algorithm.GOSTAlgorithm {
	switch alg {
	case x509gost.AlgoR341001:
		return algorithm.AlgoR341001
	case x509gost.AlgoR341012_256:
		return algorithm.AlgoR341012_256
	case x509gost.AlgoR341012_512:
		return algorithm.AlgoR341012_512
	default:
		return 0
	}
}

// GostAlgorithmToOID returns the SubjectPublicKeyInfo algorithm OID for algo.
func GostAlgorithmToOID(algo algorithm.GOSTAlgorithm) (asn1.ObjectIdentifier, error) {
	switch algo {
	case algorithm.AlgoR341001:
		return x509gost.OIDPublicKeyGOSTR341001, nil
	case algorithm.AlgoR341012_256:
		return x509gost.OIDPublicKeyGOSTR341012_256, nil
	case algorithm.AlgoR341012_512:
		return x509gost.OIDPublicKeyGOSTR341012_512, nil
	default:
		return nil, fmt.Errorf("unknown GOST algorithm %d", int(algo))
	}
}

// GostSignatureAlgorithmToOID returns the signature algorithm OID for algo.
func GostSignatureAlgorithmToOID(algo algorithm.GOSTAlgorithm) (asn1.ObjectIdentifier, error) {
	switch algo {
	case algorithm.AlgoR341001:
		return x509gost.OIDSignatureGOSTR341001, nil
	case algorithm.AlgoR341012_256:
		return x509gost.OIDSignatureGOSTR341012_256, nil
	case algorithm.AlgoR341012_512:
		return x509gost.OIDSignatureGOSTR341012_512, nil
	default:
		return nil, fmt.Errorf("unknown GOST algorithm %d", int(algo))
	}
}
