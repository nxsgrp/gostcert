package internal

import (
	"encoding/asn1"
	"fmt"

	"github.com/nxsgrp/gostcert/internal/algorithm"
)

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type subjectPublicKeyInfo struct {
	Algorithm algorithmIdentifier
	PublicKey asn1.BitString
}

// BuildSPKI builds a DER-encoded SubjectPublicKeyInfo for a GOST public key.
// pubKeyRaw is LE(X)||LE(Y). curveOID is the curve parameter OID.
func BuildSPKI(publicKey []byte, curveOID asn1.ObjectIdentifier, algo algorithm.GOSTAlgorithm) ([]byte, error) {
	rawPublicKey, err := asn1.Marshal(publicKey)
	if err != nil {
		return nil, fmt.Errorf("buildSPKI: marshal public key: %w", err)
	}

	rawCurveOID, err := asn1.Marshal(curveOID)
	if err != nil {
		return nil, fmt.Errorf("buildSPKI: marshal curve OID: %w", err)
	}

	alg, err := GostAlgorithmToOID(algo)
	if err != nil {
		return nil, fmt.Errorf("buildSPKI: get public key algorithm: %w", err)
	}

	// Encode curve OID as bare OID (the Parameters field).
	curveDER, err := asn1.Marshal(curveOID)
	if err != nil {
		return nil, fmt.Errorf("buildSPKI: marshal curve OID: %w", err)
	}

	spki, err := asn1.Marshal(subjectPublicKeyInfo{
		Algorithm: algorithmIdentifier{
			Algorithm:  alg,
			Parameters: asn1.RawValue{FullBytes: curveDER},
		},
		PublicKey: asn1.BitString{
			Bytes:     rawPublicKey,
			BitLength: len(rawCurveOID) * 8,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("buildSPKI: marshal SPKI: %w", err)
	}

	return spki, nil
}

// BuildSignatureAlgorithm builds a DER-encoded AlgorithmIdentifier for
// the GOST signature (no Parameters field, unlike SPKI).
func BuildSignatureAlgorithm(sigAlgorithm algorithm.GOSTAlgorithm) ([]byte, error) {
	sigOID, err := GostSignatureAlgorithmToOID(sigAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("buildSPKI: get signature algorithm: %w", err)
	}

	data, err := asn1.Marshal(derEncodedAlgorithmIdentifier{AlgorithmIdentifier: sigOID})
	if err != nil {
		return nil, fmt.Errorf("buildSignatureAlgorithm: marshal identifier: %w", err)
	}

	return data, nil
}
