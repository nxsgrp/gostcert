package internal

import (
	"encoding/asn1"
	"fmt"

	"github.com/tarantool/go-gostcrypto/x509gost"
)

// algorithmIdentifier is an ASN.1 SEQUENCE for AlgorithmIdentifier
// (RFC 5280, section 4.1.1.2). The Parameters field is optional and
// used to carry the curve OID in GOST SubjectPublicKeyInfo.
type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// subjectPublicKeyInfo is an ASN.1 SEQUENCE matching the
// SubjectPublicKeyInfo structure (RFC 5280, section 4.1.2.7).
type subjectPublicKeyInfo struct {
	Algorithm algorithmIdentifier
	PublicKey asn1.BitString
}

// BuildSPKI builds a DER-encoded SubjectPublicKeyInfo for a GOST public key.
//
// publicKey must be the raw GOST public key in LE(X) || LE(Y) format.
// curveOID is the ASN.1 OID of the elliptic curve parameter set. algo is
// the GOSTAlgorithm identifying the key type (e.g. AlgoR341012_256).
func BuildSPKI(publicKey []byte, curveOID asn1.ObjectIdentifier, algo x509gost.GOSTAlgorithm) ([]byte, error) {
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

// BuildSignatureAlgorithm builds a DER-encoded AlgorithmIdentifier for the
// GOST signature algorithm.
//
// Unlike BuildSPKI, the signature AlgorithmIdentifier carries no Parameters
// field — only the OID is encoded.
func BuildSignatureAlgorithm(sigAlgorithm x509gost.GOSTAlgorithm) ([]byte, error) {
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
