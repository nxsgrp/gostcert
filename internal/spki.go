package internal

import (
	"encoding/asn1"
	"fmt"

	"github.com/nxsgrp/gostcert/internal/models"
	"github.com/tarantool/go-gostcrypto/x509gost"
)

// algorithmIdentifier is an ASN.1 SEQUENCE for AlgorithmIdentifier
// (RFC 5280, section 4.1.1.2). The Parameters field is optional and
// carries GOST-specific parameter set OIDs.
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

// gostSPKIParameters is the ASN.1 SEQUENCE carried in the
// AlgorithmIdentifier.Parameters of a GOST SubjectPublicKeyInfo
// (RFC 4491 / GOST R 34.10).
//
// It contains the elliptic curve parameter set OID and optionally
// the digest algorithm OID.
type gostSPKIParameters struct {
	CurveOID  asn1.ObjectIdentifier
	DigestOID asn1.ObjectIdentifier `asn1:"optional"`
}

// BuildSPKI builds a DER-encoded SubjectPublicKeyInfo for a GOST public key.
//
// publicKey must be the raw GOST public key in LE(X) || LE(Y) format.
// curveOID is the ASN.1 OID of the elliptic curve parameter set. algo is
// the GOSTAlgorithm identifying the key type (e.g. AlgoR341012_256).
func BuildSPKI(subjectPublicKey models.SubjectPublicKey) ([]byte, error) {
	alg, err := GostAlgorithmToOID(subjectPublicKey.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("buildSPKI: get public key algorithm: %w", err)
	}

	digestOID, err := GostDigestFromCurveOID(subjectPublicKey.CurveOID)
	if err != nil {
		return nil, fmt.Errorf("buildSPKI: get digest algorithm: %w", err)
	}

	// GOST Parameters is a SEQUENCE { curveOID, digestOID } (RFC 4491).
	paramsDER, err := asn1.Marshal(gostSPKIParameters{
		CurveOID:  subjectPublicKey.CurveOID,
		DigestOID: digestOID,
	})
	if err != nil {
		return nil, fmt.Errorf("buildSPKI: marshal parameters: %w", err)
	}

	// The public key is wrapped in an OCTET STRING inside the BIT STRING,
	// per GOST SubjectPublicKeyInfo convention (see reference cert).
	rawPublicKey, err := asn1.Marshal(subjectPublicKey.RawPublicKey)
	if err != nil {
		return nil, fmt.Errorf("buildSPKI: marshal public key: %w", err)
	}

	spki, err := asn1.Marshal(subjectPublicKeyInfo{
		Algorithm: algorithmIdentifier{
			Algorithm:  alg,
			Parameters: asn1.RawValue{FullBytes: paramsDER},
		},
		PublicKey: asn1.BitString{
			Bytes:     rawPublicKey,
			BitLength: len(rawPublicKey) * 8,
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
		return nil, fmt.Errorf("buildSignatureAlgorithm: get signature algorithm: %w", err)
	}

	data, err := asn1.Marshal(derEncodedAlgorithmIdentifier{AlgorithmIdentifier: sigOID})
	if err != nil {
		return nil, fmt.Errorf("buildSignatureAlgorithm: marshal identifier: %w", err)
	}

	return data, nil
}

// GostAlgorithmToOID returns the SubjectPublicKeyInfo algorithm OID for
// a given GOST algorithm (e.g. OIDPublicKeyGOSTR341012_256).
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
// TBSCertificate.signature and the outer
// SignedCertificate.signatureAlgorithm fields.
func GostSignatureAlgorithmToOID(algo x509gost.GOSTAlgorithm) (asn1.ObjectIdentifier, error) {
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

// GostDigestFromCurveOID returns the digestParamSet OID to encode in the GOST
// SubjectPublicKeyInfo parameters for a given public key parameter set, per
// R 1323565.1.023-2018 §4.2 (RFC 9215 §4.2).
//
// It returns a nil ObjectIdentifier when the digestParamSet field is to be
// omitted from the parameters (the ASN.1 OPTIONAL field is then absent).
//
// For the GOST R 34.10-2001 public key parameter sets (id-GostR3410-2001
// Test / CryptoPro-A/B/C / XchA / XchB), §4.2 requires digestParamSet to be
// present and equal to id-tc26-digest-gost3411-12-256 (Streebog-256). For
// every other parameter set — the TC26 512-bit keys and 256-paramSetA/B/C/D —
// the field is omitted (SHOULD/MUST per §4.2), so nil is returned.
//
// algo is the GOST algorithm identifying the key/signature bit length and is
// retained for signature stability; it does not affect the result.
func GostDigestFromCurveOID(oid asn1.ObjectIdentifier) (asn1.ObjectIdentifier, error) {
	if isCryptoPro2001(oid) {
		return x509gost.OIDHashStreebog256, nil
	}
	return nil, nil
}

// isCryptoPro2001 reports whether oid is one of the GOST R 34.10-2001 public
// key parameter sets listed in §4.2 as requiring a digestParamSet.
func isCryptoPro2001(oid asn1.ObjectIdentifier) bool {
	for _, c := range cryptoPro2001ParamSets {
		if oid.Equal(c) {
			return true
		}
	}
	return false
}
