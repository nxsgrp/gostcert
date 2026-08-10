package internal

import (
	"encoding/asn1"
	"fmt"

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
func BuildSPKI(publicKey []byte, curveOID asn1.ObjectIdentifier, algo x509gost.GOSTAlgorithm) ([]byte, error) {
	alg, err := GostAlgorithmToOID(algo)
	if err != nil {
		return nil, fmt.Errorf("buildSPKI: get public key algorithm: %w", err)
	}

	digestOID, err := GostDigestAlgorithmToOID(algo)
	if err != nil {
		return nil, fmt.Errorf("buildSPKI: get digest algorithm: %w", err)
	}

	// GOST Parameters is a SEQUENCE { curveOID, digestOID } (RFC 4491).
	paramsDER, err := asn1.Marshal(gostSPKIParameters{
		CurveOID:  curveOID,
		DigestOID: digestOID,
	})
	if err != nil {
		return nil, fmt.Errorf("buildSPKI: marshal parameters: %w", err)
	}

	// The public key is wrapped in an OCTET STRING inside the BIT STRING,
	// per GOST SubjectPublicKeyInfo convention (see reference cert).
	rawPublicKey, err := asn1.Marshal(publicKey)
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

// GostDigestAlgorithmToOID returns the hash algorithm OID associated with
// a given GOSTAlgorithm (e.g. OIDHashStreebog256 for AlgoR341012_256).
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
