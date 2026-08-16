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
	alg, err := OIDPublicKeyByGostAlgorithm(subjectPublicKey.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("buildSPKI: get public key algorithm: %w", err)
	}

	digestOID, err := GostDigestFromCurveOID(subjectPublicKey.CurveOID, subjectPublicKey.Algorithm)
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
// The signature AlgorithmIdentifier carries the algorithm OID and a NULL
// Parameters field (RFC 5280 §4.1.1.2), matching OpenSSL's GOST encoding.
func BuildSignatureAlgorithm(sigAlgorithm x509gost.GOSTAlgorithm) ([]byte, error) {
	sigOID, err := OIDSignatureAlgorithmByGostAlgorithm(sigAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("buildSignatureAlgorithm: get signature algorithm: %w", err)
	}

	data, err := asn1.Marshal(derEncodedAlgorithmIdentifier{
		AlgorithmIdentifier: sigOID,
		Parameters:          asn1.NullRawValue,
	})
	if err != nil {
		return nil, fmt.Errorf("buildSignatureAlgorithm: marshal identifier: %w", err)
	}

	return data, nil
}

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
func GostDigestFromCurveOID(oid asn1.ObjectIdentifier, algo x509gost.GOSTAlgorithm) (asn1.ObjectIdentifier, error) {
	hashAlgo, err := GostDigestAlgorithmToOID(algo)
	if err != nil {
		return hashAlgo, fmt.Errorf("gostDigestFromCurveOID: %w", err)
	}

	switch {
	// MUST: digestParamSet present and equal to id-tc26-digest-gost3411-12-256
	// when publicKeyParamSet is a GOST R 34.10-2001 set (§4.2).
	case isCryptoPro2001(oid):
		return x509gost.OIDHashStreebog256, nil

	// SHOULD: digestParamSet omitted for a 512-bit GOST R 34.10-2012 key (§4.2).
	case algo == x509gost.AlgoR341012_512:
		return nil, nil

	// SHOULD: digestParamSet omitted for 256-paramSetA (§4.2).
	case oid.Equal(x509gost.OIDParamTC26_256A):
		return nil, nil

	// MUST: digestParamSet omitted for 256-paramSetB/C/D (§4.2).
	case isTC26256BCD(oid):
		return nil, nil

	// Default: any other TC26 parameter set (e.g. 512-bit sets) — omit (§4.2).
	default:
		return nil, nil
	}
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

// isTC26256BCD reports whether oid is id-tc26-gost-3410-2012-256-paramSetB/C/D,
// for which §4.2 requires digestParamSet to be omitted.
func isTC26256BCD(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(x509gost.OIDParamTC26_256B) ||
		oid.Equal(x509gost.OIDParamTC26_256C) ||
		oid.Equal(x509gost.OIDParamTC26_256D)
}
