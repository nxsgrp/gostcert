package internal

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"github.com/nxsgrp/gostcert/options"
	"github.com/tarantool/go-gostcrypto/x509gost"
)

// Ensure big is used (for SerialNumber type)
var _ = big.NewInt(0)

// derEncodedAlgorithmIdentifier is a minimal ASN.1 container for an
// AlgorithmIdentifier that carries only the OID and no parameters.
// Used for signature AlgorithmIdentifiers per GOST conventions.
type derEncodedAlgorithmIdentifier struct {
	AlgorithmIdentifier asn1.ObjectIdentifier
}

// extension is an ASN.1 representation of a single X.509v3 extension,
// matching the Extension SEQUENCE defined in RFC 5280.
//
// The field order follows the ASN.1 definition: extnID, critical (optional),
// extnValue (OCTET STRING).
type extension struct {
	ID       asn1.ObjectIdentifier
	Critical bool `asn1:"optional"`
	Value    asn1.RawValue
}

// validatedDER is an ASN.1 container for the Validity SEQUENCE
// (notBefore and notAfter) inside a TBSCertificate.
type validatedDER struct {
	NotBefore time.Time
	NotAfter  time.Time
}

// BuildTBSCertificate assembles the DER-encoded body of the
// TBSCertificate SEQUENCE (RFC 5280, section 4.1.2).
//
// The returned bytes include, in order:
//   - version [0] EXPLICIT INTEGER (v3)
//   - serialNumber
//   - signature (AlgorithmIdentifier)
//   - issuer (RawSubject from parent, or marshalled Subject)
//   - validity (notBefore, notAfter)
//   - subject
//   - subjectPublicKeyInfo (via BuildSPKI)
//
// Extensions are not included here; the caller appends them separately.
func BuildTBSCertificate(
	opts *options.CreateCertificateOptions,
	template, parent *x509.Certificate,
	sigAlgoDER []byte,
) ([]byte, error) {
	subjectDER, err := asn1.Marshal(template.Subject.ToRDNSequence())
	if err != nil {
		return nil, fmt.Errorf("CreateCertificate: marshal Subject: %w", err)
	}

	issuerDER := parent.RawSubject
	if len(issuerDER) == 0 {
		issuerDER, err = asn1.Marshal(parent.Subject.ToRDNSequence())
		if err != nil {
			return nil, fmt.Errorf("CreateCertificate: marshal Issuer: %w", err)
		}
	}

	spki, err := BuildSPKI(opts.RawPublicKey, opts.Crypto.CurveOID, opts.Crypto.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("CreateCertificate: %w", err)
	}

	serialDER, err := asn1.Marshal(opts.SerialNumber)
	if err != nil {
		return nil, fmt.Errorf("CreateCertificate: marshal serial: %w", err)
	}

	validDER := validatedDER{
		NotBefore: template.NotBefore,
		NotAfter:  template.NotAfter,
	}

	// Validity SEQUENCE { notBefore Time, notAfter Time }
	validityDER, err := asn1.Marshal(validDER)
	if err != nil {
		return nil, fmt.Errorf("CreateCertificate: marshal validity: %w", err)
	}

	rawVersionValue := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      []byte{0x02, 0x01, 0x02}, // INTEGER 2
	}

	// version [0] EXPLICIT INTEGER := 2 (v3).
	versionDER, err := asn1.Marshal(rawVersionValue)
	if err != nil {
		return nil, fmt.Errorf("CreateCertificate: marshal version: %w", err)
	}

	tbsBody := ConcatBytes(
		versionDER,
		serialDER,
		sigAlgoDER,
		issuerDER,
		validityDER,
		subjectDER,
		spki,
	)

	return tbsBody, nil
}

// HashForGOST hashes data with the GOST hash algorithm corresponding to
// the given GOST algorithm and returns the digest in little-endian byte order.
//
// GOST R 34.10 reads the digest as a little-endian integer ("alpha").
// Go's hash.Hash.Sum outputs big-endian bytes, so this function reverses
// them before returning.
func HashForGOST(algo x509gost.GOSTAlgorithm, data []byte) ([]byte, error) {
	h, err := GostAlgorithmToHash(algo)
	if err != nil {
		return nil, fmt.Errorf("hashForGOST: failed to get hasher %w", err)
	}

	_, err = h.Write(data)
	if err != nil {
		return nil, fmt.Errorf("hashForGOST: faile to write hash data %w", err)
	}
	digest := h.Sum(nil)

	// GOST R 34.10 reads the digest as a little-endian integer "alpha".
	// Go's hash.Sum outputs big-endian bytes; reverse them.
	digestLE := make([]byte, len(digest))
	for i := range digest {
		digestLE[len(digest)-1-i] = digest[i]
	}

	return digestLE, nil
}

// BuildExtensions serializes a slice of pkix.Extension into the DER-encoded
// [3] EXPLICIT Extensions field of TBSCertificate (RFC 5280, section 4.1.2.9).
//
// Returns nil, nil if extensions is empty (no extensions tag is written).
func BuildExtensions(extensions []pkix.Extension) ([]byte, error) {
	if len(extensions) == 0 {
		return nil, nil
	}

	var derExtension [][]byte
	for _, pkixExt := range extensions {
		extData, err := asn1.Marshal(extension{
			ID:       pkixExt.Id,
			Critical: pkixExt.Critical,
			Value: asn1.RawValue{
				FullBytes: pkixExt.Value,
			},
		})

		if err != nil {
			return nil, fmt.Errorf("buildExtension: marshal extension %v: %w", pkixExt.Id, err)
		}

		derExtension = append(derExtension, extData)
	}

	// Extensions ::= SEQUENCE OF Extension
	seq, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      ConcatBytes(derExtension...),
	})
	if err != nil {
		return nil, fmt.Errorf("buildExtension: marshal sequence: %w", err)
	}

	// [3] EXPLICIT
	expl, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        3,
		IsCompound: true,
		Bytes:      seq,
	})

	if err != nil {
		return nil, fmt.Errorf("buildExtension: marshal explicit: %w", err)
	}

	return expl, nil
}

// ConcatBytes concatenates multiple byte slices into a single contiguous slice.
// It pre-allocates the full size to avoid reallocation.
func ConcatBytes(parts ...[]byte) []byte {
	total := 0
	for _, p := range parts {
		total += len(p)
	}
	out := make([]byte, 0, total)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
