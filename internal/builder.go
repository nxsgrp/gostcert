package internal

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"github.com/nxsgrp/gostcert/internal/algorithm"
	"github.com/nxsgrp/gostcert/internal/options"
	gost "github.com/tarantool/go-gostcrypto"
)

// Ensure big is used (for SerialNumber type)
var _ = big.NewInt(0)

// ASN.1 structures for DER building (internal, not exported).

type derEncodedAlgorithmIdentifier struct {
	AlgorithmIdentifier asn1.ObjectIdentifier
}

type extension struct {
	ID       asn1.ObjectIdentifier
	Value    asn1.RawValue
	Critical bool `asn1:"optional"`
}

type validatedDER struct {
	NotBefore time.Time
	NotAfter  time.Time
}

// HashForGOST hashes data with the GOST hash algorithm implied by algo
// and returns the digest in little-endian byte order (GOST signing convention).
func HashForGOST(algo algorithm.GOSTAlgorithm, data []byte) ([]byte, error) {
	var h interface {
		Write([]byte) (int, error)
		Sum([]byte) []byte
	}

	switch algo {
	case algorithm.AlgoR341001:
		h = gost.NewGOSTR341194CryptoProHash()
	case algorithm.AlgoR341012_256:
		h = gost.NewStreebog256Hash()
	case algorithm.AlgoR341012_512:
		h = gost.NewStreebog512Hash()
	default:
		return nil, fmt.Errorf("hashForGOST: unknown GOSTAlgorithm %d", int(algo))
	}

	_, _ = h.Write(data)
	digest := h.Sum(nil)

	// GOST R 34.10 reads the digest as a little-endian integer "alpha".
	// Go's hash.Sum outputs big-endian bytes; reverse them.
	digestLE := make([]byte, len(digest))
	for i := range digest {
		digestLE[len(digest)-1-i] = digest[i]
	}

	return digestLE, nil
}

// BuildExtensions serializes a slice of pkix.Extension into the
// [3] EXPLICIT Extensions field of TBSCertificate.
// Returns nil if extensions is empty.
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

func BuildTBSCertificate(
	opts *options.CreateCertificateOptions,
	template, parent *x509.Certificate,
	sigAlgoDER []byte,
) ([]byte, error) {
	subjectDER := template.RawSubject
	issuerDER := parent.RawSubject

	spki, err := BuildSPKI(opts.RawPublicKey, opts.CurveOID, opts.Algorithm)
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
