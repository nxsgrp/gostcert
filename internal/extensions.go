package internal

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"github.com/nxsgrp/gostcert/internal/models"
	"github.com/nxsgrp/gostcert/options"
)

type declaredKeyUsage struct {
	keyUsage x509.KeyUsage
	value    byte
}

// ASN.1 structures for extension content encoding.

// basicConstraints matches RFC 5280 §4.2.1.9.
// The default:-1 sentinel distinguishes "not set" from pathLenConstraint=0.
type basicConstraints struct {
	IsCA    bool `asn1:"optional"`
	PathLen int  `asn1:"optional,default:-1"`
}

// authKeyID matches the ASN.1 AuthorityKeyIdentifier extension
// (RFC 5280, section 4.2.1.1). Only keyIdentifier is populated
// for self-issued certificates.
type authKeyID struct {
	KeyID []byte `asn1:"tag:0,optional"`
}

// BuildExtensions assembles the X.509v3 extensions for a GOST
// certificate:
//
//   - BasicConstraints — CA flag and optional pathLenConstraint
//   - SubjectKeyIdentifier — Streebog-256 digest of the raw subject public key
//   - AuthorityKeyIdentifier — the parent's SubjectKeyIdentifier, or the
//     subject's own SKI for self-issued certificates
//   - KeyUsage — emitted only when opts.KeyUsage is non-zero
//   - ExtraExtensions — appended verbatim
func BuildExtensions(
	opts *options.CreateCertificateOptions,
	subject *models.Subject,
	issuer *models.Issuer,
) ([]pkix.Extension, error) {
	var exts []pkix.Extension

	// 1. BasicConstraints.
	basicConstraintExt, err := buildBasicConstraintsExtension(opts.IsCA, opts.PathLenConstraint)
	if err != nil {
		return nil, fmt.Errorf("buildBasicConstraintsExtension: %w", err)
	}
	exts = append(exts, basicConstraintExt)

	// 2. SubjectKeyIdentifier = Streebog-256 of the raw subject public key.
	skiDigest, err := HashForGOST(issuer.SignAlgorithm, subject.PublicKey.RawPublicKey)
	if err != nil {
		return nil, fmt.Errorf("buildStandardExtensions: %w", err)
	}

	subjectKeyExt, err := buildSubjectKeyIdentifierExtension(skiDigest)
	if err != nil {
		return nil, fmt.Errorf("buildStandardExtensions: %w", err)
	}
	exts = append(exts, subjectKeyExt)

	// 3. AuthorityKeyIdentifier: the parent's SKI when a parent is present,
	// otherwise the subject's own SKI (self-issued certificate).
	akiKeyID := skiDigest
	if parent := issuer.GetParentCertificate(); parent != nil && len(parent.SubjectKeyId) > 0 {
		akiKeyID = parent.SubjectKeyId
	}

	authKeyExt, err := buildAuthorityKeyIdentifierExtension(akiKeyID)
	if err != nil {
		return nil, fmt.Errorf("buildStandardExtensions: %w", err)
	}
	exts = append(exts, authKeyExt)

	// 4. KeyUsage (critical), only when explicitly requested.
	kuExt, err := buildKeyUsageExtension(opts.KeyUsage)
	if err != nil {
		return nil, fmt.Errorf("buildStandardExtensions: %w", err)
	}
	if opts.KeyUsage != 0 {
		exts = append(exts, kuExt)
	}

	// 5. Extra extensions appended verbatim.
	exts = append(exts, opts.ExtraExtensions...)

	return exts, nil
}

// ConvertExtensionsToRawBytes serializes a slice of pkix.Extension into the DER-encoded
// [3] EXPLICIT Extensions field of TBSCertificate (RFC 5280, section 4.1.2.9).
//
// Returns nil, nil if extensions is empty (no extensions tag is written).
func ConvertExtensionsToRawBytes(extensions []pkix.Extension) ([]byte, error) {
	if len(extensions) == 0 {
		return nil, nil
	}

	var derExtension [][]byte
	for _, pkixExt := range extensions {
		extData, err := asn1.Marshal(pkix.Extension{
			Id:       pkixExt.Id,
			Critical: pkixExt.Critical,
			Value:    pkixExt.Value,
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

// buildSubjectKeyIdentifierExtension builds a SubjectKeyIdentifier extension
// with the given key identifier bytes.
//
// keyID should be the 160-bit (20-byte) SHA-1 hash of the public key.
// Per RFC 5280, section 4.2.1.2, SubjectKeyIdentifier ::= KeyIdentifier
// which is an OCTET STRING wrapped in an outer OCTET STRING (the extnValue).
func buildSubjectKeyIdentifierExtension(keyID []byte) (pkix.Extension, error) {
	var pkixExtension pkix.Extension

	// SubjectKeyIdentifier ::= KeyIdentifier (OCTET STRING).
	// The Value carried in pkix.Extension is this single DER element; the
	// surrounding extnValue OCTET STRING is added when the Extension is encoded.
	content, err := asn1.Marshal(keyID)
	if err != nil {
		return pkixExtension, fmt.Errorf("BuildSubjectKeyIdentifierExtension: %w", err)
	}

	pkixExtension = pkix.Extension{
		Id:    oidSubjectKeyIdentifier,
		Value: content,
	}

	return pkixExtension, nil
}

// buildAuthorityKeyIdentifierExtension builds an AuthorityKeyIdentifier
// extension with the given key identifier (typically the same as the
// SubjectKeyIdentifier for self-issued certificates).
//
// Per RFC 5280, section 4.2.1.1, the keyIdentifier is an OCTET STRING
// carried in an implicit [0] tag inside a SEQUENCE, then wrapped in
// an OCTET STRING (the extnValue).
func buildAuthorityKeyIdentifierExtension(keyID []byte) (pkix.Extension, error) {
	var pkixExtension pkix.Extension

	// AuthorityKeyIdentifier ::= KeyIdentifier (OCTET STRING).
	// The Value carried in pkix.Extension is this single DER element; the
	// surrounding extnValue OCTET STRING is added when the Extension is encoded.
	content, err := asn1.Marshal(authKeyID{KeyID: keyID})
	if err != nil {
		return pkixExtension, fmt.Errorf("BuildAuthorityKeyIdentifierExtension: %w", err)
	}

	pkixExtension = pkix.Extension{
		Id:    oidAuthorityKeyIdentifier,
		Value: content,
	}

	return pkixExtension, nil
}

// buildBasicConstraintsExtension builds a BasicConstraints extension.
// When pathLen is nil, pathLenConstraint is omitted from the ASN.1.
// When pathLen is 0, pathLenConstraint=0 is encoded (leaf-only).
func buildBasicConstraintsExtension(isCA bool, pathLen *int) (pkix.Extension, error) {
	var pkixExtension pkix.Extension

	bc := basicConstraints{IsCA: isCA, PathLen: -1}
	if pathLen != nil {
		bc.PathLen = *pathLen
	}

	content, err := asn1.Marshal(bc)
	if err != nil {
		return pkixExtension, fmt.Errorf("BuildBasicConstraintsExtension: %w", err)
	}

	pkixExtension = pkix.Extension{
		Id:       oidBasicConstraints,
		Critical: true,
		Value:    content,
	}

	return pkixExtension, nil
}

// buildKeyUsageExtension builds a KeyUsage extension from a x509.KeyUsage bitmask.
// OID 2.5.29.15, marked critical per RFC 5280.
func buildKeyUsageExtension(keyUsage x509.KeyUsage) (pkix.Extension, error) {
	var pkixExtension pkix.Extension

	var kuBytes [2]byte
	var kuBitLen int

	// Into these loops we're checking x509.KeyUsage entries like
	// if keyUsage & x509.KeyUsageDigitalSignature != 0 { ... }
	// There are both checking for least and most significant bits (0, 1)

	// most significant bits
	for index, ku := range declaredLeastKeysUsage {
		if keyUsage&ku.keyUsage != 0 {
			kuBytes[0] |= ku.value
			kuBitLen = index + 1
		}
	}

	// least significant bits
	for index, ku := range declaredMostKeysUsage {
		if keyUsage&ku.keyUsage != 0 {
			kuBytes[0] |= ku.value
			kuBitLen = index + 1
		}
	}

	bitString := asn1.BitString{Bytes: kuBytes[:], BitLength: kuBitLen}
	content, err := asn1.Marshal(bitString)
	if err != nil {
		return pkixExtension, fmt.Errorf("BuildKeyUsageExtension: %w", err)
	}

	pkixExtension = pkix.Extension{
		Id:       oidKeyUsage,
		Critical: true,
		Value:    content,
	}

	return pkixExtension, nil
}
