package internal

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

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

// Standard X.509v3 extension OIDs.
var (
	oidSubjectKeyIdentifier   = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidAuthorityKeyIdentifier = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidBasicConstraints       = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidKeyUsage               = asn1.ObjectIdentifier{2, 5, 29, 15}
)

// BuildSubjectKeyIdentifierExtension builds a SubjectKeyIdentifier extension
// with the given key identifier bytes.
//
// keyID should be the 160-bit (20-byte) SHA-1 hash of the public key.
// Per RFC 5280, section 4.2.1.2, SubjectKeyIdentifier ::= KeyIdentifier
// which is an OCTET STRING wrapped in an outer OCTET STRING (the extnValue).
func BuildSubjectKeyIdentifierExtension(keyID []byte) pkix.Extension {
	// SubjectKeyIdentifier ::= KeyIdentifier (OCTET STRING)
	content, err := asn1.Marshal(keyID)
	if err != nil {
		panic("BuildSubjectKeyIdentifierExtension: " + err.Error())
	}

	// Wrap in an OCTET STRING to form the extnValue.
	value, err := asn1.Marshal(content)
	if err != nil {
		panic("BuildSubjectKeyIdentifierExtension: " + err.Error())
	}

	return pkix.Extension{
		Id:    oidSubjectKeyIdentifier,
		Value: value,
	}
}

// BuildAuthorityKeyIdentifierExtension builds an AuthorityKeyIdentifier
// extension with the given key identifier (typically the same as the
// SubjectKeyIdentifier for self-issued certificates).
//
// Per RFC 5280, section 4.2.1.1, the keyIdentifier is an OCTET STRING
// carried in an implicit [0] tag inside a SEQUENCE, then wrapped in
// an OCTET STRING (the extnValue).
func BuildAuthorityKeyIdentifierExtension(keyID []byte) pkix.Extension {
	aki := authKeyID{KeyID: keyID}
	content, err := asn1.Marshal(aki)
	if err != nil {
		panic("BuildAuthorityKeyIdentifierExtension: " + err.Error())
	}

	// Wrap the SEQUENCE content in an OCTET STRING (extnValue).
	value, err := asn1.Marshal(content)
	if err != nil {
		panic("BuildAuthorityKeyIdentifierExtension: " + err.Error())
	}

	return pkix.Extension{
		Id:    oidAuthorityKeyIdentifier,
		Value: value,
	}
}

// BuildBasicConstraintsExtension builds a BasicConstraints extension.
// When pathLen is nil, pathLenConstraint is omitted from the ASN.1.
// When pathLen is 0, pathLenConstraint=0 is encoded (leaf-only).
func BuildBasicConstraintsExtension(isCA bool, pathLen *int) pkix.Extension {
	bc := basicConstraints{IsCA: isCA, PathLen: -1}
	if pathLen != nil {
		bc.PathLen = *pathLen
	}

	content, err := asn1.Marshal(bc)
	if err != nil {
		panic("BuildBasicConstraintsExtension: " + err.Error())
	}

	value, err := asn1.Marshal(content)
	if err != nil {
		panic("BuildBasicConstraintsExtension: " + err.Error())
	}

	return pkix.Extension{
		Id:       oidBasicConstraints,
		Critical: true,
		Value:    value,
	}
}

// BuildKeyUsageExtension builds a KeyUsage extension from a x509.KeyUsage bitmask.
// OID 2.5.29.15, marked critical per RFC 5280.
func BuildKeyUsageExtension(ku x509.KeyUsage) pkix.Extension {
	var kuBytes [2]byte
	var kuBitLen int

	if ku&x509.KeyUsageDigitalSignature != 0 {
		kuBytes[0] |= 0x80
		kuBitLen = 1
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		kuBytes[0] |= 0x40
		kuBitLen = 2
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		kuBytes[0] |= 0x20
		kuBitLen = 3
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		kuBytes[0] |= 0x10
		kuBitLen = 4
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		kuBytes[0] |= 0x08
		kuBitLen = 5
	}
	if ku&x509.KeyUsageCertSign != 0 {
		kuBytes[0] |= 0x04
		kuBitLen = 6
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		kuBytes[0] |= 0x02
		kuBitLen = 7
	}
	if ku&x509.KeyUsageEncipherOnly != 0 {
		kuBytes[1] |= 0x80
		kuBitLen = 8
	}
	if ku&x509.KeyUsageDecipherOnly != 0 {
		kuBytes[1] |= 0x40
		kuBitLen = 9
	}

	bitString := asn1.BitString{Bytes: kuBytes[:], BitLength: kuBitLen}
	content, err := asn1.Marshal(bitString)
	if err != nil {
		panic("BuildKeyUsageExtension: " + err.Error())
	}

	value, err := asn1.Marshal(content)
	if err != nil {
		panic("BuildKeyUsageExtension: " + err.Error())
	}

	return pkix.Extension{
		Id:       oidKeyUsage,
		Critical: true,
		Value:    value,
	}
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
