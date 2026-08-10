package internal

import (
	"crypto/x509/pkix"
	"encoding/asn1"
)

// ASN.1 structures for extension content encoding.

// basicConstraints matches the ASN.1 BasicConstraints extension
// (RFC 5280, section 4.2.1.9).
type basicConstraints struct {
	IsCA bool `asn1:"optional"`
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

// BuildBasicConstraintsExtension builds a BasicConstraints extension
// marking the certificate as a CA (or not).
//
// Per RFC 5280, section 4.2.1.9, BasicConstraints is a SEQUENCE containing
// an optional BOOLEAN cA and an optional INTEGER pathLenConstraint, then
// wrapped in an OCTET STRING (the extnValue).
func BuildBasicConstraintsExtension(isCA bool) pkix.Extension {
	bc := basicConstraints{IsCA: isCA}
	content, err := asn1.Marshal(bc)
	if err != nil {
		panic("BuildBasicConstraintsExtension: " + err.Error())
	}

	// Wrap the SEQUENCE content in an OCTET STRING (extnValue).
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
