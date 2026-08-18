package internal

import (
	"encoding/asn1"
	"fmt"
	"time"

	"github.com/nxsgrp/gostcert/internal/models"
)

// derEncodedAlgorithmIdentifier is an ASN.1 container for the signature
// AlgorithmIdentifier. It carries the algorithm OID plus a NULL Parameters
// field, matching the encoding produced by OpenSSL for GOST signature
// algorithms (RFC 5280 §4.1.1.2 requires the parameters to be present and be
// NULL for most algorithms).
type derEncodedAlgorithmIdentifier struct {
	AlgorithmIdentifier asn1.ObjectIdentifier
	Parameters          asn1.RawValue `asn1:"optional"`
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
	certInfo *models.CertificateInformation,
	subject *models.Subject,
	issuer *models.Issuer,
	sigAlgoDER []byte,
) ([]byte, error) {
	subjectDER, err := BuildSubjectDER(subject)
	if err != nil {
		return nil, fmt.Errorf("CreateCertificate: marshal Subject: %w", err)
	}

	var issuerDER []byte
	if issuer.GetParentCertificate() != nil {
		issuerDER = issuer.GetParentCertificate().RawSubject
	} else {
		issuerDER = subjectDER
	}

	//nolint
	//issuerDER := issuer.GetParentCertificate().RawSubject
	if len(issuerDER) == 0 {
		issuerDER, err = asn1.Marshal(issuer.GetParentCertificate().Subject.ToRDNSequence())
		if err != nil {
			return nil, fmt.Errorf("CreateCertificate: marshal Issuer: %w", err)
		}
	}

	spki, err := BuildSPKI(subject.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("CreateCertificate: build SPKI: %w", err)
	}

	serialDER, err := asn1.Marshal(certInfo.SerialNumber)
	if err != nil {
		return nil, fmt.Errorf("CreateCertificate: marshal serial: %w", err)
	}

	// Validity SEQUENCE { notBefore Time, notAfter Time }
	validityDER, err := asn1.Marshal(validatedDER{
		NotBefore: certInfo.NotBefore.UTC(),
		NotAfter:  certInfo.NotAfter.UTC(),
	})
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

func BuildTBSCertificateRawValue(tbsBody []byte) ([]byte, error) {
	tbsRawValue := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      tbsBody,
	}

	tbsDER, err := asn1.Marshal(tbsRawValue)
	if err != nil {
		return nil, fmt.Errorf("BuildTBSCertificateRawValue: marshal TBS: %w", err)
	}

	return tbsDER, nil
}

func BuildSigBitString(signature []byte) ([]byte, error) {
	sigBitString := asn1.BitString{
		Bytes:     signature,
		BitLength: len(signature) * 8,
	}

	sigBitDER, err := asn1.Marshal(sigBitString)
	if err != nil {
		return nil, fmt.Errorf("BuildSigBitString: marshal signature: %w", err)
	}

	return sigBitDER, nil
}

func BuildSigCertificateRawValue(sigCertBody []byte) ([]byte, error) {
	certRawValue := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      sigCertBody,
	}

	certDER, err := asn1.Marshal(certRawValue)
	if err != nil {
		return nil, fmt.Errorf("BuildSigCertificateRawValue: marshal sig cert: %w", err)
	}

	return certDER, nil
}

// BuildSubjectDER marshals the subject Name into an asn1.RDNSequence, encoding
// every string attribute as UTF8String except countryName (left as
// PrintableString). This matches the DER encoding OpenSSL produces for GOST
// certificates, enabling byte-for-byte comparison with an OpenSSL-built
// certificate.
func BuildSubjectDER(subject *models.Subject) ([]byte, error) {
	rdns := subject.GetPkixName().ToRDNSequence()

	for i := range rdns {
		for j := range rdns[i] {
			atv := &rdns[i][j]

			if atv.Type.Equal(oidCountryName) {
				// Country stays PrintableString (as OpenSSL encodes it).
				continue
			}

			if str, ok := atv.Value.(string); ok {
				atv.Value = asn1.RawValue{
					Class: asn1.ClassUniversal,
					Tag:   asn1.TagUTF8String,
					Bytes: []byte(str),
				}
			}
		}
	}

	return asn1.Marshal(rdns)
}
