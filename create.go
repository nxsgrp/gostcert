package gostcert

import (
	"encoding/asn1"
	"fmt"

	"github.com/nxsgrp/gostcert/internal"
	"github.com/nxsgrp/gostcert/options"
)

// CreateCertificate creates a new DER-encoded GOST X.509 certificate and
// returns a parsed Certificate wrapper.
//
// The certificate is built from the provided options: template fields (subject,
// serial number, validity), public key (RawPublicKey), signature and key
// algorithm identifiers, and the key material for signing.
//
// If opts.ParentCertificate is set the issued certificate uses the parent's
// subject as the Issuer field (CA-issued certificate). Otherwise the
// certificate is self-issued (Issuer = Subject).
//
// The function assembles the TBSCertificate DER body, signs it with the
// provided crypto.Signer (which may wrap a hardware token), wraps the
// result in the SignedCertificate SEQUENCE, and re-parses the DER output
// through ParseCertificate before returning.
func CreateCertificate(opts *options.CreateCertificateOptions) (*Certificate, error) {
	template := opts.BuildTemplateCertificate()

	parentCert := template
	if opts.ParentCertificate != nil {
		parentCert = opts.ParentCertificate
	}

	// Create sig DER algorithm
	sigAlgoDER, err := internal.BuildSignatureAlgorithm(opts.Crypto.SignAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("CreateCertificate: build sig algo: %w", err)
	}

	// Build standard X.509v3 extensions.
	template.ExtraExtensions = internal.BuildStandardExtensions(opts, parentCert)

	// Create TBS Certificate raw body by concatenation
	tbsBody, err := internal.BuildTBSCertificate(opts, template, parentCert, sigAlgoDER)
	if err != nil {
		return nil, fmt.Errorf("CreateCertificate: build tbs certificate: %w", err)
	}

	// Extensions (optional [3] EXPLICIT).
	extDER, err := internal.BuildExtensions(template.ExtraExtensions)
	if err != nil {
		return nil, fmt.Errorf("CreateCertificate: %w", err)
	}
	if len(extDER) > 0 {
		tbsBody = append(tbsBody, extDER...)
	}

	tbsRawValue := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      tbsBody,
	}

	tbsDER, err := asn1.Marshal(tbsRawValue)
	if err != nil {
		return nil, fmt.Errorf("CreateCertificate: marshal TBS: %w", err)
	}

	// Sign temp certificate
	digestLE, err := internal.HashForGOST(opts.Crypto.SignAlgorithm, tbsDER)
	if err != nil {
		return nil, fmt.Errorf("CreateCertificate: hash: %w", err)
	}

	sig, err := opts.Crypto.Signer.Sign(opts.Crypto.RandReader, digestLE, nil)
	if err != nil {
		return nil, fmt.Errorf("CreateCertificate: sign: %w", err)
	}

	// Building final certificate
	sigBitString := asn1.BitString{
		Bytes:     sig,
		BitLength: len(sig) * 8,
	}

	sigBitDER, err := asn1.Marshal(sigBitString)
	if err != nil {
		return nil, fmt.Errorf("CreateCertificate: marshal signature: %w", err)
	}

	certBody := internal.ConcatBytes(tbsDER, sigAlgoDER)
	certBody = append(certBody, sigBitDER...)

	certRawValue := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      certBody,
	}

	certDER, err := asn1.Marshal(certRawValue)
	if err != nil {
		return nil, fmt.Errorf("CreateCertificate: marshal cert: %w", err)
	}

	cert, err := ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("CreateCertificate: parse result: %w", err)
	}

	return cert, nil
}
