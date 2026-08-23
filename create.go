package gostcert

import (
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
	issuer, err := opts.Issuer.BuildIssuer()
	if err != nil {
		return nil, fmt.Errorf("CreateCertificate: %w", err)
	}

	subject, err := opts.Subject.BuildSubject()
	if err != nil {
		return nil, fmt.Errorf("CreateCertificate: %w", err)
	}

	certInfo, err := opts.BuildCertificateInformation()
	if err != nil {
		return nil, fmt.Errorf("CreateCertificate: %w", err)
	}

	// Create sig DER algorithm
	sigAlgoDER, err := internal.BuildSignatureAlgorithm(issuer.SignAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("CreateCertificate: build sig algo: %w", err)
	}

	// Build standard X.509v3 extensions.
	template.ExtraExtensions = internal.BuildExtraExtensions(opts, parentCert)

	// Create TBS Certificate raw body by concatenation
	tbsBody, err := internal.BuildTBSCertificate(certInfo, subject, issuer, sigAlgoDER)
	if err != nil {
		return nil, fmt.Errorf("CreateCertificate: build tbs certificate: %w", err)
	}

	// TODO: will be implemented to another MR.
	// Extensions (optional [3] EXPLICIT).
	//nolint
	//template := opts.BuildTemplateCertificate()
	//extDER, err := internal.BuildExtensions(nil)
	//if err != nil {
	//	return nil, fmt.Errorf("CreateCertificate: %w", err)
	//}
	//if len(extDER) > 0 {
	//	tbsBody = append(tbsBody, extDER...)
	//}

	tbsDER, err := internal.BuildTBSCertificateRawValue(tbsBody)
	if err != nil {
		return nil, fmt.Errorf("CreateCertificate: build tbs raw value: %w", err)
	}

	// Sign temp certificate
	digestLE, err := internal.HashForGOST(issuer.SignAlgorithm, tbsDER)
	if err != nil {
		return nil, fmt.Errorf("CreateCertificate: hash: %w", err)
	}

	sig, err := issuer.Signer.Sign(issuer.RandReader, digestLE, nil)
	if err != nil {
		return nil, fmt.Errorf("CreateCertificate: sign: %w", err)
	}

	// Building final certificate
	sigBitDER, err := internal.BuildSigBitString(sig)
	if err != nil {
		return nil, fmt.Errorf("CreateCertificate: build sig bit string: %w", err)
	}

	certBody := internal.ConcatBytes(tbsDER, sigAlgoDER)
	certBody = append(certBody, sigBitDER...)

	certDER, err := internal.BuildSigCertificateRawValue(certBody)
	if err != nil {
		return nil, fmt.Errorf("CreateCertificate: marshal sig cert: %w", err)
	}

	cert, err := ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("CreateCertificate: parse result: %w", err)
	}

	return cert, nil
}
