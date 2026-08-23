package gostcert

import (
	"crypto/x509/pkix"
	"fmt"

	"github.com/nxsgrp/gostcert/internal"
	"github.com/nxsgrp/gostcert/internal/models"
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

	// Create TBS Certificate raw body by concatenation
	tbsBody, err := internal.BuildTBSCertificate(certInfo, subject, issuer, sigAlgoDER)
	if err != nil {
		return nil, fmt.Errorf("CreateCertificate: build tbs certificate: %w", err)
	}

	// Build standard X.509v3 extensions and append them to the TBS body as
	// the optional [3] EXPLICIT Extensions field (RFC 5280, section 4.1.2.9).
	extensions, err := buildStandardExtensions(opts, subject, issuer)
	if err != nil {
		return nil, fmt.Errorf("CreateCertificate: build standard extensions: %w", err)
	}

	extDER, err := internal.BuildExtensions(extensions)
	if err != nil {
		return nil, fmt.Errorf("CreateCertificate: build extensions: %w", err)
	}
	if len(extDER) > 0 {
		tbsBody = append(tbsBody, extDER...)
	}

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

// buildStandardExtensions assembles the X.509v3 extensions for a GOST
// certificate:
//
//   - BasicConstraints — CA flag and optional pathLenConstraint
//   - SubjectKeyIdentifier — Streebog-256 digest of the raw subject public key
//   - AuthorityKeyIdentifier — the parent's SubjectKeyIdentifier, or the
//     subject's own SKI for self-issued certificates
//   - KeyUsage — emitted only when opts.KeyUsage is non-zero
//   - ExtraExtensions — appended verbatim
func buildStandardExtensions(
	opts *options.CreateCertificateOptions,
	subject *models.Subject,
	issuer *models.Issuer,
) ([]pkix.Extension, error) {
	var exts []pkix.Extension

	// 1. BasicConstraints.
	basicConstraitExt, err := internal.BuildBasicConstraintsExtension(opts.IsCA, opts.PathLenConstraint)
	if err != nil {
		return nil, fmt.Errorf("buildBasicConstraintsExtension: %w", err)
	}
	exts = append(exts, basicConstraitExt)

	// 2. SubjectKeyIdentifier = Streebog-256 of the raw subject public key.
	skiDigest, err := internal.Streebog256(subject.PublicKey.RawPublicKey)
	if err != nil {
		return nil, fmt.Errorf("buildStandardExtensions: %w", err)
	}

	subjectKeyExt, err := internal.BuildSubjectKeyIdentifierExtension(skiDigest)
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

	authKeyExt, err := internal.BuildAuthorityKeyIdentifierExtension(akiKeyID)
	if err != nil {
		return nil, fmt.Errorf("buildStandardExtensions: %w", err)
	}
	exts = append(exts, authKeyExt)

	// 4. KeyUsage (critical), only when explicitly requested.
	kuExt, err := internal.BuildKeyUsageExtension(opts.KeyUsage)
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
