package options

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"

	"github.com/nxsgrp/gostcert/internal/models"
)

// CreateCertificateOptions holds all parameters needed to issue a new
// GOST X.509 certificate via CreateCertificate.
type CreateCertificateOptions struct {
	// SerialNumber is the unique serial number assigned to the certificate.
	SerialNumber *big.Int

	// NotBefore ...
	NotBefore time.Time

	// TTL is the certificate validity duration in seconds from the
	// current time (NotAfter = Now + TTL).
	TTL time.Duration

	// SubjectOptions is the necessary subject options to create certificate.
	Subject SubjectOptions

	// IssuerOptions is the necessary issuer options to sign certificate.
	Issuer IssuerOptions

	// IsCA enables the CA flag in the BasicConstraints extension.
	// When true, the certificate can sign other certificates.
	IsCA bool

	// PathLenConstraint sets the path length constraint for CA certificates.
	// nil means no constraint; 0 means only leaf certificates;
	// 1 means one level of intermediate CA, etc.
	// Only meaningful when IsCA is true.
	PathLenConstraint *int

	// KeyUsage specifies the permitted key usages as a bitmask
	// (RFC 5280, section 4.2.1.3). When non-zero, a critical KeyUsage
	// extension is emitted. When zero, no KeyUsage extension is written.
	KeyUsage x509.KeyUsage

	// ExtraExtensions are additional X.509v3 extensions appended verbatim to
	// the certificate, typically for CryptoPro OIDs (49.3, 49.4). Each entry
	// keeps its own Critical flag from pkix.Extension.
	ExtraExtensions []pkix.Extension
}

func (cco *CreateCertificateOptions) BuildCertificateInformation() (*models.CertificateInformation, error) {
	// Default NotBefore to "now" before computing NotAfter = NotBefore + TTL,
	// otherwise an unset NotBefore (zero time) would shift NotAfter into 1970
	// and fail validation against the defaulted NotBefore.
	notBefore := cco.NotBefore
	if notBefore.IsZero() {
		notBefore = time.Now()
	}

	certInfo, err := models.CreateCertificateInformation(
		cco.SerialNumber,
		notBefore,
		notBefore.Add(cco.TTL),
	)

	if err != nil {
		return nil, fmt.Errorf("failed to build certificate information: %w", err)
	}

	return certInfo, nil
}
