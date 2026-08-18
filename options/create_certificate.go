package options

import (
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
}

func (cco *CreateCertificateOptions) BuildCertificateInformation() (*models.CertificateInformation, error) {
	certInfo := &models.CertificateInformation{
		SerialNumber: cco.SerialNumber,
		NotBefore:    cco.NotBefore,
		NotAfter:     cco.NotBefore.Add(cco.TTL),
	}

	err := certInfo.Validate()
	if err != nil {
		return nil, fmt.Errorf("failed to build certificate information: %w", err)
	}

	return certInfo, nil
}
