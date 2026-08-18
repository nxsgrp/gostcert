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
