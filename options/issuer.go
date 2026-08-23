package options

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/nxsgrp/gostcert/gost"
	"github.com/nxsgrp/gostcert/internal/models"
)

// IssuerOptions aggregated model of issuer options to sign certificate.
type IssuerOptions struct {
	// RandReader is the entropy source used during signing. Typically crypto/rand.Reader.
	RandReader io.Reader

	// Signer is the crypto.Signer that produces the GOST signature.
	// It may wrap a software key or a hardware token (PKCS#11, Rutoken).
	Signer crypto.Signer

	// SignAlgorithm identifies the signature algorithm used to sign
	// the TBSCertificate (e.g. AlgoR341012_256 for
	// GOST R 34.11-2012 with GOST R 34.10-2012).
	SignAlgorithm gost.GOSTAlgorithm

	// ParentCertificate is the issuer certificate. When set, the issued
	// certificate uses the parent's Subject as the Issuer field.
	// When nil, the certificate is self-issued (Issuer = Subject).
	ParentCertificate *x509.Certificate
}

func (io *IssuerOptions) BuildIssuer() (*models.Issuer, error) {
	algorithm := io.SignAlgorithm.ToX509()

	issuer, err := models.CreateIssuer(
		io.RandReader,
		io.Signer,
		algorithm,
		io.ParentCertificate,
	)

	if err != nil {
		return nil, fmt.Errorf("build issuer from options: %w", err)
	}

	return issuer, nil
}
