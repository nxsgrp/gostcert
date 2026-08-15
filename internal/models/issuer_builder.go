package models

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/tarantool/go-gostcrypto/x509gost"
)

type IssuerBuilder struct {
	issuer *Issuer
}

func NewIssuerBuilder() *IssuerBuilder {
	return &IssuerBuilder{
		issuer: &Issuer{},
	}
}

func (ib *IssuerBuilder) WithRandReader(reader io.Reader) *IssuerBuilder {
	ib.issuer.RandReader = reader
	return ib
}

func (ib *IssuerBuilder) WithSigner(signer crypto.Signer) *IssuerBuilder {
	ib.issuer.Signer = signer
	return ib
}

func (ib *IssuerBuilder) WithSignAlgorithm(signAlgorithm x509gost.GOSTAlgorithm) *IssuerBuilder {
	ib.issuer.SignAlgorithm = signAlgorithm
	return ib
}

func (ib *IssuerBuilder) WithParentCertificate(parentCertificate *x509.Certificate) *IssuerBuilder {
	ib.issuer.ParentCertificate = parentCertificate
	return ib
}

func (ib *IssuerBuilder) Build() (*Issuer, error) {
	if ib.issuer.RandReader == nil {
		return nil, fmt.Errorf("build issuer: nil rand reader")
	}

	if ib.issuer.Signer == nil {
		return nil, fmt.Errorf("build issuer: nil signer")
	}

	if err := ib.validateSignAlgorithm(); err != nil {
		return nil, fmt.Errorf("build issuer: %w", err)
	}

	return ib.issuer, nil
}

func (ib *IssuerBuilder) validateSignAlgorithm() error {
	// Checking using forbidden algorithm.
	if ib.issuer.SignAlgorithm == x509gost.AlgoR341001 {
		return fmt.Errorf("the GOST R 34.10-2001 algorithm was been forbidden")
	}
	return nil
}
