package options

import (
	"encoding/asn1"
	"fmt"

	"github.com/nxsgrp/gostcert/gost"
	"github.com/nxsgrp/gostcert/internal/models"
	"github.com/tarantool/go-gostcrypto/x509gost"
)

// SubjectOptions aggregated model of subject options to build certificate.
type SubjectOptions struct {
	Information      SubjetInformationOptions
	PublicKeyOptions SubjectPublicKeyOptions
}

// SubjetInformationOptions contains necessary information of certificate publisher.
type SubjetInformationOptions struct {
	// CommonName is the (CN) for the certificate subject.
	CommonName string
	// Country is the (C) values for the certificate subject.
	Country []string
	// Organization is the (O) values for the certificate subject.
	Organization []string
}

// SubjectPublicKeyOptions contains subject public key options.
type SubjectPublicKeyOptions struct {
	// CurveOID is the ASN.1 OID of the elliptic curve parameter set
	// (e.g. id-GostR3410-2012-CryptoPro-A-ParamSet).
	CurveOID asn1.ObjectIdentifier

	// Algorithm identifies the subject public key algorithm
	// (e.g. AlgoR341012_256 for GOST R 34.10-2012 with a 256-bit key).
	Algorithm gost.GOSTAlgorithm

	// RawPublicKey is the raw GOST public key in LE(X) || LE(Y) format.
	RawPublicKey []byte
}

func (so *SubjectOptions) BuildSubject() (*models.Subject, error) {
	algorithm := x509gost.GOSTAlgorithm(so.PublicKeyOptions.Algorithm)

	subject, err := models.NewSubjectBuilder().
		WithCommonName(so.Information.CommonName).
		WithCountry(so.Information.Country).
		WithOrganization(so.Information.Organization).
		WithCurveOID(so.PublicKeyOptions.CurveOID).
		WithPublicKey(so.PublicKeyOptions.RawPublicKey).
		WithAlgorithm(algorithm).
		Build()

	if err != nil {
		return nil, fmt.Errorf("build subject from options: %w", err)
	}

	return subject, nil
}
