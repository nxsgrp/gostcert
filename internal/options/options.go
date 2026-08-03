package options

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"math/big"
	"time"

	"github.com/nxsgrp/gostcert/internal/algorithm"
)

type CreateCertificateOptions struct {
	SubjectName  string
	Organization []string

	CurveOID   asn1.ObjectIdentifier
	RandReader io.Reader
	Signer     crypto.Signer

	Algorithm     algorithm.GOSTAlgorithm
	SignAlgorithm algorithm.GOSTAlgorithm

	RawPublicKey  []byte
	RawPrivateKey []byte

	ParentCertificate   *x509.Certificate
	TemplateCertificate *x509.Certificate

	SerialNumber *big.Int
	TTL          time.Duration // secs
}

func (o *CreateCertificateOptions) BuildTemplateCertificate() *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: o.SerialNumber,

		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(o.TTL),

		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment,

		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},

		Subject: pkix.Name{
			CommonName:   o.SubjectName,
			Organization: o.Organization,
		},
	}
}
