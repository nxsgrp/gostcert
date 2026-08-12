package options

import (
	"crypto/x509"
	"math/big"
	"time"
)

// CreateCertificateOptions holds all parameters needed to issue a new
// GOST X.509 certificate via CreateCertificate.
type CreateCertificateOptions struct {
	// SerialNumber is the unique serial number assigned to the certificate.
	SerialNumber *big.Int

	// SubjectOptions is pkix.Name of subject certificate fields.
	Subject SubjectOptions

	// Crypto is the suit of certificated crypto options.
	Crypto CryptoOptions

	// RawPublicKey is the raw GOST public key in LE(X) || LE(Y) format.
	RawPublicKey []byte

	// RawPrivateKey is the raw GOST private key bytes (little-endian scalar).
	// Used when creating an internal Signer from raw key material.
	RawPrivateKey []byte

	// ParentCertificate is the issuer certificate. When set, the issued
	// certificate uses the parent's Subject as the Issuer field.
	// When nil, the certificate is self-issued (Issuer = Subject).
	ParentCertificate *x509.Certificate

	// TTL is the certificate validity duration in seconds from the
	// current time (NotAfter = Now + TTL).
	TTL time.Duration
}

// BuildTemplateCertificate creates a *x509.Certificate template populated
// from the CreateCertificateOptions fields.
//
// The returned template is used as both the subject template and, if
// ParentCertificate is nil, as the issuer template for self-issued certs.
func (o *CreateCertificateOptions) BuildTemplateCertificate() *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: o.SerialNumber,

		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(o.TTL),

		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,

		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},

		Subject: o.Subject.toPkixName(),
	}
}
