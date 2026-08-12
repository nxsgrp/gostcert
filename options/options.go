// Package options defines configuration types for certificate issuance.
package options

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"math/big"
	"time"

	"github.com/tarantool/go-gostcrypto/x509gost"
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

	// IsCA enables the CA flag in BasicConstraints extension.
	// When true, the certificate can sign other certificates.
	IsCA bool

	// PathLenConstraint sets the path length constraint for CA certificates.
	// nil means no constraint; 0 means only leaf certificates;
	// 1 means one level of intermediate CA, etc.
	// Only meaningful when IsCA is true.
	PathLenConstraint *int

	// KeyUsage specifies the permitted key usages as a bitmask.
	// When non-zero, a KeyUsage extension (critical) is emitted.
	// When zero, defaults to x509.KeyUsageDigitalSignature.
	KeyUsage x509.KeyUsage

	// ExtraExtensions are additional X.509v3 extensions appended to
	// the certificate, typically for CryptoPro OIDs (49.3, 49.4).
	// These are emitted verbatim (critical flag from each pkix.Extension).
	ExtraExtensions []pkix.Extension
}

type SubjectOptions struct {
	// CommonName is the (CN) for the certificate subject.
	CommonName string
	// Country is the (C) values for the certificate subject.
	Country []string
	// Organization is the (O) values for the certificate subject.
	Organization []string
}

func (so *SubjectOptions) toPkixName() pkix.Name {
	return pkix.Name{
		CommonName:   so.CommonName,
		Country:      so.Country,
		Organization: so.Organization,
	}
}

type CryptoOptions struct {
	// CurveOID is the ASN.1 OID of the elliptic curve parameter set
	// (e.g. id-GostR3410-2001-CryptoPro-A-ParamSet).
	CurveOID asn1.ObjectIdentifier

	// RandReader is the entropy source used during signing.
	// Typically crypto/rand.Reader.
	RandReader io.Reader

	// Signer is the crypto.Signer that produces the GOST signature.
	// It may wrap a software key or a hardware token (PKCS#11, Rutoken).
	Signer crypto.Signer

	// Algorithm identifies the subject public key algorithm
	// (e.g. AlgoR341012_256 for GOST R 34.10-2012 with a 256-bit key).
	Algorithm x509gost.GOSTAlgorithm

	// SignAlgorithm identifies the signature algorithm used to sign
	// the TBSCertificate (e.g. AlgoR341012_256 for
	// GOST R 34.11-2012 with GOST R 34.10-2012).
	SignAlgorithm x509gost.GOSTAlgorithm
}

// BuildTemplateCertificate creates a *x509.Certificate template populated
// from the CreateCertificateOptions fields.
//
// The returned template is used as both the subject template and, if
// ParentCertificate is nil, as the issuer template for self-issued certs.
func (o *CreateCertificateOptions) BuildTemplateCertificate() *x509.Certificate {
	tpl := &x509.Certificate{
		SerialNumber: o.SerialNumber,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(o.TTL),
		Subject:      o.Subject.toPkixName(),
		IsCA:         o.IsCA,
		MaxPathLen:   0,

		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}

	if o.PathLenConstraint != nil {
		tpl.MaxPathLen = *o.PathLenConstraint
		tpl.MaxPathLenZero = *o.PathLenConstraint == 0
	}

	if o.KeyUsage == 0 {
		tpl.KeyUsage = x509.KeyUsageDigitalSignature
	} else {
		tpl.KeyUsage = o.KeyUsage
	}

	return tpl
}
