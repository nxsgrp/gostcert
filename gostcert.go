package gostcert

import (
	"crypto/x509"

	"github.com/tarantool/go-gostcrypto/x509gost"
)

// Certificate is a GOST-aware X.509 certificate.
//
// It mirrors every field from x509gost.Certificate, keeping the underlying
// implementation (currently tarantool/go-gostcrypto) as an internal detail.
//
// Note: For GOST-signed certificates SignatureAlgorithm in the underlying
// *x509.Certificate (returned by StdCertificate) will be
// UnknownSignatureAlgorithm because the standard library cannot verify
// GOST signatures.
type Certificate struct {
	cert *x509gost.Certificate
}

// StdCertificate returns the underlying standard-library *x509.Certificate.
//
// The returned value contains all standard X.509 fields (Subject, Issuer,
// NotBefore, NotAfter, SerialNumber, etc.) parsed from the DER blob.
// GOST-specific fields (IsGOST, GOSTAlgo, SigGOSTAlgo, PubKeyRaw) are
// accessible only through the gostcert.Certificate wrapper.
func (c *Certificate) StdCertificate() *x509.Certificate {
	return c.cert.Stdlib
}

func (c *Certificate) GetRawCertificate() []byte {
	return c.cert.Raw
}
