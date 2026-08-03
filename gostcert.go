package gostcert

import (
	"crypto/x509"

	"github.com/tarantool/go-gostcrypto/x509gost"
)

// Certificate is a GOST-aware X.509 certificate.
//
// It mirrors every field from x509gost.Certificate, keeping the underlying
// implementation (currently tarantool/go-gostcrypto) as an internal detail.
type Certificate struct {
	// For GOST-signed certs SignatureAlgorithm will be UnknownSignatureAlgorithm
	// because the stdlib cannot verify GOST signatures.
	cert *x509gost.Certificate
}

func (c *Certificate) StdCertificate() *x509.Certificate {
	return c.cert.Stdlib
}
