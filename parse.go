package gostcert

import (
	"fmt"

	"github.com/tarantool/go-gostcrypto/x509gost"
)

// ParseCertificate parses a DER-encoded X.509 certificate and returns a
// GOST-aware Certificate wrapper.
//
// The function delegates to x509gost.ParseCertificate which handles both GOST
// and non-GOST certificates transparently.
func ParseCertificate(der []byte) (*Certificate, error) {
	gc, err := x509gost.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("gostcert: parse: %w", err)
	}

	cert := &Certificate{
		cert: gc,
	}

	return cert, nil
}
