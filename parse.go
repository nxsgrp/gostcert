package gostcert

import (
	"fmt"

	"github.com/nxsgrp/gostcert/internal"
	"github.com/tarantool/go-gostcrypto/x509gost"
)

// ParseCertificate parses a DER-encoded X.509 certificate.
//
// For GOST-signed certificates the returned Certificate will have GOST-specific
// fields populated. Non-GOST certificates are parsed through the stdlib and
// stored in the Stdlib field.
func ParseCertificate(der []byte) (*Certificate, error) {
	gc, err := x509gost.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("gostcert: parse: %w", err)
	}

	cert := &Certificate{
		Stdlib:           gc.Stdlib,
		Raw:              gc.Raw,
		IsGOST:           gc.IsGOST,
		HasGOSTPublicKey: gc.HasGOSTPubKey,
		GOSTAlgorithm:    internal.MapAlgorithm(gc.GOSTAlgo),
		SigGOSTAlgorithm: internal.MapAlgorithm(gc.SigGOSTAlgo),
		PublicKeyRaw:     gc.PubKeyRaw,
		CurveOID:         gc.CurveOID,
		SPKIAlgorithmDER: gc.SPKIAlgorithmDER,
	}

	return cert, nil
}
