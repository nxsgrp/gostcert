package models

import (
	"crypto/x509/pkix"
	"encoding/asn1"

	"github.com/tarantool/go-gostcrypto/x509gost"
)

type Subject struct {
	Information SubjetInformation
	PublicKey   SubjectPublicKey
}

// SubjetInformation contains necessary information of certificate publisher.
type SubjetInformation struct {
	// CommonName is the (CN) for the certificate subject.
	CommonName string
	// Country is the (C) values for the certificate subject.
	Country []string
	// Organization is the (O) values for the certificate subject.
	Organization []string
}

// SubjectPublicKey contains subject public key options.
type SubjectPublicKey struct {
	// CurveOID is the ASN.1 OID of the elliptic curve parameter set
	// (e.g. id-GostR3410-2012-CryptoPro-A-ParamSet).
	CurveOID asn1.ObjectIdentifier

	// Algorithm identifies the subject public key algorithm
	// (e.g. AlgoR341012_256 for GOST R 34.10-2012 with a 256-bit key).
	Algorithm x509gost.GOSTAlgorithm

	// RawPublicKey is the raw GOST public key in LE(X) || LE(Y) format.
	RawPublicKey []byte
}

func (s *Subject) GetPkixName() pkix.Name {
	return pkix.Name{
		CommonName:   s.Information.CommonName,
		Country:      s.Information.Country,
		Organization: s.Information.Organization,
	}
}
