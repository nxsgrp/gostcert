package models

import (
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/tarantool/go-gostcrypto/x509gost"
)

var (
	ForbiddenError         = errors.New("the GOST R 34.10-2001 algorithm was not supported")
	InvalidPublicKeyLength = errors.New("invalid public key length for algorithm")

	UnavailableAlgorithms = []asn1.ObjectIdentifier{
		x509gost.OIDParamCryptoProA,
		x509gost.OIDParamCryptoProB,
		x509gost.OIDParamCryptoProC,
	}

	OID256Digits = []asn1.ObjectIdentifier{
		x509gost.OIDParamTC26_256A,
		x509gost.OIDParamTC26_256B,
		x509gost.OIDParamTC26_256C,
		x509gost.OIDParamTC26_256D,
	}

	OID512Digits = []asn1.ObjectIdentifier{
		x509gost.OIDParamTC26_512A,
		x509gost.OIDParamTC26_512B,
		x509gost.OIDParamTC26_512C,
	}
)

type SubjectBuilder struct {
	subject *Subject
}

func NewSubjectBuilder() *SubjectBuilder {
	return &SubjectBuilder{
		subject: &Subject{
			Information: SubjetInformation{},
			PublicKey:   SubjectPublicKey{},
		},
	}
}

func (sb *SubjectBuilder) WithCommonName(commonName string) *SubjectBuilder {
	sb.subject.Information.CommonName = commonName
	return sb
}

func (sb *SubjectBuilder) WithCountry(country []string) *SubjectBuilder {
	sb.subject.Information.Country = country
	return sb
}

func (sb *SubjectBuilder) WithOrganization(organization []string) *SubjectBuilder {
	sb.subject.Information.Organization = organization
	return sb
}

func (sb *SubjectBuilder) WithCurveOID(curveOID asn1.ObjectIdentifier) *SubjectBuilder {
	sb.subject.PublicKey.CurveOID = curveOID
	return sb
}

func (sb *SubjectBuilder) WithAlgorithm(algorithm x509gost.GOSTAlgorithm) *SubjectBuilder {
	sb.subject.PublicKey.Algorithm = algorithm
	return sb
}

func (sb *SubjectBuilder) WithPublicKey(rawPublicKey []byte) *SubjectBuilder {
	sb.subject.PublicKey.RawPublicKey = rawPublicKey
	return sb
}

func (sb *SubjectBuilder) Build() (*Subject, error) {
	if sb.subject.PublicKey.CurveOID == nil {
		return nil, fmt.Errorf("curve oid is required")
	}

	if sb.subject.PublicKey.RawPublicKey == nil {
		return nil, fmt.Errorf("raw public key is required")
	}

	// validate that curve oid forbidden
	err := sb.validateCurveOID()
	if err != nil {
		return nil, fmt.Errorf("build issuer: %w", err)
	}

	// check curve oid and algo digit
	err = sb.validateCurveOIDAndAlgorithmDigit()
	if err != nil {
		return nil, fmt.Errorf("build issuer: %w", err)
	}

	// check length of keys by algo digit
	err = sb.validatePublicKeyLength()
	if err != nil {
		return nil, fmt.Errorf("build issuer: %w", err)
	}

	return sb.subject, nil
}

func (sb *SubjectBuilder) validateCurveOID() error {
	for _, oid := range UnavailableAlgorithms {
		if sb.subject.PublicKey.CurveOID.Equal(oid) {
			return ForbiddenError
		}
	}
	return nil
}

func (sb *SubjectBuilder) validatePublicKeyLength() error {
	algoDigit, err := GetDigitByAlgorithm(sb.subject.PublicKey.Algorithm)
	if err != nil {
		return err
	}

	// A 256-bit curve expects a 64-byte public key (LE(x)||LE(y)), a 512-bit
	// curve a 128-byte key. Any other length is rejected.
	wantLen := 64
	if algoDigit == 512 {
		wantLen = 128
	}

	if len(sb.subject.PublicKey.RawPublicKey) != wantLen {
		return InvalidPublicKeyLength
	}

	return nil
}

func (sb *SubjectBuilder) validateCurveOIDAndAlgorithmDigit() error {
	curveDigit, err := GetDigitByCurveOID(sb.subject.PublicKey.CurveOID)
	if err != nil {
		return err
	}

	algoDigit, err := GetDigitByAlgorithm(sb.subject.PublicKey.Algorithm)
	if err != nil {
		return err
	}

	if algoDigit != curveDigit {
		return ForbiddenError
	}

	return nil
}

func GetDigitByCurveOID(curveOID asn1.ObjectIdentifier) (int, error) {
	for _, oid := range OID256Digits {
		if curveOID.Equal(oid) {
			return 256, nil
		}
	}

	for _, oid := range OID512Digits {
		if curveOID.Equal(oid) {
			return 512, nil
		}
	}

	return 0, ForbiddenError
}

func GetDigitByAlgorithm(algo x509gost.GOSTAlgorithm) (int, error) {
	switch algo {
	case x509gost.AlgoR341012_256:
		return 256, nil
	case x509gost.AlgoR341012_512:
		return 512, nil
	default:
		return 0, ForbiddenError
	}
}
