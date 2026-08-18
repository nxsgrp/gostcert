package models

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/tarantool/go-gostcrypto/x509gost"
)

var (
	ErrForbidden              = errors.New("the GOST R 34.10-2001 algorithm was not supported")
	ErrInvalidPublicKeyLength = errors.New("invalid public key length for algorithm")

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

type Subject struct {
	Information SubjetInformation
	PublicKey   SubjectPublicKey
}

func CreateSubject(information SubjetInformation, publicKey SubjectPublicKey) *Subject {
	return &Subject{
		Information: information,
		PublicKey:   publicKey,
	}
}

func (s *Subject) GetPkixName() pkix.Name {
	return pkix.Name{
		CommonName:   s.Information.CommonName,
		Country:      s.Information.Country,
		Organization: s.Information.Organization,
	}
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

func CreateSubjectInformation(commonName string, country, organization []string) (SubjetInformation, error) {
	var subInfo SubjetInformation
	subInfo = SubjetInformation{
		CommonName:   commonName,
		Country:      country,
		Organization: organization,
	}

	err := subInfo.validate()
	if err != nil {
		return subInfo, fmt.Errorf("validating subject info: %w", err)
	}

	return subInfo, nil
}

func (si *SubjetInformation) validate() error {
	if si.CommonName == "" {
		return fmt.Errorf("common name is required")
	}

	if len(si.Country) == 0 {
		return fmt.Errorf("country is required")
	}

	if len(si.Organization) == 0 {
		return fmt.Errorf("organization is required")
	}

	return nil
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

func CreateSubjectPublicKey(
	curveOID asn1.ObjectIdentifier,
	algorithm x509gost.GOSTAlgorithm,
	rawPublicKey []byte,
) (SubjectPublicKey, error) {
	var subPublicKey SubjectPublicKey
	subPublicKey = SubjectPublicKey{
		Algorithm:    algorithm,
		CurveOID:     curveOID,
		RawPublicKey: rawPublicKey,
	}

	err := subPublicKey.validate()
	if err != nil {
		return subPublicKey, fmt.Errorf("validating subject public key: %w", err)
	}

	return subPublicKey, nil
}

func (spk *SubjectPublicKey) validate() error {
	if spk.CurveOID == nil {
		return fmt.Errorf("curve oid is required")
	}

	if spk.RawPublicKey == nil {
		return fmt.Errorf("raw public key is required")
	}

	// validate that curve oid forbidden
	err := spk.validateCurveOID()
	if err != nil {
		return fmt.Errorf("build issuer: %w", err)
	}

	// check curve oid and algo digit
	err = spk.validateCurveOIDAndAlgorithmDigit()
	if err != nil {
		return fmt.Errorf("build issuer: %w", err)
	}

	// check length of keys by algo digit
	err = spk.validatePublicKeyLength()
	if err != nil {
		return fmt.Errorf("build issuer: %w", err)
	}

	return nil
}

func (spk *SubjectPublicKey) validateCurveOID() error {
	for _, oid := range UnavailableAlgorithms {
		if spk.CurveOID.Equal(oid) {
			return ErrForbidden
		}
	}
	return nil
}

func (spk *SubjectPublicKey) validatePublicKeyLength() error {
	algoDigit, err := getDigitByAlgorithm(spk.Algorithm)
	if err != nil {
		return err
	}

	// A 256-bit curve expects a 64-byte public key (LE(x)||LE(y)), a 512-bit
	// curve a 128-byte key. Any other length is rejected.
	wantLen := 64
	if algoDigit == 512 {
		wantLen = 128
	}

	if len(spk.RawPublicKey) != wantLen {
		return ErrInvalidPublicKeyLength
	}

	return nil
}

func (spk *SubjectPublicKey) validateCurveOIDAndAlgorithmDigit() error {
	curveDigit, err := getDigitByCurveOID(spk.CurveOID)
	if err != nil {
		return err
	}

	algoDigit, err := getDigitByAlgorithm(spk.Algorithm)
	if err != nil {
		return err
	}

	if algoDigit != curveDigit {
		return ErrForbidden
	}

	return nil
}

func getDigitByCurveOID(curveOID asn1.ObjectIdentifier) (int, error) {
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

	return 0, ErrForbidden
}

func getDigitByAlgorithm(algo x509gost.GOSTAlgorithm) (int, error) {
	//nolint
	switch algo {
	case x509gost.AlgoR341012_256:
		return 256, nil
	case x509gost.AlgoR341012_512:
		return 512, nil
	default:
		return 0, ErrForbidden
	}
}
