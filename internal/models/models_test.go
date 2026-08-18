package models

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tarantool/go-gostcrypto/x509gost"
)

const (
	testCommonName   = "Test CN"
	testCountry      = "RU"
	testOrganization = "Test"
)

func TestSubjectBuilder(t *testing.T) {
	subjectInfo, err := CreateSubjectInformation(testCommonName, []string{testCountry}, []string{testOrganization})
	require.NoError(t, err)

	subjectPublicKey, err := CreateSubjectPublicKey(
		x509gost.OIDParamTC26_256A,
		x509gost.AlgoR341012_256,
		keyLen(64),
	)
	require.NoError(t, err)

	subject := CreateSubject(subjectInfo, subjectPublicKey)
	require.NotNil(t, subject)

	name := subject.GetPkixName()
	assert.Equal(t, testCommonName, name.CommonName)
	assert.Equal(t, []string{testCountry}, name.Country)
	assert.Equal(t, []string{testOrganization}, name.Organization)

	assert.Equal(t, testCommonName, subject.Information.CommonName)
	assert.Equal(t, []string{testCountry}, subject.Information.Country)
	assert.Equal(t, []string{testOrganization}, subject.Information.Organization)
	assert.Equal(t, x509gost.OIDParamTC26_256A, subject.PublicKey.CurveOID)
	assert.Equal(t, x509gost.AlgoR341012_256, subject.PublicKey.Algorithm)
	assert.Equal(t, keyLen(64), subject.PublicKey.RawPublicKey)
}

func TestCreateSubjectInformation(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		info, err := CreateSubjectInformation(testCommonName, []string{testCountry}, []string{testOrganization})
		require.NoError(t, err)
		assert.Equal(t, testCommonName, info.CommonName)
		assert.Equal(t, []string{testCountry}, info.Country)
		assert.Equal(t, []string{testOrganization}, info.Organization)
	})

	t.Run("missing common name", func(t *testing.T) {
		_, err := CreateSubjectInformation("", []string{testCountry}, []string{testOrganization})
		require.Error(t, err)
	})

	t.Run("missing country", func(t *testing.T) {
		_, err := CreateSubjectInformation(testCommonName, nil, []string{testOrganization})
		require.Error(t, err)
	})

	t.Run("missing organization", func(t *testing.T) {
		_, err := CreateSubjectInformation(testCommonName, []string{testCountry}, nil)
		require.Error(t, err)
	})
}

func TestSubjectBuilderWithForbiddenAlgorithm(t *testing.T) {
	_, err := CreateSubjectPublicKey(
		x509gost.OIDParamTC26_256A,
		x509gost.AlgoR341001,
		keyLen(64),
	)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrForbidden)
}

func TestSubjectBuilderWithForbiddenCurve(t *testing.T) {
	_, err := CreateSubjectPublicKey(
		x509gost.OIDParamCryptoProA,
		x509gost.AlgoR341012_256,
		keyLen(64),
	)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrForbidden)
}

func TestCreateSubjectPublicKeyRequiredFields(t *testing.T) {
	t.Run("missing curve oid", func(t *testing.T) {
		_, err := CreateSubjectPublicKey(nil, x509gost.AlgoR341012_256, keyLen(64))
		require.Error(t, err)
	})

	t.Run("missing raw public key", func(t *testing.T) {
		_, err := CreateSubjectPublicKey(x509gost.OIDParamTC26_256A, x509gost.AlgoR341012_256, nil)
		require.Error(t, err)
	})
}

func TestSubjectBuilderValid256(t *testing.T) {
	_, err := CreateSubjectPublicKey(x509gost.OIDParamTC26_256A, x509gost.AlgoR341012_256, keyLen(64))
	require.NoError(t, err)
}

func TestSubjectBuilderValid512(t *testing.T) {
	_, err := CreateSubjectPublicKey(x509gost.OIDParamTC26_512A, x509gost.AlgoR341012_512, keyLen(128))
	require.NoError(t, err)
}

// TestSubjectBuilderDigitMismatch verifies that mixing an algorithm and a curve
// of different bit widths (256 vs 512) is rejected.
func TestSubjectBuilderDigitMismatch(t *testing.T) {
	tests := []struct {
		name  string
		curve asn1.ObjectIdentifier
		algo  x509gost.GOSTAlgorithm
		pub   []byte
	}{
		{"curve512_algo256", x509gost.OIDParamTC26_512A, x509gost.AlgoR341012_256, keyLen(64)},
		{"curve256_algo512", x509gost.OIDParamTC26_256A, x509gost.AlgoR341012_512, keyLen(128)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CreateSubjectPublicKey(tt.curve, tt.algo, tt.pub)
			require.Error(t, err)
			require.ErrorIs(t, err, ErrForbidden)
		})
	}
}

// TestSubjectBuilderKeyLengthMismatch verifies that a public key whose byte
// length does not match the algorithm bit width is rejected. Each curve/algo
// pair shares the same digit so the length check is actually reached.
func TestSubjectBuilderKeyLengthMismatch(t *testing.T) {
	tests := []struct {
		name  string
		curve asn1.ObjectIdentifier
		algo  x509gost.GOSTAlgorithm
		pub   []byte // length that does NOT match the algo digit
	}{
		{"256_too_short", x509gost.OIDParamTC26_256A, x509gost.AlgoR341012_256, keyLen(32)},
		{"256_too_long", x509gost.OIDParamTC26_256A, x509gost.AlgoR341012_256, keyLen(96)},
		{"512_too_short", x509gost.OIDParamTC26_512A, x509gost.AlgoR341012_512, keyLen(64)},
		{"512_too_long", x509gost.OIDParamTC26_512A, x509gost.AlgoR341012_512, keyLen(160)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CreateSubjectPublicKey(tt.curve, tt.algo, tt.pub)
			require.Error(t, err)
			require.ErrorIs(t, err, ErrInvalidPublicKeyLength)
		})
	}
}

// TestSubjectBuilderUnknownCurve verifies that a curve OID outside the
// supported 256/512 sets is rejected.
func TestSubjectBuilderUnknownCurve(t *testing.T) {
	unknown := asn1.ObjectIdentifier{1, 2, 3, 4, 5}

	_, err := CreateSubjectPublicKey(unknown, x509gost.AlgoR341012_256, keyLen(64))
	require.Error(t, err)
	require.ErrorIs(t, err, ErrForbidden)
}

func TestIssuerGetParentCertificate(t *testing.T) {
	t.Run("nil when not set", func(t *testing.T) {
		issuer := &Issuer{}
		assert.Nil(t, issuer.GetParentCertificate())
	})

	t.Run("returns the set certificate", func(t *testing.T) {
		parent := &x509.Certificate{Subject: pkix.Name{CommonName: "Parent"}}
		issuer := &Issuer{ParentCertificate: parent}
		assert.Same(t, parent, issuer.GetParentCertificate())
	})
}

func TestCreateIssuer(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		issuer, err := CreateIssuer(rand.Reader, stubSigner{}, x509gost.AlgoR341012_256, nil)
		require.NoError(t, err)
		require.NotNil(t, issuer)
	})

	t.Run("nil rand reader", func(t *testing.T) {
		_, err := CreateIssuer(nil, stubSigner{}, x509gost.AlgoR341012_256, nil)
		require.Error(t, err)
	})

	t.Run("nil signer", func(t *testing.T) {
		_, err := CreateIssuer(rand.Reader, nil, x509gost.AlgoR341012_256, nil)
		require.Error(t, err)
	})

	t.Run("forbidden algorithm", func(t *testing.T) {
		_, err := CreateIssuer(rand.Reader, stubSigner{}, x509gost.AlgoR341001, nil)
		require.Error(t, err)
	})
}

func TestCreateCertificateInformation(t *testing.T) {
	now := time.Now()

	t.Run("valid", func(t *testing.T) {
		info, err := CreateCertificateInformation(big.NewInt(1), now, now.Add(time.Hour))
		require.NoError(t, err)
		require.NotNil(t, info)
		assert.Equal(t, big.NewInt(1), info.SerialNumber)
	})

	t.Run("missing serial number", func(t *testing.T) {
		_, err := CreateCertificateInformation(nil, now, now.Add(time.Hour))
		require.Error(t, err)
	})

	t.Run("not after before not before", func(t *testing.T) {
		_, err := CreateCertificateInformation(big.NewInt(1), now, now.Add(-time.Hour))
		require.Error(t, err)
	})
}

// keyLen returns a pubkey of exactly n bytes so key-length validation can be
// triggered with a precise value.
func keyLen(n int) []byte {
	return make([]byte, n)
}
