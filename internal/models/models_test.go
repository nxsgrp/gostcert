package models

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tarantool/go-gostcrypto/x509gost"
)

func TestSubjectBuilder(t *testing.T) {
	//nolint
	subject, err := NewSubjectBuilder().
		WithCommonName("Test CN").
		WithCountry([]string{"RU"}).
		WithOrganization([]string{"Test"}).
		WithCurveOID(x509gost.OIDParamTC26_256A).
		WithAlgorithm(x509gost.AlgoR341012_256).
		WithPublicKey(keyLen(64)).
		Build()
	require.NoError(t, err)

	name := subject.GetPkixName()
	assert.Equal(t, "Test CN", name.CommonName)
	assert.Equal(t, []string{"RU"}, name.Country)
	assert.Equal(t, []string{"Test"}, name.Organization)

	assert.Equal(t, "Test CN", subject.Information.CommonName)
	assert.Equal(t, []string{"RU"}, subject.Information.Country)
	assert.Equal(t, []string{"Test"}, subject.Information.Organization)
	assert.Equal(t, x509gost.OIDParamTC26_256A, subject.PublicKey.CurveOID)
	assert.Equal(t, x509gost.AlgoR341012_256, subject.PublicKey.Algorithm)
	assert.Equal(t, keyLen(64), subject.PublicKey.RawPublicKey)
}

func TestSubjectBuilderWithEmptyPublicKey(t *testing.T) {
	subject, err := NewSubjectBuilder().
		WithCommonName("Test CN").
		WithCountry([]string{"RU"}).
		WithOrganization([]string{"Test"}).
		Build()
	require.Error(t, err)
	require.Nil(t, subject)
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

func TestSubjectBuilderWithForbiddenAlgorithm(t *testing.T) {
	subject, err := NewSubjectBuilder().
		WithCommonName("Test CN").
		WithCountry([]string{"RU"}).
		WithOrganization([]string{"Test"}).
		WithCurveOID(x509gost.OIDParamTC26_256A).
		WithAlgorithm(x509gost.AlgoR341001).
		WithPublicKey([]byte{0x01, 0x02, 0x03}).
		Build()

	require.Error(t, err)
	require.Nil(t, subject)
}

func TestSubjectBuilderWithForbiddenCurve(t *testing.T) {
	subject, err := NewSubjectBuilder().
		WithCommonName("Test CN").
		WithCountry([]string{"RU"}).
		WithOrganization([]string{"Test"}).
		WithCurveOID(x509gost.OIDParamCryptoProA).
		WithAlgorithm(x509gost.AlgoR341012_256).
		WithPublicKey([]byte{0x01, 0x02, 0x03}).
		Build()

	require.Error(t, err)
	require.Nil(t, subject)
}

// buildSubject is a helper that constructs a Subject with the given curve OID,
// algorithm and raw public key (lengths are chosen by the caller so the key
// length / digit validations can be exercised independently).
func buildSubject(curveOID asn1.ObjectIdentifier, algo x509gost.GOSTAlgorithm, pubKey []byte) (*Subject, error) {
	return NewSubjectBuilder().
		WithCommonName("Test CN").
		WithCountry([]string{"RU"}).
		WithOrganization([]string{"Test"}).
		WithCurveOID(curveOID).
		WithAlgorithm(algo).
		WithPublicKey(pubKey).
		Build()
}

// keyLen returns a pubkey of exactly n bytes so key-length validation can be
// triggered with a precise value.
func keyLen(n int) []byte {
	return make([]byte, n)
}

func TestSubjectBuilderValid256(t *testing.T) {
	subject, err := buildSubject(x509gost.OIDParamTC26_256A, x509gost.AlgoR341012_256, keyLen(64))
	require.NoError(t, err)
	require.NotNil(t, subject)
}

func TestSubjectBuilderValid512(t *testing.T) {
	subject, err := buildSubject(x509gost.OIDParamTC26_512A, x509gost.AlgoR341012_512, keyLen(128))
	require.NoError(t, err)
	require.NotNil(t, subject)
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
			subject, err := buildSubject(tt.curve, tt.algo, tt.pub)
			require.Error(t, err)
			require.Nil(t, subject)
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
			subject, err := buildSubject(tt.curve, tt.algo, tt.pub)
			require.Error(t, err)
			require.Nil(t, subject)
			require.ErrorIs(t, err, ErrInvalidPublicKeyLength)
		})
	}
}

// TestSubjectBuilderUnknownCurve verifies that a curve OID outside the
// supported 256/512 sets is rejected.
func TestSubjectBuilderUnknownCurve(t *testing.T) {
	unknown := asn1.ObjectIdentifier{1, 2, 3, 4, 5}

	subject, err := buildSubject(unknown, x509gost.AlgoR341012_256, keyLen(64))
	require.Error(t, err)
	require.Nil(t, subject)
	require.ErrorIs(t, err, ErrForbidden)
}
