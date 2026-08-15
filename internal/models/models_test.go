package models

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tarantool/go-gostcrypto/x509gost"
)

func TestSubjectBuilder(t *testing.T) {
	subject, err := NewSubjectBuilder().
		WithCommonName("Test CN").
		WithCountry([]string{"RU"}).
		WithOrganization([]string{"Test"}).
		WithCurveOID(x509gost.OIDParamTC26_256A).
		WithAlgorithm(x509gost.AlgoR341012_256).
		WithPublicKey([]byte{0x01, 0x02, 0x03}).
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
	assert.Equal(t, []byte{0x01, 0x02, 0x03}, subject.PublicKey.RawPublicKey)
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
