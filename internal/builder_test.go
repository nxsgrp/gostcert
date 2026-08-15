package internal

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/nxsgrp/gostcert/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tarantool/go-gostcrypto/x509gost"
)

// countSequenceChildren parses der as a SEQUENCE and returns the number of
// top-level child elements it contains.
func countSequenceChildren(t *testing.T, der []byte) int {
	t.Helper()

	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(der, &raw)
	require.NoError(t, err, "DER must parse as a single value")
	require.Empty(t, rest, "DER must not have trailing bytes")
	require.Equal(t, asn1.TagSequence, raw.Tag, "DER must be a SEQUENCE")

	children, data := 0, raw.Bytes
	for len(data) > 0 {
		var child asn1.RawValue
		data, err = asn1.Unmarshal(data, &child)
		require.NoError(t, err)
		children++
	}
	return children
}

func TestBuildTBSCertificate(t *testing.T) {
	curveOID, pubRaw := newTestPublicKey(t)

	subject := &models.Subject{
		Information: models.SubjetInformation{
			CommonName:   "Test Certificate",
			Country:      []string{"RU"},
			Organization: []string{"Test"},
		},
		PublicKey: models.SubjectPublicKey{
			CurveOID:     curveOID,
			Algorithm:    x509gost.AlgoR341012_256,
			RawPublicKey: pubRaw,
		},
	}

	// No ParentCertificate -> self-issued (Issuer == Subject).
	issuer := &models.Issuer{SignAlgorithm: x509gost.AlgoR341012_256}
	certInfo := &models.CertificateInformation{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	sigAlgoDER, err := BuildSignatureAlgorithm(x509gost.AlgoR341012_256)
	require.NoError(t, err)

	tbsBody, err := BuildTBSCertificate(certInfo, subject, issuer, sigAlgoDER)
	require.NoError(t, err)
	assert.NotEmpty(t, tbsBody, "TBS body must not be empty")

	// The wrapped TBS SEQUENCE must contain exactly the seven RFC 5280
	// fields in order: version, serial, signature, issuer, validity,
	// subject, subjectPublicKeyInfo.
	wrapped, err := BuildTBSCertificateRawValue(tbsBody)
	require.NoError(t, err)
	assert.Equal(t, 7, countSequenceChildren(t, wrapped),
		"TBS certificate must contain exactly 7 top-level fields")
}

func TestBuildTBSCertificateRawValue(t *testing.T) {
	body := []byte{0x02, 0x01, 0x05} // arbitrary SEQUENCE body

	der, err := BuildTBSCertificateRawValue(body)
	require.NoError(t, err)

	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(der, &raw)
	require.NoError(t, err)
	require.Empty(t, rest)
	assert.Equal(t, asn1.TagSequence, raw.Tag, "must be a SEQUENCE")
	assert.True(t, raw.IsCompound)
	assert.Equal(t, body, raw.Bytes, "SEQUENCE content must round-trip")
}

func TestBuildSigBitString(t *testing.T) {
	sig := []byte{0xde, 0xad, 0xbe, 0xef}

	der, err := BuildSigBitString(sig)
	require.NoError(t, err)

	var bs asn1.BitString
	rest, err := asn1.Unmarshal(der, &bs)
	require.NoError(t, err)
	require.Empty(t, rest)
	assert.Equal(t, sig, bs.Bytes, "BIT STRING bytes must round-trip")
	assert.Equal(t, len(sig)*8, bs.BitLength, "bit length must reflect byte count")
}

func TestBuildSigCertificateRawValue(t *testing.T) {
	body := []byte{0x02, 0x01, 0x07} // arbitrary SEQUENCE body

	der, err := BuildSigCertificateRawValue(body)
	require.NoError(t, err)

	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(der, &raw)
	require.NoError(t, err)
	require.Empty(t, rest)
	assert.Equal(t, asn1.TagSequence, raw.Tag, "must be a SEQUENCE")
	assert.True(t, raw.IsCompound)
	assert.Equal(t, body, raw.Bytes, "SEQUENCE content must round-trip")
}

func TestBuildExtensions(t *testing.T) {
	t.Run("empty produces nothing", func(t *testing.T) {
		der, err := BuildExtensions(nil)
		assert.NoError(t, err)
		assert.Nil(t, der, "no extensions must produce nil DER")
	})

	t.Run("non-empty round-trips", func(t *testing.T) {
		in := []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: []byte{0x30, 0x00}},
		}

		der, err := BuildExtensions(in)
		require.NoError(t, err)
		assert.NotEmpty(t, der)

		// The result is wrapped in [3] EXPLICIT SEQUENCE OF Extension.
		var raw asn1.RawValue
		rest, err := asn1.Unmarshal(der, &raw)
		require.NoError(t, err)
		require.Empty(t, rest)
		assert.Equal(t, asn1.ClassContextSpecific, raw.Class)
		assert.Equal(t, 3, raw.Tag)

		var got []pkix.Extension
		_, err = asn1.Unmarshal(raw.Bytes, &got)
		require.NoError(t, err)
		assert.Len(t, got, len(in))
		assert.Equal(t, in[0].Id, got[0].Id)
		assert.Equal(t, in[0].Critical, got[0].Critical)
		assert.Equal(t, in[0].Value, got[0].Value)
	})
}

func TestConcatBytes(t *testing.T) {
	t.Run("concatenates in order", func(t *testing.T) {
		got := ConcatBytes([]byte("ab"), []byte("c"), []byte("def"))
		assert.Equal(t, []byte("abcdef"), got)
	})

	t.Run("single part", func(t *testing.T) {
		assert.Equal(t, []byte("solo"), ConcatBytes([]byte("solo")))
	})

	t.Run("empty yields empty", func(t *testing.T) {
		assert.Empty(t, ConcatBytes())
		assert.Empty(t, ConcatBytes([]byte{}, []byte{}))
	})
}
