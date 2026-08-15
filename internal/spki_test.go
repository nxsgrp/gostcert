package internal

import (
	"crypto/rand"
	"encoding/asn1"
	"testing"

	"github.com/nxsgrp/gostcert/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gost "github.com/tarantool/go-gostcrypto"
	"github.com/tarantool/go-gostcrypto/x509gost"
)

// newTestPublicKey generates a fresh GOST public key on the CryptoPro-A curve
// (the same curve used across the certificate tests).
func newTestPublicKey(t *testing.T) (curveOID asn1.ObjectIdentifier, pubRaw []byte) {
	t.Helper()
	curveOID = x509gost.OIDParamCryptoProA
	curve, err := gost.CurveByOID(curveOID)
	require.NoError(t, err)
	_, pubRaw, err = gost.GenerateEphemeralKey(curve, rand.Reader)
	require.NoError(t, err)
	require.NotEmpty(t, pubRaw, "generated public key must not be empty")
	return curveOID, pubRaw
}

func TestBuildSPKI(t *testing.T) {
	curveOID, pubRaw := newTestPublicKey(t)

	spkiDER, err := BuildSPKI(models.SubjectPublicKey{
		CurveOID:     curveOID,
		Algorithm:    x509gost.AlgoR341012_256,
		RawPublicKey: pubRaw,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, spkiDER, "SPKI DER must not be empty")

	// The SPKI must round-trip to a SubjectPublicKeyInfo whose algorithm OID
	// is the GOST public key OID and whose Parameters carry the curve OID.
	var spki subjectPublicKeyInfo
	rest, err := asn1.Unmarshal(spkiDER, &spki)
	require.NoError(t, err)
	require.Empty(t, rest, "SPKI DER should contain exactly one element")
	assert.Equal(t, x509gost.OIDPublicKeyGOSTR341012_256, spki.Algorithm.Algorithm,
		"public key algorithm OID mismatch")

	var params gostSPKIParameters
	_, err = asn1.Unmarshal(spki.Algorithm.Parameters.FullBytes, &params)
	require.NoError(t, err, "SPKI parameters must be a valid gostSPKIParameters")
	assert.Equal(t, curveOID, params.CurveOID, "curve OID in SPKI parameters mismatch")
	assert.Equal(t, x509gost.OIDHashStreebog256, params.DigestOID, "digest OID in SPKI parameters mismatch")
}

func TestBuildSPKI_UnknownAlgorithm(t *testing.T) {
	_, err := BuildSPKI(models.SubjectPublicKey{
		Algorithm: x509gost.GOSTAlgorithm(999),
	})
	assert.Error(t, err, "unknown algorithm must return an error")
}

func TestBuildSignatureAlgorithm(t *testing.T) {
	sigAlgoDER, err := BuildSignatureAlgorithm(x509gost.AlgoR341012_256)
	require.NoError(t, err)
	assert.NotEmpty(t, sigAlgoDER, "signature AlgorithmIdentifier DER must not be empty")

	var decoded derEncodedAlgorithmIdentifier
	rest, err := asn1.Unmarshal(sigAlgoDER, &decoded)
	require.NoError(t, err)
	require.Empty(t, rest, "signature AlgorithmIdentifier DER should contain exactly one element")
	assert.Equal(t, x509gost.OIDSignatureGOSTR341012_256, decoded.AlgorithmIdentifier,
		"signature algorithm OID mismatch")
}

func TestGostAlgorithmToOID(t *testing.T) {
	cases := []struct {
		name string
		algo x509gost.GOSTAlgorithm
		want asn1.ObjectIdentifier
	}{
		{"r341001", x509gost.AlgoR341001, x509gost.OIDPublicKeyGOSTR341001},
		{"streebog256", x509gost.AlgoR341012_256, x509gost.OIDPublicKeyGOSTR341012_256},
		{"streebog512", x509gost.AlgoR341012_512, x509gost.OIDPublicKeyGOSTR341012_512},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := OIDPublicKeyByGostAlgorithm(tc.algo)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}

	_, err := OIDPublicKeyByGostAlgorithm(x509gost.GOSTAlgorithm(999))
	assert.Error(t, err, "unknown algorithm must return an error")
}

func TestGostSignatureAlgorithmToOID(t *testing.T) {
	cases := []struct {
		name string
		algo x509gost.GOSTAlgorithm
		want asn1.ObjectIdentifier
	}{
		{"r341001", x509gost.AlgoR341001, x509gost.OIDSignatureGOSTR341001},
		{"streebog256", x509gost.AlgoR341012_256, x509gost.OIDSignatureGOSTR341012_256},
		{"streebog512", x509gost.AlgoR341012_512, x509gost.OIDSignatureGOSTR341012_512},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := OIDSignatureAlgorithmByGostAlgorithm(tc.algo)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}

	_, err := OIDSignatureAlgorithmByGostAlgorithm(x509gost.GOSTAlgorithm(999))
	assert.Error(t, err, "unknown algorithm must return an error")
}

func TestGostDigestAlgorithmToOID(t *testing.T) {
	cases := []struct {
		name string
		algo x509gost.GOSTAlgorithm
		want asn1.ObjectIdentifier
	}{
		{"r341001", x509gost.AlgoR341001, x509gost.OIDHashGOSTR341194},
		{"streebog256", x509gost.AlgoR341012_256, x509gost.OIDHashStreebog256},
		{"streebog512", x509gost.AlgoR341012_512, x509gost.OIDHashStreebog512},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := GostDigestAlgorithmToOID(tc.algo)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}

	_, err := GostDigestAlgorithmToOID(x509gost.GOSTAlgorithm(999))
	assert.Error(t, err, "unknown algorithm must return an error")
}

func TestGostDigestFromCurveOID(t *testing.T) {
	tests := []struct {
		name  string
		curve asn1.ObjectIdentifier
		want  asn1.ObjectIdentifier // nil => digestParamSet omitted
	}{
		// MUST: Streebog-256 present for the GOST R 34.10-2001 sets.
		{"testParamSet", oidParamCryptoProTest, x509gost.OIDHashStreebog256},
		{"cryptoproA", x509gost.OIDParamCryptoProA, x509gost.OIDHashStreebog256},
		{"cryptoproB", x509gost.OIDParamCryptoProB, x509gost.OIDHashStreebog256},
		{"cryptoproC", x509gost.OIDParamCryptoProC, x509gost.OIDHashStreebog256},
		{"xchA", oidParamCryptoProXchA, x509gost.OIDHashStreebog256},
		{"xchB", oidParamCryptoProXchB, x509gost.OIDHashStreebog256},

		// TC26 256-bit sets: omitted (SHOULD for paramSetA, MUST for B/C/D).
		{"paramSetA", x509gost.OIDParamTC26_256A, nil},
		{"paramSetB", x509gost.OIDParamTC26_256B, nil},
		{"paramSetC", x509gost.OIDParamTC26_256C, nil},
		{"paramSetD", x509gost.OIDParamTC26_256D, nil},

		// TC26 512-bit sets: omitted (SHOULD).
		{"512A", x509gost.OIDParamTC26_512A, nil},
		{"512B", x509gost.OIDParamTC26_512B, nil},
		{"512 test", oidParamTC26_512Test, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GostDigestFromCurveOID(tt.curve, x509gost.AlgoR341012_256)
			require.NoError(t, err)

			if tt.want == nil {
				assert.Nil(t, got, "digestParamSet should be omitted (nil)")
			} else {
				assert.Equal(t, tt.want, got, "digestParamSet OID mismatch")
			}
		})
	}
}
