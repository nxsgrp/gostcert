package internal

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gost "github.com/tarantool/go-gostcrypto"
	"github.com/tarantool/go-gostcrypto/x509gost"
)

func TestSignerPublic(t *testing.T) {
	curve, err := gost.CurveByOID(x509gost.OIDParamCryptoProA)
	require.NoError(t, err)

	privRaw, pubRaw, err := gost.GenerateEphemeralKey(curve, rand.Reader)
	require.NoError(t, err)

	signer, err := BuildSigner(x509gost.OIDParamCryptoProA, privRaw)
	require.NoError(t, err, "failed to build signer")

	// Signer.Public() must agree with the key independently derived from the same private scalar.
	assert.Equal(t, pubRaw, signer.Public(), "derived public key mismatch")

	// CryptoPro-A is a 256-bit curve, so the public key is LE(X)||LE(Y), i.e. two 32-byte coordinates.
	assert.Len(t, pubRaw, 64, "256-bit GOST public key must be 64 bytes")
}

func TestSignerSign(t *testing.T) {
	curve, err := gost.CurveByOID(x509gost.OIDParamCryptoProA)
	require.NoError(t, err)

	privRaw, pubRaw, err := gost.GenerateEphemeralKey(curve, rand.Reader)
	require.NoError(t, err)

	signer, err := BuildSigner(x509gost.OIDParamCryptoProA, privRaw)
	require.NoError(t, err, "failed to build signer")

	// Sign only accepts a little-endian digest as produced by HashForGOST.
	digest, err := HashForGOST(x509gost.AlgoR341012_256, []byte("sign me"))
	require.NoError(t, err)

	digestBE := SwapEndianBytes(digest)

	sig, err := signer.Sign(rand.Reader, digestBE, nil)
	require.NoError(t, err)
	assert.Len(t, sig, 64, "GOST R 34.10-2012 256-bit signature must be 64 bytes")

	// The signature must independently verify against the signer's own
	// public key.
	ok, err := gost.VerifyDigestOnCurve(curve, pubRaw, digestBE, sig)
	require.NoError(t, err)
	assert.True(t, ok, "signature must verify against the signer's public key")
}
