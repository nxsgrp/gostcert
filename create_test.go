package gostcert

import (
	"crypto/rand"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/nxsgrp/gostcert/internal"
	"github.com/nxsgrp/gostcert/internal/options"
	"github.com/stretchr/testify/assert"
	gost "github.com/tarantool/go-gostcrypto"
	"github.com/tarantool/go-gostcrypto/x509gost"
)

const (
	newTestCertPath = "test/resources/certs/created-certificate.der"
)

func TestCreateCertificate_SelfSigned(t *testing.T) {
	// Generate a random 20-byte serial number (matching OpenSSL convention).
	serialBytes := make([]byte, 20)
	_, err := rand.Read(serialBytes)
	assert.NoError(t, err, "failed to generate serial number")
	serialNumber := new(big.Int).SetBytes(serialBytes)

	// Use the CryptoPro-A curve parameter set (matches the reference
	// openssl-generated certificate).
	curveOID := x509gost.OIDParamCryptoProA
	curve, err := gost.CurveByOID(curveOID)
	assert.NoError(t, err, "failed to generate curve oid")

	privRaw, pubRaw, err := gost.GenerateEphemeralKey(curve, rand.Reader)
	assert.NoError(t, err, "failed to generate ephemeral key")
	assert.NotNil(t, pubRaw, "failed to generate public key")
	assert.NotEmpty(t, pubRaw, "expected public key is not empty")
	assert.NotNil(t, privRaw, "failed to generate private key")
	assert.NotEmpty(t, privRaw, "expected private key is not empty")

	signer := &internal.Signer{RawPrivateKey: privRaw, CurveOID: curveOID}

	opts := &options.CreateCertificateOptions{
		SerialNumber: serialNumber,

		Subject: options.SubjectOptions{
			CommonName:   "GOST R 34.10-2012 Test Certificate",
			Country:      []string{"RU"},
			Organization: []string{"Test"},
		},

		Crypto: options.CryptoOptions{
			CurveOID: curveOID,
			Signer:   signer,

			RandReader: rand.Reader,

			Algorithm:     x509gost.AlgoR341012_256,
			SignAlgorithm: x509gost.AlgoR341012_256,
		},

		RawPrivateKey: privRaw,
		RawPublicKey:  pubRaw,

		TTL: 365 * 24 * time.Hour,
	}

	cert, err := CreateCertificate(opts)
	assert.NoError(t, err, "failed to create certificate")
	assert.NotNil(t, cert, "test cert should not be nil")
	assert.NotNil(t, cert.cert.IsGOST, "expected GOST certificate")
	assert.NotNil(t, cert.cert.Stdlib, "expected parsed Stdlib")
	assert.NotEmpty(t, cert.cert.Raw, "expected cert raw bytes is not empty")
	assert.NotEmpty(t, cert.cert.PubKeyRaw, "expected cert public key is not empty")
	assert.NotEmpty(t, cert.cert.Stdlib.Subject.CommonName, "expected subject common name is not empty")
	assert.Equal(t, cert.cert.GOSTAlgo, x509gost.AlgoR341012_256, "expected AlgoR341012_256 algorithm")
	assert.Equal(t, cert.cert.SigGOSTAlgo, x509gost.AlgoR341012_256, "expected AlgoR341012_256 signature algorithm")

	// Verify via x509gost
	chains, err := cert.cert.Verify(x509gost.VerifyOptions{
		GOSTRoots: []*x509gost.Certificate{cert.cert},
	})
	assert.NoError(t, err, "failed to verify certificate")
	assert.NotEmpty(t, chains, "expected certificate chains is not empty")

	// FIX: Remove after handle testing
	err = os.WriteFile(newTestCertPath, cert.cert.Raw, 0600)
	assert.NoError(t, err, "failed to write new test certificate")
}
