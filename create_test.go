package gostcert

import (
	"crypto/rand"
	"encoding/asn1"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/nxsgrp/gostcert/gost"
	"github.com/nxsgrp/gostcert/internal"
	"github.com/nxsgrp/gostcert/options"
	"github.com/stretchr/testify/assert"
	"github.com/tarantool/go-gostcrypto"
	"github.com/tarantool/go-gostcrypto/x509gost"
)

func TestCreateCertificate_SelfSigned(t *testing.T) {
	// Generate a random 20-byte serial number (matching OpenSSL convention).
	serialNumber, err := generateSerialNumber()
	assert.NoError(t, err, "unexpected error while generating serial number")

	// Use the CryptoPro-A curve parameter set (matches the reference openssl-generated certificate).
	curveOID := gost.OIDParamTC26_256A
	rawPrivateKey, rawPublicKey, err := generateEphemeralKey(curveOID)
	assert.NoError(t, err, "unexpected error while generating ephemeral key")
	assert.NoError(t, err, "failed to generate ephemeral key")
	assert.NotNil(t, rawPublicKey, "failed to generate public key")
	assert.NotEmpty(t, rawPublicKey, "expected public key is not empty")
	assert.NotNil(t, rawPrivateKey, "failed to generate private key")
	assert.NotEmpty(t, rawPrivateKey, "expected private key is not empty")

	signer, err := internal.BuildSigner(curveOID, rawPrivateKey)
	assert.NoError(t, err, "failed to build signer")

	opts := &options.CreateCertificateOptions{
		SerialNumber: serialNumber,
		TTL:          365 * 24 * time.Hour,

		Subject: options.SubjectOptions{
			Information: options.SubjetInformationOptions{
				CommonName:   "GOST R 34.10-2012 Test Certificate",
				Country:      []string{"RU"},
				Organization: []string{"Test"},
			},
			PublicKeyOptions: options.SubjectPublicKeyOptions{
				CurveOID:     curveOID,
				Algorithm:    gost.AlgoR341012_256,
				RawPublicKey: rawPublicKey,
			},
		},
		Issuer: options.IssuerOptions{
			RandReader:        rand.Reader,
			Signer:            signer,
			SignAlgorithm:     gost.AlgoR341012_256,
			ParentCertificate: nil,
		},
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
	//chains, err := cert.cert.Verify(x509gost.VerifyOptions{
	//	GOSTRoots: []*x509gost.Certificate{cert.cert},
	//})
	//assert.NoError(t, err, "failed to verify certificate")
	//assert.NotEmpty(t, chains, "expected certificate chains is not empty")
}

func generateSerialNumber() (*big.Int, error) {
	serialBytes := make([]byte, 20)
	_, err := rand.Read(serialBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	serialNumber := new(big.Int).SetBytes(serialBytes)
	return serialNumber, nil
}

func generateEphemeralKey(curveOID asn1.ObjectIdentifier) ([]byte, []byte, error) {
	curveObject, err := gostcrypto.CurveByOID(curveOID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get curve object: %w", err)
	}

	privRaw, pubRaw, err := gostcrypto.GenerateEphemeralKey(curveObject, rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	return pubRaw, privRaw, nil
}
