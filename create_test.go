package gostcert

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/nxsgrp/gostcert/internal"
	"github.com/nxsgrp/gostcert/options"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

		TTL:      365 * 24 * time.Hour,
		IsCA:     true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
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

func TestCreateCertificate_Chain_RootIntermediateLeaf(t *testing.T) {
	curveOID := x509gost.OIDParamCryptoProA
	curve, err := gost.CurveByOID(curveOID)
	require.NoError(t, err)

	// ── Generate keypairs for root, intermediate, leaf ──
	rootPriv, rootPub, err := gost.GenerateEphemeralKey(curve, rand.Reader)
	require.NoError(t, err)

	intermPriv, intermPub, err := gost.GenerateEphemeralKey(curve, rand.Reader)
	require.NoError(t, err)

	leafPriv, leafPub, err := gost.GenerateEphemeralKey(curve, rand.Reader)
	require.NoError(t, err)

	// ── 1. Create Root CA (self-signed, CA=true, pathLen=1) ──
	rootSerial := big.NewInt(1)
	pathLen1 := 1

	rootOpts := &options.CreateCertificateOptions{
		SerialNumber: rootSerial,
		Subject: options.SubjectOptions{
			CommonName: "GOST Root CA",
			Country:    []string{"RU"},
		},
		IsCA:              true,
		PathLenConstraint: &pathLen1,
		KeyUsage:          x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		Crypto: options.CryptoOptions{
			CurveOID:      curveOID,
			Signer:        &internal.Signer{RawPrivateKey: rootPriv, CurveOID: curveOID},
			RandReader:    rand.Reader,
			Algorithm:     x509gost.AlgoR341012_256,
			SignAlgorithm: x509gost.AlgoR341012_256,
		},
		RawPrivateKey: rootPriv,
		RawPublicKey:  rootPub,
		TTL:           365 * 24 * time.Hour,
	}

	rootCert, err := CreateCertificate(rootOpts)
	require.NoError(t, err)
	require.NotNil(t, rootCert)

	// Verify self-signed root
	_, err = rootCert.cert.Verify(x509gost.VerifyOptions{
		GOSTRoots: []*x509gost.Certificate{rootCert.cert},
	})
	require.NoError(t, err, "root CA self-verification failed")

	t.Logf("Root CA SubjectKeyId: %x", rootCert.StdCertificate().SubjectKeyId)

	// ── 2. Create Intermediate CA (parent=root, CA=true, pathLen=0) ──
	intermSerial := big.NewInt(2)
	pathLen0 := 0

	intermOpts := &options.CreateCertificateOptions{
		SerialNumber: intermSerial,
		Subject: options.SubjectOptions{
			CommonName: "GOST Intermediate CA",
			Country:    []string{"RU"},
		},
		IsCA:              true,
		PathLenConstraint: &pathLen0,
		KeyUsage:          x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ParentCertificate: rootCert.StdCertificate(),
		Crypto: options.CryptoOptions{
			CurveOID:      curveOID,
			Signer:        &internal.Signer{RawPrivateKey: rootPriv, CurveOID: curveOID},
			RandReader:    rand.Reader,
			Algorithm:     x509gost.AlgoR341012_256,
			SignAlgorithm: x509gost.AlgoR341012_256,
		},
		RawPrivateKey: intermPriv,
		RawPublicKey:  intermPub,
		TTL:           365 * 24 * time.Hour,
	}

	intermCert, err := CreateCertificate(intermOpts)
	require.NoError(t, err)
	require.NotNil(t, intermCert)

	t.Logf("Intermediate SubjectKeyId: %x", intermCert.StdCertificate().SubjectKeyId)
	t.Logf("Intermediate AuthorityKeyId: %x", intermCert.StdCertificate().AuthorityKeyId)

	// Verify AKI of intermediate matches SKI of root
	assert.Equal(t, rootCert.StdCertificate().SubjectKeyId,
		intermCert.StdCertificate().AuthorityKeyId,
		"intermediate AKI should match root SKI")

	// ── 3. Create Leaf (parent=intermediate, CA=false) ──
	leafSerial := big.NewInt(3)

	leafOpts := &options.CreateCertificateOptions{
		SerialNumber: leafSerial,
		Subject: options.SubjectOptions{
			CommonName: "GOST Leaf Certificate",
			Country:    []string{"RU"},
		},
		IsCA:              false,
		KeyUsage:          x509.KeyUsageDigitalSignature,
		ParentCertificate: intermCert.StdCertificate(),
		Crypto: options.CryptoOptions{
			CurveOID:      curveOID,
			Signer:        &internal.Signer{RawPrivateKey: intermPriv, CurveOID: curveOID},
			RandReader:    rand.Reader,
			Algorithm:     x509gost.AlgoR341012_256,
			SignAlgorithm: x509gost.AlgoR341012_256,
		},
		RawPrivateKey: leafPriv,
		RawPublicKey:  leafPub,
		TTL:           365 * 24 * time.Hour,
	}

	leafCert, err := CreateCertificate(leafOpts)
	require.NoError(t, err)
	require.NotNil(t, leafCert)

	t.Logf("Leaf SubjectKeyId: %x", leafCert.StdCertificate().SubjectKeyId)
	t.Logf("Leaf AuthorityKeyId: %x", leafCert.StdCertificate().AuthorityKeyId)

	// Verify AKI of leaf matches SKI of intermediate
	assert.Equal(t, intermCert.StdCertificate().SubjectKeyId,
		leafCert.StdCertificate().AuthorityKeyId,
		"leaf AKI should match intermediate SKI")

	// ── 4. Verify full chain ──
	chains, err := leafCert.cert.Verify(x509gost.VerifyOptions{
		GOSTRoots:         []*x509gost.Certificate{rootCert.cert},
		GOSTIntermediates: []*x509gost.Certificate{intermCert.cert},
	})
	require.NoError(t, err, "full chain verification failed")
	require.NotEmpty(t, chains, "expected at least one chain")

	t.Logf("Chain verified successfully, %d chains found", len(chains))
	for i, chain := range chains {
		t.Logf("Chain %d:", i)
		for j, c := range chain {
			t.Logf("  [%d] %s", j, c.Stdlib.Subject.CommonName)
		}
	}

	// ── 5. Verify that root cannot verify leaf directly (no intermediates) ──
	_, err = leafCert.cert.Verify(x509gost.VerifyOptions{
		GOSTRoots: []*x509gost.Certificate{rootCert.cert},
	})
	require.Error(t, err, "leaf should not verify without intermediate")
}

func TestCreateCertificate_WithExtraExtensions(t *testing.T) {
	curveOID := x509gost.OIDParamCryptoProA
	curve, err := gost.CurveByOID(curveOID)
	require.NoError(t, err)

	priv, pub, err := gost.GenerateEphemeralKey(curve, rand.Reader)
	require.NoError(t, err)

	oid49_3 := asn1.ObjectIdentifier{1, 2, 643, 2, 2, 49, 3}
	oid49_4 := asn1.ObjectIdentifier{1, 2, 643, 2, 2, 49, 4}

	ext49_3Value, encodeErr := asn1.Marshal([]byte("test-value-49.3"))
	require.NoError(t, encodeErr)
	ext49_4Value, encodeErr := asn1.Marshal([]byte("test-value-49.4"))
	require.NoError(t, encodeErr)

	extraExts := []pkix.Extension{
		{Id: oid49_3, Critical: false, Value: ext49_3Value},
		{Id: oid49_4, Critical: false, Value: ext49_4Value},
	}

	opts := &options.CreateCertificateOptions{
		SerialNumber: big.NewInt(1),
		Subject: options.SubjectOptions{
			CommonName: "Extra Extensions Test",
			Country:    []string{"RU"},
		},
		IsCA:            true,
		KeyUsage:        x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtraExtensions: extraExts,
		Crypto: options.CryptoOptions{
			CurveOID:      curveOID,
			Signer:        &internal.Signer{RawPrivateKey: priv, CurveOID: curveOID},
			RandReader:    rand.Reader,
			Algorithm:     x509gost.AlgoR341012_256,
			SignAlgorithm: x509gost.AlgoR341012_256,
		},
		RawPrivateKey: priv,
		RawPublicKey:  pub,
		TTL:           365 * 24 * time.Hour,
	}

	cert, err := CreateCertificate(opts)
	require.NoError(t, err)
	require.NotNil(t, cert)

	// Verify cert parses, then check extensions
	stdCert := cert.StdCertificate()

	// Find our extra extensions by OID
	found49_3 := false
	found49_4 := false

	for _, ext := range stdCert.Extensions {
		if ext.Id.Equal(oid49_3) {
			found49_3 = true
			assert.False(t, ext.Critical, "49.3 extension should NOT be critical")
		}
		if ext.Id.Equal(oid49_4) {
			found49_4 = true
			assert.False(t, ext.Critical, "49.4 extension should NOT be critical")
		}
	}

	assert.True(t, found49_3, "49.3 extension not found in parsed cert")
	assert.True(t, found49_4, "49.4 extension not found in parsed cert")

	// Self-verify
	_, err = cert.cert.Verify(x509gost.VerifyOptions{
		GOSTRoots: []*x509gost.Certificate{cert.cert},
	})
	require.NoError(t, err)
}
