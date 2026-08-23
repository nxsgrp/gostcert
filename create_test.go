package gostcert

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/nxsgrp/gostcert/gost"
	"github.com/nxsgrp/gostcert/internal"
	"github.com/nxsgrp/gostcert/options"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tarantool/go-gostcrypto"
	"github.com/tarantool/go-gostcrypto/x509gost"
)

// testOrganization is the Organization attribute used by every test subject.
const testOrganization = "Test"

func TestCreateCertificate_SelfSigned(t *testing.T) {
	// Generate a random 20-byte serial number (matching OpenSSL convention).
	serialNumber, err := generateSerialNumber()
	assert.NoError(t, err, "unexpected error while generating serial number")

	// Use the CryptoPro-A curve parameter set (matches the reference openssl-generated certificate).
	curveOID := x509gost.OIDParamTC26_512A
	rawPublicKey, rawPrivateKey, err := generateEphemeralKey(curveOID)
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
				Organization: []string{testOrganization},
			},
			PublicKeyOptions: options.SubjectPublicKeyOptions{
				CurveOID:     curveOID,
				Algorithm:    gost.AlgoR341012_512,
				RawPublicKey: rawPublicKey,
			},
		},
		Issuer: options.IssuerOptions{
			RandReader:        rand.Reader,
			Signer:            signer,
			SignAlgorithm:     gost.AlgoR341012_512,
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
	assert.Equal(t, cert.cert.GOSTAlgo, x509gost.AlgoR341012_512, "expected AlgoR341012_512 algorithm")
	assert.Equal(t, cert.cert.SigGOSTAlgo, x509gost.AlgoR341012_512, "expected AlgoR341012_512 signature algorithm")

	// Verify via x509gost
	//nolint
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
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	return pubRaw, privRaw, nil
}

func TestCreateCertificate_Chain_RootIntermediateLeaf(t *testing.T) {
	curveOID := x509gost.OIDParamTC26_256A
	curve, err := gostcrypto.CurveByOID(curveOID)
	require.NoError(t, err)

	// ── Generate keypairs for root, intermediate, leaf ──
	rootPriv, rootPub, err := gostcrypto.GenerateEphemeralKey(curve, rand.Reader)
	require.NoError(t, err)

	intermPriv, intermPub, err := gostcrypto.GenerateEphemeralKey(curve, rand.Reader)
	require.NoError(t, err)

	_, leafPub, err := gostcrypto.GenerateEphemeralKey(curve, rand.Reader)
	require.NoError(t, err)

	rootSigner, err := internal.BuildSigner(curveOID, rootPriv)
	require.NoError(t, err)

	intermSigner, err := internal.BuildSigner(curveOID, intermPriv)
	require.NoError(t, err)

	// ── 1. Create Root CA (self-signed, CA=true, pathLen=1) ──
	pathLen1 := 1

	rootOpts := &options.CreateCertificateOptions{
		SerialNumber:      big.NewInt(1),
		TTL:               365 * 24 * time.Hour,
		IsCA:              true,
		PathLenConstraint: &pathLen1,
		KeyUsage:          x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		Subject: options.SubjectOptions{
			Information: options.SubjetInformationOptions{
				CommonName:   "GOST Root CA",
				Country:      []string{"RU"},
				Organization: []string{testOrganization},
			},
			PublicKeyOptions: options.SubjectPublicKeyOptions{
				CurveOID:     curveOID,
				Algorithm:    gost.AlgoR341012_256,
				RawPublicKey: rootPub,
			},
		},
		Issuer: options.IssuerOptions{
			RandReader:    rand.Reader,
			Signer:        rootSigner,
			SignAlgorithm: gost.AlgoR341012_256,
		},
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
	pathLen0 := 0

	intermOpts := &options.CreateCertificateOptions{
		SerialNumber:      big.NewInt(2),
		TTL:               365 * 24 * time.Hour,
		IsCA:              true,
		PathLenConstraint: &pathLen0,
		KeyUsage:          x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		Subject: options.SubjectOptions{
			Information: options.SubjetInformationOptions{
				CommonName:   "GOST Intermediate CA",
				Country:      []string{"RU"},
				Organization: []string{testOrganization},
			},
			PublicKeyOptions: options.SubjectPublicKeyOptions{
				CurveOID:     curveOID,
				Algorithm:    gost.AlgoR341012_256,
				RawPublicKey: intermPub,
			},
		},
		Issuer: options.IssuerOptions{
			RandReader:        rand.Reader,
			Signer:            rootSigner, // root signs the intermediate
			SignAlgorithm:     gost.AlgoR341012_256,
			ParentCertificate: rootCert.StdCertificate(),
		},
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
	leafOpts := &options.CreateCertificateOptions{
		SerialNumber: big.NewInt(3),
		TTL:          365 * 24 * time.Hour,
		IsCA:         false,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		Subject: options.SubjectOptions{
			Information: options.SubjetInformationOptions{
				CommonName:   "GOST Leaf Certificate",
				Country:      []string{"RU"},
				Organization: []string{testOrganization},
			},
			PublicKeyOptions: options.SubjectPublicKeyOptions{
				CurveOID:     curveOID,
				Algorithm:    gost.AlgoR341012_256,
				RawPublicKey: leafPub,
			},
		},
		Issuer: options.IssuerOptions{
			RandReader:        rand.Reader,
			Signer:            intermSigner, // intermediate signs the leaf
			SignAlgorithm:     gost.AlgoR341012_256,
			ParentCertificate: intermCert.StdCertificate(),
		},
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
	curveOID := x509gost.OIDParamTC26_256A
	curve, err := gostcrypto.CurveByOID(curveOID)
	require.NoError(t, err)

	priv, pub, err := gostcrypto.GenerateEphemeralKey(curve, rand.Reader)
	require.NoError(t, err)

	signer, err := internal.BuildSigner(curveOID, priv)
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
		SerialNumber:    big.NewInt(1),
		TTL:             365 * 24 * time.Hour,
		IsCA:            true,
		KeyUsage:        x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtraExtensions: extraExts,
		Subject: options.SubjectOptions{
			Information: options.SubjetInformationOptions{
				CommonName:   "Extra Extensions Test",
				Country:      []string{"RU"},
				Organization: []string{testOrganization},
			},
			PublicKeyOptions: options.SubjectPublicKeyOptions{
				CurveOID:     curveOID,
				Algorithm:    gost.AlgoR341012_256,
				RawPublicKey: pub,
			},
		},
		Issuer: options.IssuerOptions{
			RandReader:    rand.Reader,
			Signer:        signer,
			SignAlgorithm: gost.AlgoR341012_256,
		},
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
