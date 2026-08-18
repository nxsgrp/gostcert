package test

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/nxsgrp/gostcert"
	"github.com/nxsgrp/gostcert/gost"
	"github.com/nxsgrp/gostcert/internal"
	"github.com/nxsgrp/gostcert/options"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testOpensslGostConf     = "test/resources/openssl/openssl-gost.conf"
	createdGostCertFileName = "gostcert.der"
)

// TestOpenSSL_ParsesOurCertificate is the acceptance criterion "parse our
// certificate in an OpenSSL built with GOST support". It is skipped when no
// GOST-capable OpenSSL binary is available (e.g. system LibreSSL).
func TestOpenSSL_ParsesOurCertificate(t *testing.T) {
	testCase := createCertTestCase{
		name:    "tc26_256a",
		derPath: tc26_256DerFilePath,
		scalar:  tc26_256Scalar,
		curve:   gost.OIDParamTC26_256A,
		algo:    gost.AlgoR341012_256,
		sigLen:  64,
	}

	der, err := os.ReadFile(testCase.derPath)
	require.NoError(t, err, "read reference certificate")

	ref, err := gostcert.ParseCertificate(der)
	require.NoError(t, err, "parse reference certificate")
	std := ref.StdCertificate()

	notBefore := std.NotBefore.UTC()
	notAfter := std.NotAfter.UTC()

	scalar := revBytes(mustHexString(t, testCase.scalar))
	signer, err := internal.BuildSigner(testCase.curve, scalar)
	require.NoError(t, err, "build signer failed")

	opts := &options.CreateCertificateOptions{
		SerialNumber: new(big.Int).Set(std.SerialNumber),
		NotBefore:    notBefore,
		TTL:          notAfter.Sub(notBefore),
		Subject: options.SubjectOptions{
			Information: options.SubjetInformationOptions{
				CommonName:   std.Subject.CommonName,
				Country:      std.Subject.Country,
				Organization: std.Subject.Organization,
			},
			PublicKeyOptions: options.SubjectPublicKeyOptions{
				CurveOID:     testCase.curve,
				Algorithm:    testCase.algo,
				RawPublicKey: signer.Public().([]byte),
			},
		},
		Issuer: options.IssuerOptions{
			RandReader:    rand.Reader,
			Signer:        signer,
			SignAlgorithm: testCase.algo,
		},
	}

	ours, err := gostcert.CreateCertificate(opts)
	require.NoError(t, err, "create certificate")

	certPath := filepath.Join(t.TempDir(), createdGostCertFileName)
	require.NoError(t, os.WriteFile(certPath, ours.GetRawCertificate(), 0o600))

	confPath, err := filepath.Abs(testOpensslGostConf)
	require.NoError(t, err)

	// Executing openssl x509 -in <file-path.der> -inform DER -text -noout
	args := []string{"x509", "-in", certPath, "-inform", "DER", "-noout", "-subject"}

	cmd := exec.CommandContext(t.Context(), "openssl", args...)
	cmd.Env = append(os.Environ(), fmt.Sprintf("OPENSSL_CONF=%s", confPath))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Errorf("OpenSSL cannot parse GOST: %v: %s", err, out)
	}

	assert.Contains(t, string(out), std.Subject.CommonName, "failed to parse created gostcert")
}
