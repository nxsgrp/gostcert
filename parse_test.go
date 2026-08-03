package gostcert

import (
	"os"
	"testing"

	"github.com/nxsgrp/gostcert/algorithm"
	"github.com/stretchr/testify/assert"
)

const testCertPath = "test/resources/certs/certificate.der"

func TestParseCertificate(t *testing.T) {
	derBytes, err := os.ReadFile(testCertPath)
	assert.NoError(t, err, "failed to read test cert")
	assert.NotNil(t, derBytes, "test cert should not be nil")

	cert, err := ParseCertificate(derBytes)
	assert.NoError(t, err, "failed to parse test cert")
	assert.NotNil(t, cert, "test cert should not be nil")
	assert.NotNil(t, cert.IsGOST, "expected GOST certificate")
	assert.NotNil(t, cert.Stdlib, "expected parsed Stdlib")
	assert.NotEmpty(t, cert.Raw, "expected cert raw bytes is not empty")
	assert.NotEmpty(t, cert.PublicKeyRaw, "expected cert public key is not empty")
	assert.NotEmpty(t, cert.Stdlib.Subject.CommonName, "expected subject common name is not empty")
	assert.Equal(t, cert.GOSTAlgorithm, algorithm.AlgoR341012_256, "expected AlgoR341012_256 algorithm")
	assert.Equal(t, cert.SigGOSTAlgorithm, algorithm.AlgoR341012_256, "expected AlgoR341012_256 signature algorithm")

	stdCert := cert.Stdlib
	t.Logf("Certificate has been parsed successfully")
	t.Logf(" -> Subject: %s\n", stdCert.Subject)
	t.Logf(" -> Issuer:  %s\n", stdCert.Issuer)
	t.Logf(" -> NotBefore: %s\n", stdCert.NotBefore)
	t.Logf(" -> NotAfter:  %s\n", stdCert.NotAfter)
	t.Logf(" -> Serial: %s\n", stdCert.SerialNumber)
	t.Logf(" -> Public Key Algorithm: %s\n", stdCert.PublicKeyAlgorithm)
}
