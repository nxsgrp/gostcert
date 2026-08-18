package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/nxsgrp/gostcert"
	"github.com/nxsgrp/gostcert/gost"
	"github.com/nxsgrp/gostcert/internal"
	"github.com/nxsgrp/gostcert/options"
)

func main() {
	serialNumber, err := generateSerialNumber()
	if err != nil {
		log.Fatalf("failed to generate serial number: %v", err)
	}

	rawPrivateKey, err := os.ReadFile("private.key")
	if err != nil {
		log.Fatalf("failed to read private key: %v", err)
	}

	rawPublicKey, err := os.ReadFile("public.key")
	if err != nil {
		log.Fatalf("failed to read public key: %v", err)
	}

	curveOID := gost.OIDParamTC26_256A
	signer, err := internal.BuildSigner(curveOID, rawPrivateKey)
	if err != nil {
		log.Fatalf("failed to build signer: %v", err)
	}

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

	cert, err := gostcert.CreateCertificate(opts)
	if err != nil {
		log.Fatalf("failed to parse test der file: %v", err)
	}

	stdCert := cert.StdCertificate()
	log.Printf("Certificate has been parsed successfully")
	log.Printf(" -> Subject: %s\n", stdCert.Subject)
	log.Printf(" -> Issuer:  %s\n", stdCert.Issuer)
	log.Printf(" -> NotBefore: %s\n", stdCert.NotBefore)
	log.Printf(" -> NotAfter:  %s\n", stdCert.NotAfter)
	log.Printf(" -> Serial: %s\n", stdCert.SerialNumber)
	log.Printf(" -> Public Key Algorithm: %s\n", stdCert.PublicKeyAlgorithm)
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
