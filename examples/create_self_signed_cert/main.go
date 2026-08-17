package main

import (
	"crypto/rand"
	"encoding/asn1"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/nxsgrp/gostcert"
	"github.com/nxsgrp/gostcert/gost"
	"github.com/nxsgrp/gostcert/internal"
	"github.com/nxsgrp/gostcert/options"
	"github.com/tarantool/go-gostcrypto"
)

func main() {
	serialNumber, err := generateSerialNumber()
	if err != nil {
		log.Fatalf("failed to generate serial number: %v", err)
	}

	curveOID := gost.OIDParamTC26_256A
	rawPrivateKey, rawPublicKey, err := generateEphemeralKey(curveOID)
	if err != nil {
		log.Fatalf("failed to generate keys: %v", err)
	}

	signer := &internal.Signer{RawPrivateKey: rawPrivateKey, CurveOID: curveOID}

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
