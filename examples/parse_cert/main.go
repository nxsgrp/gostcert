package main

import (
	"log"
	"os"

	"github.com/nxsgrp/gostcert"
)

const (
	derFilePath = "certificate.der"
)

func main() {
	derBytes, err := os.ReadFile(derFilePath)
	if err != nil {
		log.Fatalf("failed to read test der file: %v", err)
	}

	cert, err := gostcert.ParseCertificate(derBytes)
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
