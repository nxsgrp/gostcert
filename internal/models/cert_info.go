package models

import (
	"fmt"
	"math/big"
	"time"
)

type CertificateInformation struct {
	// SerialNumber is the unique serial number assigned to the certificate.
	SerialNumber *big.Int

	// NotBefore ...
	NotBefore time.Time

	// NotBefore ...
	NotAfter time.Time
}

func CreateCertificateInformation(serial *big.Int, notBefore, notAfter time.Time) (*CertificateInformation, error) {
	certInfo := &CertificateInformation{
		SerialNumber: serial,
		NotAfter:     notAfter,
		NotBefore:    notBefore,
	}

	err := certInfo.validate()
	if err != nil {
		return nil, fmt.Errorf("validating certificate information: %w", err)
	}

	return certInfo, nil
}

func (c *CertificateInformation) validate() error {
	if c.SerialNumber == nil {
		return fmt.Errorf("serial number is required")
	}

	// Only default NotBefore to "now" when the caller did not supply one;
	// NotAfter is always derived from NotBefore + TTL. Checking NotAfter here
	// (instead of NotBefore alone) would clobber an explicitly passed
	// NotBefore whenever the caller set only NotBefore and the TTL.
	if c.NotBefore.IsZero() {
		c.NotBefore = time.Now()
	}

	if c.NotAfter.Before(c.NotBefore) {
		return fmt.Errorf("not before time is too far in the future")
	}

	return nil
}
