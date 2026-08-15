package models

import (
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
