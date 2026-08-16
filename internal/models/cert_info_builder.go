package models

import (
	"fmt"
	"math/big"
	"time"
)

type CertificateInformationBuilder struct {
	certInfo *CertificateInformation

	ttl time.Duration
}

func NewCertificateInformationBuilder() *CertificateInformationBuilder {
	return &CertificateInformationBuilder{
		certInfo: &CertificateInformation{},
	}
}

func (b *CertificateInformationBuilder) WithSerialNumber(serialNumber *big.Int) *CertificateInformationBuilder {
	b.certInfo.SerialNumber = serialNumber
	return b
}

func (b *CertificateInformationBuilder) WithNotBefore(notBefore time.Time) *CertificateInformationBuilder {
	b.certInfo.NotBefore = notBefore
	return b
}

func (b *CertificateInformationBuilder) WithTTL(ttl time.Duration) *CertificateInformationBuilder {
	b.ttl = ttl
	return b
}

func (b *CertificateInformationBuilder) Build() (*CertificateInformation, error) {
	if b.certInfo.SerialNumber == nil {
		return nil, fmt.Errorf("serial number is required")
	}

	// Only default NotBefore to "now" when the caller did not supply one;
	// NotAfter is always derived from NotBefore + TTL. Checking NotAfter here
	// (instead of NotBefore alone) would clobber an explicitly passed
	// NotBefore whenever the caller set only NotBefore and the TTL.
	if b.certInfo.NotBefore.IsZero() {
		b.certInfo.NotBefore = time.Now()
	}

	b.certInfo.NotAfter = b.certInfo.NotBefore.Add(b.ttl)
	if b.certInfo.NotAfter.Before(b.certInfo.NotBefore) {
		return nil, fmt.Errorf("not before time is too far in the future")
	}

	return b.certInfo, nil
}
