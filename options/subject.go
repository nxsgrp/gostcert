package options

import "crypto/x509/pkix"

// SubjectOptions contains necessary information of certificate publisher.
type SubjectOptions struct {
	// CommonName is the (CN) for the certificate subject.
	CommonName string
	// Country is the (C) values for the certificate subject.
	Country []string
	// Organization is the (O) values for the certificate subject.
	Organization []string
}

func (so *SubjectOptions) toPkixName() pkix.Name {
	return pkix.Name{
		CommonName:   so.CommonName,
		Country:      so.Country,
		Organization: so.Organization,
	}
}
