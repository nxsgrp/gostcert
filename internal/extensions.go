package internal

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

// BuildExtensions serializes a slice of pkix.Extension into the DER-encoded
// [3] EXPLICIT Extensions field of TBSCertificate (RFC 5280, section 4.1.2.9).
//
// Returns nil, nil if extensions is empty (no extensions tag is written).
func BuildExtensions(extensions []pkix.Extension) ([]byte, error) {
	if len(extensions) == 0 {
		return nil, nil
	}

	var derExtension [][]byte
	for _, pkixExt := range extensions {
		extData, err := asn1.Marshal(pkix.Extension{
			Id:       pkixExt.Id,
			Critical: pkixExt.Critical,
			Value:    pkixExt.Value,
		})

		if err != nil {
			return nil, fmt.Errorf("buildExtension: marshal extension %v: %w", pkixExt.Id, err)
		}

		derExtension = append(derExtension, extData)
	}

	// Extensions ::= SEQUENCE OF Extension
	seq, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      ConcatBytes(derExtension...),
	})
	if err != nil {
		return nil, fmt.Errorf("buildExtension: marshal sequence: %w", err)
	}

	// [3] EXPLICIT
	expl, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        3,
		IsCompound: true,
		Bytes:      seq,
	})

	if err != nil {
		return nil, fmt.Errorf("buildExtension: marshal explicit: %w", err)
	}

	return expl, nil
}
