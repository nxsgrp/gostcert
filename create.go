package gostcert

import (
	"encoding/asn1"
	"fmt"

	"github.com/nxsgrp/gostcert/internal"
	"github.com/nxsgrp/gostcert/internal/options"
)

// CreateCertificate creates a new DER-encoded GOST X.509 certificate.
//
// Параметры:
//   - rand — источник энтропии (передаётся в signer.Sign).
//   - template — шаблон сертификата (Subject, SerialNumber, NotBefore/NotAfter,
//     ExtraExtensions и т.д.).
//   - parent — вышестоящий сертификат (issuer): его RawSubject становится
//     Issuer полем выпускаемого сертификата.
//   - pubKeyRaw — сырые байты публичного ключа субъекта LE(X)||LE(Y).
//   - signer — подписант (issuer), реализующий crypto.Signer. Sign() должен
//     возвращать raw GOST signature bytes (R||S в LE).
//   - curveOID — OID кривой (напр. x509gost.OIDParamTC26_256A).
//   - algo — алгоритм ключа субъекта (x509gost.GOSTAlgorithm).
//   - sigAlgo — алгоритм подписи, определяет хеш TBSCertificate.
func CreateCertificate(opts *options.CreateCertificateOptions) (*Certificate, error) {
	template := opts.BuildTemplateCertificate()

	sigAlgoDER, err := internal.BuildSignatureAlgorithm(opts.SignAlgorithm)
	if err != nil {
		return nil, fmt.Errorf("CreateCertificate: build sig algo: %w", err)
	}

	// Create TBS Certificate raw body by concatenation
	tbsBody, err := internal.BuildTBSCertificate(opts, template, opts.ParentCertificate, sigAlgoDER)
	if err != nil {
		return nil, fmt.Errorf("CreateCertificate: build tbs certificate: %w", err)
	}

	// Extensions (optional [3] EXPLICIT).
	extDER, err := internal.BuildExtensions(template.ExtraExtensions)
	if err != nil {
		return nil, fmt.Errorf("CreateCertificate: %w", err)
	}
	if len(extDER) > 0 {
		tbsBody = append(tbsBody, extDER...)
	}

	tbsRawValue := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      tbsBody,
	}

	tbsDER, err := asn1.Marshal(tbsRawValue)
	if err != nil {
		return nil, fmt.Errorf("CreateCertificate: marshal TBS: %w", err)
	}

	// Sign temp certificate
	digestLE, err := internal.HashForGOST(opts.SignAlgorithm, tbsDER)
	if err != nil {
		return nil, fmt.Errorf("CreateCertificate: hash: %w", err)
	}

	sig, err := opts.Signer.Sign(opts.RandReader, digestLE, nil)
	if err != nil {
		return nil, fmt.Errorf("CreateCertificate: sign: %w", err)
	}

	// Building final certificate
	sigBitString := asn1.BitString{
		Bytes:     sig,
		BitLength: len(sig) * 8,
	}

	sigBitDER, err := asn1.Marshal(sigBitString)
	if err != nil {
		return nil, fmt.Errorf("CreateCertificate: marshal signature: %w", err)
	}

	certBody := internal.ConcatBytes(tbsDER, sigAlgoDER)
	certBody = append(certBody, sigBitDER...)

	certRawValue := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      certBody,
	}

	certDER, err := asn1.Marshal(certRawValue)
	if err != nil {
		return nil, fmt.Errorf("CreateCertificate: marshal cert: %w", err)
	}

	cert, err := ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("CreateCertificate: parse result: %w", err)
	}

	return cert, nil
}
