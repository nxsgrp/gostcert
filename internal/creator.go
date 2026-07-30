package internal

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"time"

	gost "github.com/tarantool/go-gostcrypto"
	"github.com/tarantool/go-gostcrypto/x509gost"
)

// ASN.1 structures for DER building (internal, not exported).

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type subjectPublicKeyInfo struct {
	Algorithm algorithmIdentifier
	PublicKey asn1.BitString
}

type extension struct {
	ID       asn1.ObjectIdentifier
	Critical bool `asn1:"optional"`
	Value    asn1.RawValue
}

// gostPubKeyOID returns the SubjectPublicKeyInfo algorithm OID for algo.
func gostPubKeyOID(algo x509gost.GOSTAlgorithm) asn1.ObjectIdentifier {
	switch algo {
	case x509gost.AlgoR341001:
		return x509gost.OIDPublicKeyGOSTR341001
	case x509gost.AlgoR341012_256:
		return x509gost.OIDPublicKeyGOSTR341012_256
	case x509gost.AlgoR341012_512:
		return x509gost.OIDPublicKeyGOSTR341012_512
	default:
		panic(fmt.Sprintf("gostcert: unknown GOSTAlgorithm %d", int(algo)))
	}
}

// sigAlgoOID returns the signature algorithm OID for algo.
func sigAlgoOID(algo x509gost.GOSTAlgorithm) asn1.ObjectIdentifier {
	switch algo {
	case x509gost.AlgoR341001:
		return x509gost.OIDSignatureGOSTR341001
	case x509gost.AlgoR341012_256:
		return x509gost.OIDSignatureGOSTR341012_256
	case x509gost.AlgoR341012_512:
		return x509gost.OIDSignatureGOSTR341012_512
	default:
		panic(fmt.Sprintf("gostcert: unknown GOSTAlgorithm %d", int(algo)))
	}
}

// buildSPKI builds a DER-encoded SubjectPublicKeyInfo for a GOST public key.
// pubKeyRaw is LE(X)||LE(Y). curveOID is the curve parameter OID.
func buildSPKI(pubKeyRaw []byte, curveOID asn1.ObjectIdentifier, algo x509gost.GOSTAlgorithm) ([]byte, error) {
	// Encode raw public key as OCTET STRING (RFC 4491 §2.1).
	pubKeyOctet, err := asn1.Marshal(pubKeyRaw)
	if err != nil {
		return nil, fmt.Errorf("buildSPKI: marshal pub key: %w", err)
	}

	// Encode curve OID as bare OID (the Parameters field).
	curveDER, err := asn1.Marshal(curveOID)
	if err != nil {
		return nil, fmt.Errorf("buildSPKI: marshal curve OID: %w", err)
	}

	spki, err := asn1.Marshal(subjectPublicKeyInfo{
		Algorithm: algorithmIdentifier{
			Algorithm:  gostPubKeyOID(algo),
			Parameters: asn1.RawValue{FullBytes: curveDER},
		},
		PublicKey: asn1.BitString{
			Bytes:     pubKeyOctet,
			BitLength: len(pubKeyOctet) * 8,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("buildSPKI: marshal SPKI: %w", err)
	}

	return spki, nil
}

// hashForGOST hashes data with the GOST hash algorithm implied by algo
// and returns the digest in little-endian byte order (GOST signing convention).
func hashForGOST(algo x509gost.GOSTAlgorithm, data []byte) ([]byte, error) {
	var h interface {
		Write([]byte) (int, error)
		Sum([]byte) []byte
	}

	switch algo {
	case x509gost.AlgoR341001:
		h = gost.NewGOSTR341194CryptoProHash()
	case x509gost.AlgoR341012_256:
		h = gost.NewStreebog256Hash()
	case x509gost.AlgoR341012_512:
		h = gost.NewStreebog512Hash()
	default:
		return nil, fmt.Errorf("hashForGOST: unknown GOSTAlgorithm %d", int(algo))
	}

	_, _ = h.Write(data)
	digest := h.Sum(nil)

	// GOST R 34.10 reads the digest as a little-endian integer "alpha".
	// Go's hash.Sum outputs big-endian bytes; reverse them.
	digestLE := make([]byte, len(digest))
	for i := range digest {
		digestLE[len(digest)-1-i] = digest[i]
	}

	return digestLE, nil
}

// buildSignatureAlgorithm builds a DER-encoded AlgorithmIdentifier for
// the GOST signature (no Parameters field, unlike SPKI).
func buildSignatureAlgorithm(sigAlgoOID asn1.ObjectIdentifier) ([]byte, error) {
	return asn1.Marshal(struct {
		Algorithm asn1.ObjectIdentifier
	}{sigAlgoOID})
}

// buildExtensions serializes a slice of pkix.Extension into the
// [3] EXPLICIT Extensions field of TBSCertificate.
// Returns nil if extensions is empty.
func buildExtensions(exts []pkix.Extension) ([]byte, error) {
	if len(exts) == 0 {
		return nil, nil
	}

	var extDER [][]byte
	for _, ext := range exts {
		e, err := asn1.Marshal(extension{
			ID:       ext.Id,
			Critical: ext.Critical,
			Value:    asn1.RawValue{FullBytes: ext.Value},
		})
		if err != nil {
			return nil, fmt.Errorf("buildExtensions: marshal extension %v: %w", ext.Id, err)
		}
		extDER = append(extDER, e)
	}

	// Extensions ::= SEQUENCE OF Extension
	seq, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      concatBytes(extDER...),
	})
	if err != nil {
		return nil, fmt.Errorf("buildExtensions: marshal sequence: %w", err)
	}

	// [3] EXPLICIT
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        3,
		IsCompound: true,
		Bytes:      seq,
	})
}

func concatBytes(parts ...[]byte) []byte {
	total := 0
	for _, p := range parts {
		total += len(p)
	}
	out := make([]byte, 0, total)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

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
//
// Возвращает DER-байты сертификата и распарсенный *x509gost.Certificate.
func CreateCertificate(
	rand io.Reader,
	template, parent *x509.Certificate,
	pubKeyRaw []byte,
	signer crypto.Signer,
	curveOID asn1.ObjectIdentifier,
	algo x509gost.GOSTAlgorithm,
	sigAlgo x509gost.GOSTAlgorithm,
) ([]byte, *x509gost.Certificate, error) {
	// ── 1. Определяем Subject и Issuer ───────────────────────────────────
	subjectDER := template.RawSubject
	if len(subjectDER) == 0 {
		rdns := template.Subject.ToRDNSequence()
		var err error
		subjectDER, err = asn1.Marshal(rdns)
		if err != nil {
			return nil, nil, fmt.Errorf("CreateCertificate: marshal Subject: %w", err)
		}
	}

	issuerDER := parent.RawSubject
	if len(issuerDER) == 0 {
		rdns := parent.Subject.ToRDNSequence()
		var err error
		issuerDER, err = asn1.Marshal(rdns)
		if err != nil {
			return nil, nil, fmt.Errorf("CreateCertificate: marshal Issuer: %w", err)
		}
	}

	// ── 2. Определяем Validity ───────────────────────────────────────────
	notBefore := template.NotBefore
	notAfter := template.NotAfter
	if notBefore.IsZero() {
		notBefore = parent.NotBefore
	}
	if notAfter.IsZero() {
		notAfter = parent.NotAfter
	}

	// ── 3. Собираем SPKI ─────────────────────────────────────────────────
	spkiDER, err := buildSPKI(pubKeyRaw, curveOID, algo)
	if err != nil {
		return nil, nil, fmt.Errorf("CreateCertificate: %w", err)
	}

	// ── 4. Собираем TBSCertificate ───────────────────────────────────────
	sigOID := sigAlgoOID(sigAlgo)

	sigAlgoDER, err := buildSignatureAlgorithm(sigOID)
	if err != nil {
		return nil, nil, fmt.Errorf("CreateCertificate: build sig algo: %w", err)
	}

	serialDER, err := asn1.Marshal(template.SerialNumber)
	if err != nil {
		return nil, nil, fmt.Errorf("CreateCertificate: marshal serial: %w", err)
	}

	// Validity SEQUENCE { notBefore Time, notAfter Time }
	validityDER, err := asn1.Marshal(struct {
		NotBefore time.Time
		NotAfter  time.Time
	}{notBefore.UTC(), notAfter.UTC()})
	if err != nil {
		return nil, nil, fmt.Errorf("CreateCertificate: marshal validity: %w", err)
	}

	// version [0] EXPLICIT INTEGER := 2 (v3).
	versionDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      []byte{0x02, 0x01, 0x02}, // INTEGER 2
	})
	if err != nil {
		return nil, nil, fmt.Errorf("CreateCertificate: marshal version: %w", err)
	}

	tbsBody := concatBytes(
		versionDER,
		serialDER,
		sigAlgoDER,
		issuerDER,
		validityDER,
		subjectDER,
		spkiDER,
	)

	// Extensions (optional [3] EXPLICIT).
	extDER, err := buildExtensions(template.ExtraExtensions)
	if err != nil {
		return nil, nil, fmt.Errorf("CreateCertificate: %w", err)
	}
	if len(extDER) > 0 {
		tbsBody = append(tbsBody, extDER...)
	}

	tbsDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      tbsBody,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("CreateCertificate: marshal TBS: %w", err)
	}

	// ── 5. Хешируем TBSCertificate ───────────────────────────────────────
	digestLE, err := hashForGOST(sigAlgo, tbsDER)
	if err != nil {
		return nil, nil, fmt.Errorf("CreateCertificate: hash: %w", err)
	}

	// ── 6. Подписываем ───────────────────────────────────────────────────
	sig, err := signer.Sign(rand, digestLE, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("CreateCertificate: sign: %w", err)
	}

	// ── 7. Собираем финальный Certificate SEQUENCE ────────────────────────
	sigBitString := asn1.BitString{
		Bytes:     sig,
		BitLength: len(sig) * 8,
	}

	certBody := concatBytes(tbsDER, sigAlgoDER)

	sigBitDER, err := asn1.Marshal(sigBitString)
	if err != nil {
		return nil, nil, fmt.Errorf("CreateCertificate: marshal signature: %w", err)
	}
	certBody = append(certBody, sigBitDER...)

	certDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      certBody,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("CreateCertificate: marshal cert: %w", err)
	}

	// ── 8. Парсим результат ──────────────────────────────────────────────
	cert, err := x509gost.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("CreateCertificate: parse result: %w", err)
	}

	return certDER, cert, nil
}

// Ensure big is used (for SerialNumber type)
var _ = big.NewInt(0)