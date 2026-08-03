package internal

import (
	"crypto"
	"encoding/asn1"
	"io"

	gost "github.com/tarantool/go-gostcrypto"
)

type Signer struct {
	RawPrivateKey []byte
	CurveOID      asn1.ObjectIdentifier
}

func (s *Signer) Public() crypto.PublicKey {
	gostCurveOID, _ := gost.CurveByOID(s.CurveOID)
	rawPublicKey, _ := gost.PublicKeyRawFromPrivate(gostCurveOID, s.RawPrivateKey)
	return rawPublicKey
}

func (s *Signer) Sign(r io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	curve, err := gost.CurveByOID(s.CurveOID)
	if err != nil {
		return nil, err
	}
	return gost.SignDigestOnCurve(curve, s.RawPrivateKey, digest, r)
}
