package models

import (
	"crypto"
	"io"
)

// stubSigner is a minimal crypto.Signer used only to satisfy the non-nil
// Signer check in Issuer validation. It is never actually used for signing.
type stubSigner struct{}

func (stubSigner) Public() crypto.PublicKey { return nil }

func (stubSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, nil
}
