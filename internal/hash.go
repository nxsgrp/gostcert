package internal

import (
	"fmt"

	"github.com/tarantool/go-gostcrypto/x509gost"
)

type Hasher interface {
	Write([]byte) (int, error)
	Sum([]byte) []byte
}

// HashForGOST hashes data with the GOST hash algorithm corresponding to
// the given GOST algorithm and returns the digest in little-endian byte order.
//
// GOST R 34.10 reads the digest as a little-endian integer ("alpha").
// Go's hash.Hash.Sum outputs big-endian bytes, so this function reverses
// them before returning.
//
// The output is in big-endian byte order (no reversal), suitable for use as a
// key identifier (SKI/AKI). This is NOT the little-endian reversal required
// for GOST R 34.10 signature digests.
func HashForGOST(algo x509gost.GOSTAlgorithm, data []byte) ([]byte, error) {
	hasher, err := GostAlgorithmToHash(algo)
	if err != nil {
		return nil, fmt.Errorf("hashForGOST: failed to get hasher %w", err)
	}

	_, err = hasher.Write(data)
	if err != nil {
		return nil, fmt.Errorf("hashForGOST: failed to write hash data %w", err)
	}
	digest := hasher.Sum(nil)

	return digest, nil
}
