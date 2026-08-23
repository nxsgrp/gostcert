package internal

import (
	"fmt"

	"github.com/tarantool/go-gostcrypto"
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
func HashForGOST(algo x509gost.GOSTAlgorithm, data []byte) ([]byte, error) {
	hasher, err := GostAlgorithmToHash(algo)
	if err != nil {
		return nil, fmt.Errorf("hashForGOST: failed to get hasher %w", err)
	}

	_, err = hasher.Write(data)
	if err != nil {
		return nil, fmt.Errorf("hashForGOST: failed to write hash data %w", err)
	}

	// TODO: replace nil to data
	digest := hasher.Sum(nil)

	// GOST R 34.10 reads the digest as a little-endian integer "alpha".
	// Go's hash.Sum outputs big-endian bytes; reverse them.
	digestLE := make([]byte, len(digest))
	for i := range digest {
		digestLE[len(digest)-1-i] = digest[i]
	}

	return digestLE, nil
}

// Streebog256 computes the Streebog-256 (GOST R 34.11-2012, 256-bit) hash of data.
//
// The output is in big-endian byte order (no reversal), suitable for use as a
// key identifier (SKI/AKI). This is NOT the little-endian reversal required
// for GOST R 34.10 signature digests.
func Streebog256(data []byte) ([]byte, error) {
	hasher := gostcrypto.NewStreebog256Hash()
	_, err := hasher.Write(data)
	if err != nil {
		return nil, fmt.Errorf("streebog256: failed to write hash data %w", err)
	}
	return hasher.Sum(nil), nil
}
