package internal

import (
	"fmt"

	gost "github.com/tarantool/go-gostcrypto"
	"github.com/tarantool/go-gostcrypto/x509gost"
)

type Hasher interface {
	Write([]byte) (int, error)
	Sum([]byte) []byte
}

// Streebog256 computes the Streebog-256 (GOST R 34.11-2012) hash of data.
//
// The output is in big-endian byte order (no reversal), suitable for use as
// a key identifier (SKI/AKI). This is NOT the little-endian reversal needed
// for GOST R 34.10 signature digests.
func Streebog256(data []byte) []byte {
	h := gost.NewStreebog256Hash()
	_, _ = h.Write(data)
	return h.Sum(nil)
}

func GostAlgorithmToHash(algo x509gost.GOSTAlgorithm) (Hasher, error) {
	switch algo {
	case x509gost.AlgoR341001:
		return gost.NewGOSTR341194CryptoProHash(), nil
	case x509gost.AlgoR341012_256:
		return gost.NewStreebog256Hash(), nil
	case x509gost.AlgoR341012_512:
		return gost.NewStreebog512Hash(), nil
	default:
		return nil, fmt.Errorf("unknown GOST algorithm %d", algo)
	}
}
