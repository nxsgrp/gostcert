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
