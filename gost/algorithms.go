package gost

import "github.com/tarantool/go-gostcrypto/x509gost"

type GOSTAlgorithm int

const (
	// AlgoR341001 is GOST R 34.10-2001.
	AlgoR341001 GOSTAlgorithm = iota + 1
	// AlgoR341012_256 is GOST R 34.10-2012 with 256-bit key.
	AlgoR341012_256
	// AlgoR341012_512 is GOST R 34.10-2012 with 512-bit key.
	AlgoR341012_512
)

// ToX509 maps the public GOSTAlgorithm onto the equivalent
// x509gost.GOSTAlgorithm. The two enums are offset by one because
// go-gostcrypto declares an untyped sibling constant (pubKeyCoords) in the
// same const block, so its AlgoR341001 == 2 while ours == 1.
func (a GOSTAlgorithm) ToX509() x509gost.GOSTAlgorithm {
	return x509gost.GOSTAlgorithm(a) + 1
}
