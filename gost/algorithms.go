package gost

type GOSTAlgorithm int

const (
	// AlgoR341001 is GOST R 34.10-2001.
	AlgoR341001 GOSTAlgorithm = iota + 1
	// AlgoR341012_256 is GOST R 34.10-2012 with 256-bit key.
	AlgoR341012_256
	// AlgoR341012_512 is GOST R 34.10-2012 with 512-bit key.
	AlgoR341012_512
)
