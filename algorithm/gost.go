package algorithm

// GOSTAlgorithm identifies which GOST signature family is used.
type GOSTAlgorithm int

const (
	AlgoR341001     GOSTAlgorithm = iota + 1 // GOST R 34.10-2001
	AlgoR341012_256                          // GOST R 34.10-2012 / 256-bit
	AlgoR341012_512                          // GOST R 34.10-2012 / 512-bit
)

const (
	AlgoR341001Name     = "GOST R 34.10-2001"
	AlgoR341012_256Name = "GOST R 34.10-2012/256"
	AlgoR341012_512Name = "GOST R 34.10-2012/512"
)

func (a GOSTAlgorithm) String() string {
	switch a {
	case AlgoR341001:
		return AlgoR341001Name
	case AlgoR341012_256:
		return AlgoR341012_256Name
	case AlgoR341012_512:
		return AlgoR341012_512Name
	default:
		return AlgoR341001Name
	}
}
