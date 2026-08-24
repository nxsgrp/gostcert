package internal

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tarantool/go-gostcrypto/x509gost"
)

var hashKATs = []struct {
	name   string
	algo   x509gost.GOSTAlgorithm
	in     []byte
	wantBE string // canonical big-endian digest, hex
	size   int    // expected digest length in bytes
}{
	{
		name:   "streebog256-m1",
		algo:   x509gost.AlgoR341012_256,
		in:     []byte("012345678901234567890123456789012345678901234567890123456789012"),
		wantBE: "9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500",
		size:   32,
	},
	{
		name:   "streebog256-empty",
		algo:   x509gost.AlgoR341012_256,
		in:     nil,
		wantBE: "3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb",
		size:   32,
	},
	{
		name: "streebog512-empty",
		algo: x509gost.AlgoR341012_512,
		in:   nil,
		wantBE: "8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7" +
			"362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a",
		size: 64,
	},
	{
		name:   "gost94-abc",
		algo:   x509gost.AlgoR341001,
		in:     []byte("abc"),
		wantBE: "b285056dbf18d7392d7677369524dd14747459ed8143997e163b2986f92fd42c",
		size:   32,
	},
}

func TestHashForGOST(t *testing.T) {
	for _, testCase := range hashKATs {
		t.Run(testCase.name, func(t *testing.T) {
			digestLE, err := HashForGOST(testCase.algo, testCase.in)
			require.NoError(t, err)
			assert.Len(t, digestLE, testCase.size, "digest length must match the algorithm")

			// HashForGOST returns the digest as a little-endian integer
			// ("alpha" in GOST R 34.10), so reversing it must yield the
			// canonical big-endian known-answer value.
			wantBE := mustHex(t, testCase.wantBE)
			assert.Equal(t, wantBE, digestLE, "digest must be big-endian")
		})
	}
}

func TestHashForGOST_Deterministic(t *testing.T) {
	payload := []byte("some deterministic payload")

	aHashedSlices, err := HashForGOST(x509gost.AlgoR341012_256, payload)
	require.NoError(t, err)

	bHashedSlices, err := HashForGOST(x509gost.AlgoR341012_256, payload)
	require.NoError(t, err)

	assert.Equal(t, aHashedSlices, bHashedSlices, "hashing the same input twice must yield the same digest")
}

func TestHashForGOST_UnknownAlgorithm(t *testing.T) {
	_, err := HashForGOST(x509gost.GOSTAlgorithm(999), []byte("x"))
	assert.Error(t, err, "unknown algorithm must return an error")
}

func TestGostAlgorithmToHash(t *testing.T) {
	algos := []x509gost.GOSTAlgorithm{
		x509gost.AlgoR341001,
		x509gost.AlgoR341012_256,
		x509gost.AlgoR341012_512,
	}

	for _, algo := range algos {
		h, err := GostAlgorithmToHash(algo)
		require.NoError(t, err, "algo %d should map to a hasher", algo)
		assert.NotNil(t, h, "expected a non-nil hasher for algo %d", algo)
	}

	_, err := GostAlgorithmToHash(x509gost.GOSTAlgorithm(999))
	assert.Error(t, err, "unknown algorithm must return an error")
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err, "invalid hex literal: %s", s)
	return b
}
