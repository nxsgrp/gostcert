package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConcatBytes(t *testing.T) {
	t.Run("concatenates in order", func(t *testing.T) {
		got := ConcatBytes([]byte("ab"), []byte("c"), []byte("def"))
		assert.Equal(t, []byte("abcdef"), got)
	})

	t.Run("single part", func(t *testing.T) {
		assert.Equal(t, []byte("solo"), ConcatBytes([]byte("solo")))
	})

	t.Run("empty yields empty", func(t *testing.T) {
		assert.Empty(t, ConcatBytes())
		assert.Empty(t, ConcatBytes([]byte{}, []byte{}))
	})
}
