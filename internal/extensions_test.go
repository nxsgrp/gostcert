package internal

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildExtensions(t *testing.T) {
	t.Run("empty produces nothing", func(t *testing.T) {
		der, err := BuildExtensions(nil)
		assert.NoError(t, err)
		assert.Nil(t, der, "no extensions must produce nil DER")
	})

	t.Run("non-empty round-trips", func(t *testing.T) {
		extensions := []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier{2, 5, 29, 19},
				Critical: true,
				Value:    []byte{0x30, 0x00},
			},
		}

		der, err := BuildExtensions(extensions)
		require.NoError(t, err)
		assert.NotEmpty(t, der)

		// The result is wrapped in [3] EXPLICIT SEQUENCE OF Extension.
		var raw asn1.RawValue
		rest, err := asn1.Unmarshal(der, &raw)
		require.NoError(t, err)
		require.Empty(t, rest)
		assert.Equal(t, asn1.ClassContextSpecific, raw.Class)
		assert.Equal(t, 3, raw.Tag)

		var got []pkix.Extension
		_, err = asn1.Unmarshal(raw.Bytes, &got)
		require.NoError(t, err)
		assert.Len(t, got, len(extensions))
		assert.Equal(t, extensions[0].Id, got[0].Id)
		assert.Equal(t, extensions[0].Critical, got[0].Critical)
		assert.Equal(t, extensions[0].Value, got[0].Value)
	})
}
