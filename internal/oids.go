package internal

import (
	"encoding/asn1"

	"github.com/tarantool/go-gostcrypto/x509gost"
)

var (
	// Public key parameter set OIDs referenced by R 1323565.1.023-2018 §4.2
	// (RFC 9215 §4.2) that are not exported by the x509gost package.

	// oidParamCryptoProTest is id-GostR3410-2001-TestParamSet
	// (1.2.643.2.2.35.0), RFC 4357 §8.4. A test parameter set.
	oidParamCryptoProTest = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 35, 0}

	// oidParamCryptoProXchA is id-GostR3410-2001-CryptoPro-XchA-ParamSet
	// (1.2.643.2.2.36.0), RFC 4357.
	oidParamCryptoProXchA = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 36, 0}

	// oidParamCryptoProXchB is id-GostR3410-2001-CryptoPro-XchB-ParamSet
	// (1.2.643.2.2.36.1), RFC 4357.
	oidParamCryptoProXchB = asn1.ObjectIdentifier{1, 2, 643, 2, 2, 36, 1}

	// oidParamTC26_512Test is id-tc26-gost-3410-2012-512-paramSetTest
	// (1.2.643.7.1.2.1.2.0), RFC 9215 / RFC 7091. A test parameter set.
	oidParamTC26_512Test = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 0}
)

// oidCountryName is id-at-countryName (2.5.4.6), the one RDN attribute that
// OpenSSL leaves as PrintableString instead of UTF8String.
var oidCountryName = asn1.ObjectIdentifier{2, 5, 4, 6}

// cryptoPro2001ParamSets lists the GOST R 34.10-2001 public key parameter sets
// for which §4.2 requires digestParamSet to be present and equal to
// id-tc26-digest-gost3411-12-256 (MUST).
var cryptoPro2001ParamSets = []asn1.ObjectIdentifier{
	x509gost.OIDParamCryptoProA,
	x509gost.OIDParamCryptoProB,
	x509gost.OIDParamCryptoProC,
	oidParamCryptoProTest,
	oidParamCryptoProXchA,
	oidParamCryptoProXchB,
}
