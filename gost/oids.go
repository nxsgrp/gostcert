package gost

import "encoding/asn1"

// Curve parameter OIDs

// OIDParamTC26_256A is the TC26 GOST R 34.10-2012 256-bit curve paramSetA
// (id-tc26-gost-3410-2012-256-paramSetA / 1.2.643.7.1.2.1.1.1). RFC 7091.
var OIDParamTC26_256A = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 1}

// OIDParamTC26_256B is the TC26 GOST R 34.10-2012 256-bit curve paramSetB
// (id-tc26-gost-3410-2012-256-paramSetB / 1.2.643.7.1.2.1.1.2).
var OIDParamTC26_256B = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 2}

// OIDParamTC26_256C is the TC26 GOST R 34.10-2012 256-bit curve paramSetC
// (id-tc26-gost-3410-2012-256-paramSetC / 1.2.643.7.1.2.1.1.3).
var OIDParamTC26_256C = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 3}

// OIDParamTC26_256D is the TC26 GOST R 34.10-2012 256-bit curve paramSetD
// (id-tc26-gost-3410-2012-256-paramSetD / 1.2.643.7.1.2.1.1.4).
var OIDParamTC26_256D = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 1, 4}

// OIDParamTC26_512A is the TC26 GOST R 34.10-2012 512-bit curve paramSetA
// (id-tc26-gost-3410-2012-512-paramSetA / 1.2.643.7.1.2.1.2.1). RFC 7091.
var OIDParamTC26_512A = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 1}

// OIDParamTC26_512B is the TC26 GOST R 34.10-2012 512-bit curve paramSetB
// (id-tc26-gost-3410-2012-512-paramSetB / 1.2.643.7.1.2.1.2.2).
var OIDParamTC26_512B = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 2}

// OIDParamTC26_512C is the TC26 GOST R 34.10-2012 512-bit curve paramSetC
// (id-tc26-gost-3410-2012-512-paramSetC / 1.2.643.7.1.2.1.2.3).
var OIDParamTC26_512C = asn1.ObjectIdentifier{1, 2, 643, 7, 1, 2, 1, 2, 3}
