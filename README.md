# gostcert

Issuing, parsing, revoking and validating GOST X.509 certificates in pure Go.

Covers certificate **issuance**, **CRLs** and **PKCS#10** requests per
R 1323565.1.023-2018, plus **parsing**, **revocation** and **validity checking**.
GOST primitives and certificate parsing come from [`tarantool/go-gostcrypto`].

> **Status: work in progress (skeleton).**

## Why

There is no pure-Go GOST certificate issuer under a permissive license:
alternatives are either AGPL, cgo over OpenSSL, or carry encoding defects.
`go-gostcrypto` deliberately stops at parsing and verification. `gostcert`
covers the issuance and revocation side.

## Install

```sh
go get github.com/nxsgrp/gostcert
```

Requires Go 1.24+.

## Usage (API sketch)

The public API takes a `crypto.Signer`, so hardware tokens (PKCS#11, Rutoken)
stay outside the library.

```go
der, err := gostcert.CreateCertificate(rand.Reader, tmpl, parent, pub, signer, suite)

crl, err := gostcert.CreateCRL(rand.Reader, issuer, signer, revoked, thisUpdate, nextUpdate, suite)

cert, err := gostcert.ParseCertificate(der)
chains, err := cert.Verify(opts) // opts extends x509gost.VerifyOptions with a CRLs field
```

## Layout

```
gostcert/
  doc.go                  — package documentation
  gostcert.go             — Certificate, CertificateRequest, CRL types; shared errors
  algo.go                 — algorithm suite registry (AlgorithmSuite)
  issue.go                — CreateCertificate
  crl.go                  — CreateCRL, ParseCRL, revocation check
  csr.go                  — CreateCertificateRequest, ParseCertificateRequest
  parse.go                — wrapper over x509gost.ParseCertificate
  verify.go               — Verify + revocation check
  internal/asn1x/         — shared DER structures
```

## Roadmap

- **Phase 0** — skeleton, parsing the reference certificates from Appendix A.
- **Phase 1** — self-signed certificate issuance (byte-for-byte match with the reference given the documented `k`).
- **Phase 2** — extensions, issuance from a parent (incl. a 512-bit root over a 256-bit leaf).
- **Phase 3** — CRL.
- **Phase 4** — PKCS#10.
- **Phase 5** — revocation checking in `Verify`.
- **Phase 6** — vectors in CI, fuzzing, godoc.

## Normative references

- R 1323565.1.023-2018 — primary source; it wins on any discrepancy.
- RFC 9215, 4491, 7091, 6986, 5280, 2986 — the X.509/CRL/PKCS#10 GOST profile.

