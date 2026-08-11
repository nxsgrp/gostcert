# Test Certificates

This directory contains test resources for parsing GOST certificates using the `gostcert` library.

## Files

| File              | Format | Purpose                                                             |
|-------------------|--------|---------------------------------------------------------------------|
| `certificate.der` | DER    | Test certificate in binary DER format (used in tests)               |
| `cert.pem`        | PEM    | Same certificate as `certificate.der`, but in PEM encoding (Base64) |
| `private_key.pem` | PEM    | Private key for the certificate                                     |
| `gost.conf`       | config | OpenSSL configuration to enable GOST algorithm support              |

## Building Your Own Certificate with GOST Algorithms

To work with GOST keys and certificates, you need OpenSSL built with GOST engine support. Most Linux distributions have GOST support enabled by default (via the `openssl-gost` package or a built-in `gost` engine).

### 1. OpenSSL Configuration

The `gost.conf` file enables the built-in `gost` engine and sets cryptographic transformation parameters.

- `engine_id = gost` — name of the built-in OpenSSL algorithm engine
- `default_algorithms = ALL` — the engine intercepts all supported algorithms
- `CRYPT_PARAMS = id-Gost28147-89-CryptoPro-A-ParamSet` — encryption parameter set per GOST 28147-89 (cryptographic transformation "A")

Without this configuration, OpenSSL will not be able to generate keys, sign, or read a certificate with GOST algorithms.

### 2. Generating a Private Key

```bash
openssl genpkey -engine gost \
  -algorithm gost2012_256 \
  -pkeyopt paramset:A \
  -out mykey.pem
```

Parameters:
- `-engine gost` — use the GOST engine
- `-algorithm gost2012_256` — GOST R 34.10-2012 algorithm with 256-bit key length
- `-pkeyopt paramset:A` — elliptic curve parameter set (CryptoPro A)

For the GOST R 34.10-2001 algorithm, use `-algorithm gost2001`:

```bash
openssl genpkey -engine gost \
  -algorithm gost2001 \
  -pkeyopt paramset:A \
  -out mykey.pem
```

### 3. Creating a Self-Signed Certificate

```bash
openssl req -engine gost \
  -x509 \
  -new \
  -key mykey.pem \
  -days 3650 \
  -out mycert.pem \
  -subj "/C=RU/O=MyOrg/CN=My GOST Certificate" \
  -config gost.conf \
  -sigopt paramset:A
```

### 4. Exporting to DER Format

The `gostcert` library expects DER-encoded input. Convert PEM to DER:

```bash
openssl x509 -in mycert.pem -inform PEM \
  -out mycert.der -outform DER
```

### 5. Using in Tests

Place the resulting `mycert.der` into `test/resources/certs/` and reference it in your test:

```go
const testCertPath = "test/resources/certs/mycert.der"
```

## Inspecting an Existing Certificate

View the contents of a DER certificate:

```bash
openssl x509 -in certificate.der -inform DER -text -noout
```

Check signature and key algorithms:

```bash
openssl x509 -in certificate.der -inform DER -text -noout | grep -E "Signature Algorithm|Public Key Algorithm"
```

## Notes

- The `gostcert` library parses only DER format. PEM files (`cert.pem`) are kept for easy viewing and conversion.
- The test certificate is signed with GOST R 34.11-2012 (256-bit) + GOST R 34.10-2001 algorithms.
- The private key (`private_key.pem`) is not used in `gostcert` tests — it is only needed for generating new certificates.
- To work with OpenSSL on macOS, you may need to install OpenSSL via Homebrew (`brew install openssl`) — the system version of LibreSSL does not support the GOST engine.
