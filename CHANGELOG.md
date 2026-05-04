# wj-burnerca 1.0.0 Beta 2 - 4 May 2026

## Fixed

- **EC keys are now generated with named-curve parameter encoding.**
  Beta 1 minted the CA and leaf keys with `genpkey -algorithm EC
  -pkeyopt ec_paramgen_curve:P-256`, which (on both OpenSSL 3.x and
  LibreSSL 3.3.x) produced keys whose SubjectPublicKeyInfo embedded
  the explicit P-256 curve parameters (prime, A, B, generator, order,
  cofactor, seed) inline rather than just the named-curve OID. macOS's
  `Security.framework` refuses to load such keys
  (`errSecInvalidKeyRef`, -67712), so the CA cert was un-importable
  via Keychain Access and `security add-trusted-cert`. Both `genpkey`
  calls now also pass `-pkeyopt ec_param_enc:named_curve`, producing
  certs whose pubkey dump shows `ASN1 OID: prime256v1` /
  `NIST CURVE: P-256`. The cert verified fine on every other stack
  (OpenSSL, Go, Python `ssl`, `curl`/`SSL_CERT_FILE`) before this fix
  too — this was a macOS-specific encoding gripe.

# wj-burnerca 1.0.0 Beta 1 - 3 May 2026

Initial release.

## Features

- One positional `domain` argument; the tool generates a name-constrained
  CA scoped to that domain and issues a single cert covering both
  `<domain>` and `*.<domain>`.
- Critical X.509 `nameConstraints` extension on the CA so it is
  cryptographically incapable of signing for any other domain.
- CA private key is deleted before the tool exits — there is no escape
  hatch.
- CA validity matches cert validity (`--days`, default 365, max 365), so
  the burner CA expires when its only cert does.
- ECDSA P-256 keys (Ed25519 isn't supported by the LibreSSL 3.3.x that
  ships with macOS).
- Atomic output staging via tempdir + move; failures leave `--out`
  untouched.
- Generates `MANIFEST.txt` (with SHA-256 fingerprints and validity dates)
  and per-OS `trust-instructions.md` alongside the certs.
- Stdlib-only Python 3.14+; uses the system `openssl` binary via
  subprocess. Tested against macOS LibreSSL 3.3.x and OpenSSL 3.x.
