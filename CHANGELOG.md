# wj-burnerca 1.1.0 - 23 Nov 2026

## Features

- Several domains in one run: `wj-burnerca example.com example.net`. One CA is
  name-constrained to all of them, and one cert covers `<domain>` and `*.<domain>` for
  each. The output files and the CA's name come from the first domain, e.g.
  `wj-burnerca: example.com (+1 more)`.

## Changes

- The default validity (`--days`) is now 7 days for both the CA and the cert, down
  from 365. The maximum is still 365.
- Domains are lowercased, and repeated domains are dropped.

## Fixes

- Domains longer than 51 characters no longer fail with an openssl `string too long`
  error. X.509 caps the CA's and the cert's subject names at 64 characters, so long names
  are shortened there; the SANs and name constraints always carry the full domain.
- Domains longer than 251 characters (so that `*.<domain>` fits the 253-character DNS
  limit) are rejected with a clear error, as is a first domain too long to name the output
  files.
- Domains with non-ASCII characters (e.g. `exämple.test`) are rejected with a clear error,
  instead of failing chain verification. Give internationalised names in punycode
  (`xn--exmple-cua.test`).
- Usage errors caught by the argument parser, such as a missing domain or a non-numeric
  `--days`, now exit with `1` as documented, not `2` (the openssl failure code).

# wj-burnerca 1.0.1 - 13 Sep 2026

Packaging and documentation metadata tidy-up following the move to GitHub.

# wj-burnerca 1.0.0 - 30 May 2026

First official release. Moved to new GitHub location:
https://github.com/WaterJuice/wj-burnerca

## Features

- One positional `domain` argument; the tool generates a name-constrained CA scoped to
  that domain and issues a single cert covering both `<domain>` and `*.<domain>`.
- Critical X.509 `nameConstraints` extension on the CA so it is cryptographically
  incapable of signing for any other domain.
- CA private key is deleted before the tool exits — there is no escape hatch.
- CA validity matches cert validity (`--days`, default 365, max 365), so the burner CA
  expires when its only cert does.
- ECDSA P-256 keys (Ed25519 isn't supported by the LibreSSL 3.3.x that ships with macOS),
  encoded with the named-curve OID so the CA imports cleanly into the macOS keychain.
- Atomic output staging via tempdir + move; failures leave `--out` untouched.
- Generates `MANIFEST.txt` (with SHA-256 fingerprints and validity dates) and per-OS
  `trust-instructions.md` alongside the certs.
- Stdlib-only Python 3.14+; uses the system `openssl` binary via subprocess. Tested
  against macOS LibreSSL 3.3.x and OpenSSL 3.x.
