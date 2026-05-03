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
