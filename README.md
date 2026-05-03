# wj-burnerca

A WaterJuice tool for generating single-shot, name-constrained,
self-destroying Certificate Authorities for local development TLS.

`wj-burnerca` is a one-shot CLI. You give it one domain. It:

1. Generates a root Certificate Authority constrained — cryptographically
   — to that single domain.
2. Issues one cert covering both `<domain>` and `*.<domain>`.
3. Verifies the chain.
4. **Destroys the CA private key.**
5. Outputs the public CA certificate and the cert/key pair.

To get more certs, you generate a fresh CA and re-trust it. There is no
"reuse this CA" workflow by design.

The metaphor is a **burner phone**: single-purpose, used briefly,
intentionally discarded.

## Why

Dev environments need real TLS to mirror production faithfully. The
conventional approach is to install a long-lived root CA into your
system trust store; that CA's private key then sits on your laptop
indefinitely and can sign certs for *any* domain. If it leaks, the
attacker can MITM anything you visit.

`wj-burnerca` narrows this in two complementary ways:

- **Name constraints (RFC 5280, marked critical):** the CA is
  cryptographically incapable of signing certs outside the one domain
  you gave it. Browsers and modern TLS libraries enforce this.
- **Key destruction:** after issuing the cert, the CA private key is
  securely deleted.

## Installation

```bash
# One-shot via uvx
uvx wj-burnerca example.test

# Or install
uv pip install wj-burnerca
pip install wj-burnerca
```

Requires Python 3.14+ and an `openssl` binary on `PATH` (LibreSSL 3.x as
shipped by macOS, or OpenSSL 3.x).

## Usage

```bash
# The simple case — one domain, default 365-day validity, output to ./<domain>/
uvx wj-burnerca example.test

# Pick a shorter validity
uvx wj-burnerca example.test --days 30

# Pick where to put the output
uvx wj-burnerca example.test --out ./dev/ca/

# Overwrite an existing output dir
uvx wj-burnerca example.test --out ./dev/ca/ --force
```

After a successful run, the output directory contains:

```
<out>/
  rootCA-<domain>.crt     # public CA cert; trust this
  <domain>.crt            # cert with SANs <domain> and *.<domain>
  <domain>.key            # cert private key (mode 0600)
  MANIFEST.txt            # human-readable summary, with fingerprints
  trust-instructions.md   # per-OS trust instructions
```

The CA private key is destroyed before the tool exits.

## Trusting the CA

After a run, `<out>/trust-instructions.md` contains the right command for
your OS. Prefer **user-scoped** trust over the system trust store — the
burner CA has a bounded blast radius, but a system-wide trust install
widens *your* attack surface unnecessarily.

The simplest options that don't touch the system trust store:

```bash
# Per-shell, for Python tooling that respects SSL_CERT_FILE
export SSL_CERT_FILE="$(pwd)/rootCA-<domain>.crt"

# Per-shell, for curl
export CURL_CA_BUNDLE="$(pwd)/rootCA-<domain>.crt"
```

For browsers and tools that consult the OS keychain, the per-OS commands
in `trust-instructions.md` install into the **user** keychain only.

## Flags

| Flag             | Required | Default          | Description                                                                                                                |
|------------------|----------|------------------|----------------------------------------------------------------------------------------------------------------------------|
| `domain`         | Yes      | —                | Bare domain (e.g. `example.test`). The CA is name-constrained to this domain; the cert covers `<domain>` and `*.<domain>`. |
| `--days N`       | No       | `365`            | Validity for both the CA and the cert (they expire together). Range 1–365.                                                 |
| `--out DIR`      | No       | `./<domain>/`    | Output directory.                                                                                                          |
| `--force`        | No       | off              | Overwrite an existing non-empty `--out` directory.                                                                         |

That's it.

## Exit codes

- `0` — success.
- `1` — argument or validation error.
- `2` — openssl subprocess failure during generation.
- `3` — chain verification failed; tempdir shredded; nothing written.
- `4` — output directory exists and is non-empty without `--force`.
- `5` — could not destroy CA private key. Path is printed loudly.

## Implementation notes

- ECDSA P-256 keys throughout. Ed25519 would be the obvious modern
  default but isn't available in the LibreSSL 3.3.x that ships with
  macOS; P-256 is the strongest curve common to both LibreSSL 3.3 and
  OpenSSL 3.x.
- Both the CA and the cert are issued with the same `--days` validity,
  so the burner CA expires when its only cert does.
- Stdlib only; openssl is invoked via subprocess.

## Development

```bash
make help       # Show all targets
make dev        # Create .venv
make check      # ruff + pyright
make format     # auto-fix
make build      # wheel + docs into output/
make docs       # HTML docs into html/
make clean      # remove build artefacts
```

## Licence

Unlicense — public domain. See [LICENSE](LICENSE).
