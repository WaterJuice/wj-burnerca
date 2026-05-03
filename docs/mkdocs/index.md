# wj-burnerca

A WaterJuice tool for generating single-shot, name-constrained,
self-destroying Certificate Authorities for local development TLS.

You give it one domain. It generates a CA constrained to that domain,
issues a cert covering both `<domain>` and `*.<domain>`, verifies the
chain, and **destroys the CA private key** before exiting.

The metaphor is a **burner phone**: single-purpose, used briefly,
intentionally discarded.

## Why

The conventional approach to local TLS — installing a long-lived,
unconstrained root CA into your system trust store — leaves that CA's
private key on your laptop indefinitely. It can sign certs for *any*
domain. If it leaks, the attacker can MITM anything you visit.

`wj-burnerca` narrows this in two complementary ways:

- **Name constraints (RFC 5280, marked critical):** the CA is
  cryptographically incapable of signing certs outside the one domain
  you gave it. Modern TLS libraries and browsers enforce this.
- **Key destruction:** after issuing the cert, the CA private key is
  securely deleted.

## Installation

```bash
uvx wj-burnerca example.test
# or
uv pip install wj-burnerca
pip install wj-burnerca
```

Requires Python 3.14+ and an `openssl` binary on `PATH` (LibreSSL 3.x
as shipped by macOS, or OpenSSL 3.x — both work).

## Quick Start

```bash
# Default: 365-day validity, output to ./<domain>/
uvx wj-burnerca example.test

# Shorter validity
uvx wj-burnerca example.test --days 30

# Custom output dir
uvx wj-burnerca example.test --out ./dev/ca/
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

## Trusting the CA

Open `<out>/trust-instructions.md` for the right command for your OS.
Prefer **user-scoped** trust over the system trust store.

```bash
export SSL_CERT_FILE="$(pwd)/rootCA-<domain>.crt"   # Python tooling
export CURL_CA_BUNDLE="$(pwd)/rootCA-<domain>.crt"  # curl
```

## Security model

| Threat                                                | Mitigation                                                                                                                |
|-------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------|
| CA key stolen → forge certs for arbitrary domains     | Critical X.509 nameConstraints — CA cryptographically incapable.                                                          |
| CA key stolen at any time after issuance              | CA key destroyed at end of run; not on disk to steal.                                                                     |
| Leaf key stolen → MITM the constrained domain         | Accepted; mitigated by short validity and the fact that the constrained domain typically only resolves via `/etc/hosts`.  |
| Half-completed run leaves CA key on disk              | All work happens in a tempdir; outputs are moved into place only after chain verification; tempdir is shredded otherwise. |

## Implementation notes

- ECDSA P-256 keys throughout. Ed25519 would be the obvious modern
  default but isn't available in the LibreSSL 3.3.x that ships with
  macOS; P-256 is the strongest curve common to both libraries.
- The CA validity matches the cert validity, so the burner CA expires
  when its only cert does.

## Exit codes

- `0` — success.
- `1` — argument or validation error.
- `2` — openssl subprocess failure during generation.
- `3` — chain verification failed; tempdir shredded; `--out` untouched.
- `4` — `--out` directory exists and is non-empty without `--force`.
- `5` — could not destroy CA private key. Path is printed loudly.

## CLI Reference

```
--8<-- "_generated_command_line_help.txt"
```
