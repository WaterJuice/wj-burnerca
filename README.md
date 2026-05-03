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
  deleted.

## Installation

```bash
# One-shot, no install — fetches into a cache and runs:
uvx wj-burnerca example.com

# Install globally with uv:
uv tool install wj-burnerca

# Install globally with pipx:
pipx install wj-burnerca
```

Requires Python 3.14+ and an `openssl` binary on `PATH` (LibreSSL 3.x as
shipped by macOS, or OpenSSL 3.x).

## Usage

```bash
# The simple case — one domain, default 365-day validity, output to ./<domain>/
wj-burnerca example.com

# Pick a shorter validity
wj-burnerca example.com --days 30

# Pick where to put the output
wj-burnerca example.com --out ./dev/ca/

# Overwrite an existing output dir
wj-burnerca example.com --out ./dev/ca/ --force
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
| `domain`         | Yes      | —                | Bare domain (e.g. `example.com`). The CA is name-constrained to this domain; the cert covers `<domain>` and `*.<domain>`. |
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

## Using with `tls-switch`

The cert and key drop straight into [`tls-switch`](https://github.com/WaterJuice/tls-switch)'s
`terminate` mode. Because the cert covers `<domain>` and `*.<domain>`,
multiple SNI hostnames can share a single cert/key pair:

```json
{
  "listen": ":443",
  "hosts": {
    "example.com": {
      "mode": "terminate",
      "cert": "/path/to/example.com/example.com.crt",
      "key":  "/path/to/example.com/example.com.key",
      "backend": "127.0.0.1:8080"
    },
    "app.example.com": {
      "mode": "terminate",
      "cert": "/path/to/example.com/example.com.crt",
      "key":  "/path/to/example.com/example.com.key",
      "backend": "127.0.0.1:8081"
    }
  }
}
```

Clients still need to trust `rootCA-example.com.crt` — see
`trust-instructions.md` in the output directory.

## Implementation notes

- ECDSA P-256 keys throughout. Ed25519 would be the obvious modern
  default but isn't available in the LibreSSL 3.3.x that ships with
  macOS; P-256 is the strongest curve common to both LibreSSL 3.3 and
  OpenSSL 3.x.
- Both the CA and the cert are issued with the same `--days` validity,
  so the burner CA expires when its only cert does.
- Stdlib only; openssl is invoked via subprocess.

## FAQ

**Can I issue another cert from the existing CA?**
No — and that's the entire point. The CA's private key is destroyed
seconds after the cert is signed. To get another cert, run
`wj-burnerca` again and re-trust the new root.

**The cert just expired. What now?**
Run `wj-burnerca` again. There is no renewal path; renewals would
require a long-lived CA key, which this tool deliberately doesn't keep.

**Why ECDSA P-256 and not Ed25519?**
The LibreSSL 3.3.x that ships with macOS doesn't support Ed25519 in
its `genpkey -algorithm` set. P-256 is the strongest curve available
on both LibreSSL 3.3 and OpenSSL 3.x.

**Can the cert cover `foo.bar.example.com`?**
Not from a single `wj-burnerca example.com` run — the wildcard SAN
`*.example.com` only matches one DNS label per RFC 6125. For
two-level depth, run `wj-burnerca bar.example.com`, which covers
both `bar.example.com` and `*.bar.example.com`. The CA's name
constraint (`permitted;DNS:bar.example.com`) still keeps the blast
radius bounded.

**Can I get a cert for an IP address?**
No. IP addresses need a `subjectAltName=IP:` SAN, not `DNS:`. The
tool refuses dotted-quad input rather than mis-issue a `DNS:` SAN
that nothing will validate.

**Why doesn't the tool install the CA into my trust store for me?**
The whole appeal of a burner CA is its narrow blast radius; installing
it system-wide expands *your* attack surface unnecessarily. Per-shell
`SSL_CERT_FILE` or the user keychain are usually enough, and they're
easy to remove. If you want system-wide trust, the right `cp` /
`update-ca-*` command is in `trust-instructions.md` — but you should
have to type it yourself.

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
