# CLAUDE.md

This file provides guidance for AI agents working on this project.

## Project Overview

**wj-burnerca** is a one-shot CLI that takes one domain, generates a
name-constrained root Certificate Authority for it, issues a single cert
covering both `<domain>` and `*.<domain>`, verifies the chain, and then
destroys the CA private key. It is designed for local development TLS
where you need a real CA but want a strictly bounded blast radius.

The metaphor is a **burner phone**: single-purpose, used briefly,
intentionally discarded.

Two safety properties are load-bearing and must not regress:

1. **Name constraints are critical.** The `nameConstraints` extension on
   the root CA must be marked `critical`. Without the critical bit, many
   trust evaluators silently ignore it.
2. **The CA private key is destroyed before exit.** There is no escape
   hatch. The key must never be copied to `--out`, even transiently. All
   CA key material lives only inside the tempdir and is removed when
   the tool exits.

A third, quieter invariant — added in Beta 2 after a macOS keychain
import bug: **EC keys must be encoded with the named-curve OID, not
explicit parameters.** `Security.framework` refuses to load EC keys
whose SubjectPublicKeyInfo embeds the explicit P-256 prime/A/B/
generator/order block (`errSecInvalidKeyRef`, -67712), which made
Beta 1's CA un-importable via Keychain Access and
`security add-trusted-cert`. The fix is `-pkeyopt
ec_param_enc:named_curve` on every `genpkey` call — see the comment in
`ca.py`. If you ever change how keys are minted, verify with
`openssl x509 -text` that the pubkey dump shows
`ASN1 OID: prime256v1` rather than the long
`Field Type / Prime / A / B / Generator / Order` block.

Surface area is intentionally tiny. The CLI takes one positional
`domain` argument plus `--days`, `--out`, `--force`. Don't add flags
without a clear, repeated user need: every flag is an opportunity to
hold the tool wrong.

## Constraints

- **Stdlib only.** No third-party Python dependencies. `openssl` is
  invoked via `subprocess`.
- **macOS and Linux only.** Code should be POSIX-portable; we don't ship
  Windows support. macOS users may have either Homebrew OpenSSL 3.x or
  the system LibreSSL 3.3.x — the tool must work with both.
- **ECDSA P-256 keys.** Ed25519 would be the obvious modern choice but
  isn't available in LibreSSL 3.3.x; P-256 is the strongest curve common
  to both libraries. Don't try to switch without confirming LibreSSL 3.3
  support first.
- **Python 3.14+**.
- **Auditable.** First-party code is around 700 LOC — small enough to
  read in one sitting before trusting it.

## Language and Spelling

Use **Australian English** throughout:

- sanitise (not sanitize)
- initialise (not initialize)
- colour (not color)
- organisation (not organization)
- analyse (not analyze)
- licence (noun) / license (verb)

## Code Style

### Python Files

Every Python file should have:

1. A file header block with description, copyright, and version
   history.
2. Section headers separating major sections (Imports, Constants,
   Functions, etc.).
3. Horizontal separators (96 chars) above each function definition.

### General

- Python 3.14+
- Use type hints throughout
- Prefer `pathlib.Path` over `os.path`
- Single-line imports, no blank lines between import groups
- Run `make format` to auto-fix import ordering and formatting

## openssl portability notes

macOS ships LibreSSL 3.3.x at `/usr/bin/openssl`. Homebrew installs
OpenSSL 3.x at `/opt/homebrew/bin/openssl`. The tool uses `shutil.which`
to find whichever is on `PATH`.

When writing openssl invocations:

- Use a config file written into the tempdir for extensions
  (`-config`, `-extensions`). Do **not** rely on `-addext` — it behaves
  differently between LibreSSL and OpenSSL.
- `openssl genpkey` and `openssl req`/`openssl x509` are available on
  both. Stick to the common subset.
- `openssl verify -CAfile <root> <leaf>` works identically.

## Common Commands

```bash
make help       # Show all available targets
make check      # Run ruff + pyright
make format     # Auto-fix and format code
make build      # Build wheel + docs into output/
make docs       # Build HTML documentation into html/
make clean      # Remove build artefacts
make dev        # Just create dev (.venv) setup
make publish    # Publish output/ to PyPI and docs
```

## Project Structure

```
wj-burnerca/
├── wj_burnerca/             # Main package
│   ├── __init__.py          # Package init with version
│   ├── __main__.py          # Entry point for python -m wj_burnerca
│   ├── version.py           # Version handling (reads generated _version.py)
│   ├── cli.py               # CLI parsing + dispatch
│   ├── ca.py                # Root CA key + cert (constraint scoped to domain)
│   ├── leaf.py              # Cert key + CSR + signed cert (SANs: domain + *.domain)
│   ├── verify.py            # Chain verification
│   ├── destroy.py           # Overwrite-then-unlink for the CA key
│   ├── manifest.py          # MANIFEST.txt + trust-instructions.md
│   ├── openssl.py           # Thin wrapper over openssl subprocess
│   ├── paths.py             # Tempdir + atomic output staging
│   └── argbuilder.py        # WaterJuice argparse helper (shared across projects)
├── docs/                    # Documentation source
│   ├── mkdocs.yml           # MkDocs config
│   ├── docinfo.json         # Project metadata for docs
│   └── mkdocs/              # Documentation content
│       ├── index.md         # Main documentation page
│       └── license.md       # Licence page
├── tests/                   # pytest tests (stdlib + openssl only)
├── Makefile                 # Build automation
├── pyproject.toml           # Project metadata and tool config
├── README.md                # Project readme
├── LICENSE                  # Unlicense
├── blog.md                  # Draft blog post for waterjuiceweb.wordpress.com
└── CLAUDE.md                # This file
```

## Testing Changes

After making changes:

1. Run `make check` to verify linting and types pass.
2. Run `uv run pytest` to run the test suite.
3. Run `make build` to verify the full build works.
4. Smoke-test with `uv run wj-burnerca example.test --out /tmp/burner-smoke --force`
   then `openssl x509 -in /tmp/burner-smoke/rootCA-example.test.crt -text -noout`.

## Versioning

- Version is derived from git tags via the Makefile.
- Create a tag like `0.1.0` or `0.1.0b2` before running `make build` for
  a release (no `v` prefix).
- The Makefile generates `_version.py` at build time, which is not
  committed.
- If no tags exist, version falls back to a commit-based dev format.

## Commits

- Use clear, descriptive commit messages.
- Include `Co-Authored-By: Claude Opus 4.7 <noreply@anthropic.com>` in
  commits made with AI assistance.
- **Never rewrite git history** unless explicitly asked.

## Licence

Unlicense — public domain. See LICENSE.
