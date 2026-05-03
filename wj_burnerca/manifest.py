# ----------------------------------------------------------------------------------------
#   manifest.py
#   -----------
#
#   Generates MANIFEST.txt and trust-instructions.md alongside the certs.
#
#   MANIFEST.txt summarises what was issued, with SHA-256 fingerprints and validity
#   dates, so the user can sanity-check before trusting rootCA.crt.
#   trust-instructions.md is the per-OS guide.
#
#   (c) 2026 WaterJuice — Unlicense; see LICENSE in the project root.
#
#   Version History
#   ---------------
#   May 2026 - Created
# ----------------------------------------------------------------------------------------

# ----------------------------------------------------------------------------------------
#   Imports
# ----------------------------------------------------------------------------------------

import base64
import hashlib
import platform
from datetime import UTC
from datetime import datetime
from pathlib import Path
from wj_burnerca import openssl
from wj_burnerca.ca import RootCA
from wj_burnerca.leaf import IssuedCert
from wj_burnerca.version import VERSION_STR

# ----------------------------------------------------------------------------------------
#   Public API
# ----------------------------------------------------------------------------------------


# ----------------------------------------------------------------------------------------
def write_manifest(workdir: Path, root: RootCA, cert: IssuedCert) -> Path:
    """Write MANIFEST.txt into the workdir and return its path."""
    path = workdir / "MANIFEST.txt"
    path.write_text(_render_manifest(root, cert))
    return path


# ----------------------------------------------------------------------------------------
def write_trust_instructions(workdir: Path, root: RootCA) -> Path:
    """Write trust-instructions.md into the workdir and return its path."""
    path = workdir / "trust-instructions.md"
    path.write_text(_render_trust_instructions(root))
    return path


# ----------------------------------------------------------------------------------------
#   Rendering
# ----------------------------------------------------------------------------------------


# ----------------------------------------------------------------------------------------
def _render_manifest(root: RootCA, cert: IssuedCert) -> str:
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    host = platform.node() or "(unknown)"

    root_validity = _read_validity(root.cert_path)
    cert_validity = _read_validity(cert.cert_path)
    root_fp = _sha256_fingerprint(root.cert_path)
    cert_fp = _sha256_fingerprint(cert.cert_path)
    san_list = ", ".join(cert.sans)

    return (
        f"wj-burnerca — generated {now}\n"
        f"Hostname: {host}\n"
        f"Tool version: {VERSION_STR}\n"
        f"Domain: {root.domain}\n"
        "\n"
        "Root CA:\n"
        f"  Subject:       CN={root.common_name}, O={root.common_name}\n"
        f"  Validity:      {root_validity[0]} → {root_validity[1]}\n"
        "  Name constraints (critical):\n"
        f"    permitted DNS: {root.domain}\n"
        f"  SHA-256 fingerprint: {root_fp}\n"
        "  Private key: DESTROYED\n"
        "\n"
        "Certificate:\n"
        f"  File: {cert.cert_path.name}\n"
        f"  SANs: {san_list}\n"
        f"  Validity: {cert_validity[0]} → {cert_validity[1]}\n"
        f"  SHA-256 fingerprint: {cert_fp}\n"
    )


# ----------------------------------------------------------------------------------------
def _read_validity(cert_path: Path) -> tuple[str, str]:
    """Return (notBefore, notAfter) as ISO-ish dates by asking openssl to print them."""
    result = openssl.run([
        "x509",
        "-in", str(cert_path),
        "-noout",
        "-startdate",
        "-enddate",
    ])  # fmt: skip
    not_before = ""
    not_after = ""
    for line in result.stdout.splitlines():
        if line.startswith("notBefore="):
            not_before = _format_openssl_date(line.split("=", 1)[1].strip())
        elif line.startswith("notAfter="):
            not_after = _format_openssl_date(line.split("=", 1)[1].strip())
    return (not_before, not_after)


# ----------------------------------------------------------------------------------------
def _format_openssl_date(raw: str) -> str:
    """Convert openssl's `Mon DD HH:MM:SS YYYY GMT` into `YYYY-MM-DD`."""
    try:
        dt = datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z")
    except ValueError:
        return raw
    return dt.strftime("%Y-%m-%d")


# ----------------------------------------------------------------------------------------
def _sha256_fingerprint(cert_path: Path) -> str:
    """Return the SHA-256 fingerprint of a PEM-encoded cert as colon-separated hex."""
    der = _pem_to_der(cert_path.read_bytes())
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


# ----------------------------------------------------------------------------------------
def _pem_to_der(pem: bytes) -> bytes:
    """Strip PEM armour and base64-decode to DER. First cert in the file only."""
    text = pem.decode("ascii")
    in_block = False
    body: list[str] = []
    for line in text.splitlines():
        if line.startswith("-----BEGIN CERTIFICATE-----"):
            in_block = True
            continue
        if line.startswith("-----END CERTIFICATE-----"):
            break
        if in_block:
            body.append(line.strip())
    return base64.b64decode("".join(body))


# ----------------------------------------------------------------------------------------
#   Trust instructions content
# ----------------------------------------------------------------------------------------


# ----------------------------------------------------------------------------------------
def _render_trust_instructions(root: RootCA) -> str:
    """Render trust-instructions.md, customised with the CA's filename and CN.

    The system-trust-store install destinations include the domain so that
    multiple burner CAs can cohabit a single trust store without clobbering
    each other.
    """
    cert_file = root.cert_path.name  # rootCA-<domain>.crt
    cn = root.common_name  # wj-burnerca: <domain>
    install_stem = f"wj-burnerca-{root.domain}"  # used as the trust-store filename

    return f"""\
# Trusting your burner CA

The burner CA's public certificate is `{cert_file}` in this directory.
You only need to trust the root — the cert chains to it automatically.

**Prefer user-scoped trust over the system trust store.** A burner CA
already has a bounded blast radius (name constraints + destroyed key),
but installing it system-wide widens *your* attack surface
unnecessarily. Pick the narrowest option that works for the tools you
actually need.

## Per-shell (narrowest)

For Python tooling that respects the standard env vars (`pip`,
`requests`, `httpx`, `uv`, …):

```bash
export SSL_CERT_FILE="$(pwd)/{cert_file}"
```

For `curl`:

```bash
export CURL_CA_BUNDLE="$(pwd)/{cert_file}"
```

These last only as long as the shell session. When you close the shell,
trust is gone.

## macOS — user keychain

```bash
security add-trusted-cert \\
    -k ~/Library/Keychains/login.keychain-db \\
    {cert_file}
```

To remove later, find "{cn}" in Keychain Access under
"login → Certificates" and delete it, or run:

```bash
security delete-certificate -c "{cn}" \\
    ~/Library/Keychains/login.keychain-db
```

## Linux — Debian / Ubuntu (system-wide)

```bash
sudo cp {cert_file} /usr/local/share/ca-certificates/{install_stem}.crt
sudo update-ca-certificates
```

To remove:

```bash
sudo rm /usr/local/share/ca-certificates/{install_stem}.crt
sudo update-ca-certificates --fresh
```

## Linux — Fedora / RHEL (system-wide)

```bash
sudo cp {cert_file} /etc/pki/ca-trust/source/anchors/{install_stem}.crt
sudo update-ca-trust
```

To remove:

```bash
sudo rm /etc/pki/ca-trust/source/anchors/{install_stem}.crt
sudo update-ca-trust
```

## Firefox

Firefox keeps its own trust store and ignores the OS one.

1. Open `about:preferences#privacy`
2. Scroll to **Certificates** → **View Certificates…**
3. Switch to the **Authorities** tab → **Import…**
4. Select `{cert_file}`
5. Tick "Trust this CA to identify websites"

To remove later, find "{cn}" in that list and delete it.
"""
