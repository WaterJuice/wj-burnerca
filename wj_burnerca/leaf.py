# ----------------------------------------------------------------------------------------
#   leaf.py
#   -------
#
#   Issuance of the single leaf certificate from the burner root CA.
#
#   The leaf has two SANs: the bare domain (`example.test`) and its wildcard
#   (`*.example.test`). One keypair, one cert.
#
#   ECDSA P-256 — the strongest modern curve available on both OpenSSL 3.x and the
#   LibreSSL 3.3.x that ships with macOS.
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

from dataclasses import dataclass
from pathlib import Path
from wj_burnerca import openssl
from wj_burnerca.ca import RootCA

# ----------------------------------------------------------------------------------------
#   Types
# ----------------------------------------------------------------------------------------


@dataclass
class IssuedCert:
    """Paths and SAN list for the issued leaf cert."""

    domain: str
    sans: list[str]
    key_path: Path
    cert_path: Path


# ----------------------------------------------------------------------------------------
#   Public API
# ----------------------------------------------------------------------------------------


# ----------------------------------------------------------------------------------------
def issue_cert(workdir: Path, root: RootCA, *, domain: str, days: int) -> IssuedCert:
    """Generate a keypair, CSR, and signed leaf cert for `domain` and `*.domain`."""
    sans = [domain, f"*.{domain}"]
    stem = domain

    key_path = workdir / f"{stem}.key"
    csr_path = workdir / f"{stem}.csr"
    cert_path = workdir / f"{stem}.crt"
    ext_path = workdir / f"{stem}.ext.cnf"

    ext_path.write_text(_render_extensions(sans))

    # ECDSA P-256 with named-curve encoding — see ca.py for why the latter matters.
    openssl.run([
        "genpkey",
        "-algorithm", "EC",
        "-pkeyopt", "ec_paramgen_curve:P-256",
        "-pkeyopt", "ec_param_enc:named_curve",
        "-out", str(key_path),
    ])  # fmt: skip
    key_path.chmod(0o600)

    # Subject CN is the bare domain; modern verifiers ignore CN entirely and use SANs,
    # but populating it keeps `openssl x509 -text` output readable.
    openssl.run([
        "req",
        "-new",
        "-key", str(key_path),
        "-subj", f"/CN={domain}",
        "-out", str(csr_path),
    ])  # fmt: skip

    serial = openssl.random_serial_hex()
    openssl.run([
        "x509",
        "-req",
        "-in", str(csr_path),
        "-CA", str(root.cert_path),
        "-CAkey", str(root.key_path),
        "-set_serial", f"0x{serial}",
        "-days", str(days),
        "-sha256",
        "-extfile", str(ext_path),
        "-out", str(cert_path),
    ])  # fmt: skip

    return IssuedCert(domain=domain, sans=sans, key_path=key_path, cert_path=cert_path)


# ----------------------------------------------------------------------------------------
#   Internal
# ----------------------------------------------------------------------------------------


# ----------------------------------------------------------------------------------------
def _render_extensions(sans: list[str]) -> str:
    """Render the openssl extensions config for the leaf cert."""
    san_lines = ", ".join(f"DNS:{s}" for s in sans)
    return f"""\
basicConstraints       = critical, CA:FALSE
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = serverAuth
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid, issuer
subjectAltName         = {san_lines}
"""
