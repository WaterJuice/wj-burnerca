# ----------------------------------------------------------------------------------------
#   ca.py
#   -----
#
#   Root CA generation: ECDSA P-256 keypair, openssl config (with critical name
#   constraints scoped to the user's domain), self-signed cert with the same validity
#   as the leaf it will sign.
#
#   The CA private key is written into the workdir only and is destroyed by
#   `destroy.shred_file()` before the tool exits.
#
#   We use ECDSA P-256 because it's the strongest modern curve supported by *both*
#   OpenSSL 3.x and the LibreSSL 3.3.x that ships with macOS — Ed25519 isn't in
#   LibreSSL 3.3's `genpkey -algorithm` set.
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

# ----------------------------------------------------------------------------------------
#   Types
# ----------------------------------------------------------------------------------------


@dataclass
class RootCA:
    """Paths and identifiers for a freshly generated root CA living in the workdir."""

    key_path: Path
    cert_path: Path
    common_name: str
    domain: str


# ----------------------------------------------------------------------------------------
#   Public API
# ----------------------------------------------------------------------------------------


# ----------------------------------------------------------------------------------------
def generate_root_ca(workdir: Path, *, domain: str, days: int) -> RootCA:
    """Generate the root keypair, openssl config, and self-signed root cert.

    Parameters:
        workdir: Tempdir to write all artefacts into.
        domain:  The single domain this burner CA exists to serve. Used for the CN/O
                 (`wj-burnerca: <domain>`) and as the sole permitted DNS name in the
                 critical X.509 nameConstraints extension.
        days:    Validity in days. Both the root and the leaf use the same value, so
                 the burner CA expires when its only leaf does.
    """
    common_name = f"wj-burnerca: {domain}"

    config_path = workdir / "openssl.cnf"
    config_path.write_text(_render_openssl_config(common_name, domain))

    # Domain in the filename: when a user has CAs for multiple domains, this stops
    # `rootCA.crt`s from clobbering each other if they're ever copied side by side
    # (e.g. into a system trust store).
    stem = f"rootCA-{domain}"
    key_path = workdir / f"{stem}.key"
    cert_path = workdir / f"{stem}.crt"

    # ECDSA P-256 — best modern curve available on both OpenSSL 3.x and LibreSSL 3.3.x.
    # `ec_param_enc:named_curve` is load-bearing for macOS keychain trust: without it,
    # the CA's SubjectPublicKeyInfo embeds explicit curve parameters (prime, A, B,
    # generator, order…) and Security.framework refuses to load the key. The cert is
    # otherwise valid and verifies fine on every other stack we care about.
    openssl.run([
        "genpkey",
        "-algorithm", "EC",
        "-pkeyopt", "ec_paramgen_curve:P-256",
        "-pkeyopt", "ec_param_enc:named_curve",
        "-out", str(key_path),
    ])  # fmt: skip

    serial = openssl.random_serial_hex()
    openssl.run([
        "req",
        "-x509",
        "-new",
        "-nodes",
        "-key", str(key_path),
        "-sha256",
        "-days", str(days),
        "-config", str(config_path),
        "-extensions", "v3_ca",
        "-set_serial", f"0x{serial}",
        "-out", str(cert_path),
    ])  # fmt: skip

    # Tighten permissions on the private key while it still exists.
    key_path.chmod(0o600)

    return RootCA(
        key_path=key_path,
        cert_path=cert_path,
        common_name=common_name,
        domain=domain,
    )


# ----------------------------------------------------------------------------------------
#   Internal
# ----------------------------------------------------------------------------------------


# ----------------------------------------------------------------------------------------
def _render_openssl_config(common_name: str, domain: str) -> str:
    """Render the openssl config used to self-sign the root CA.

    The `v3_ca` section is applied with `-extensions v3_ca`. The nameConstraints
    are inlined (rather than referenced from a sub-section): openssl config
    sub-sections require unique LHS keys, and the inline form is well supported by
    both OpenSSL 3.x and LibreSSL 3.3.x.
    """
    return f"""\
[ req ]
distinguished_name = req_distinguished_name
prompt             = no
string_mask        = utf8only

[ req_distinguished_name ]
CN = {common_name}
O  = {common_name}

[ v3_ca ]
basicConstraints       = critical, CA:TRUE
keyUsage               = critical, keyCertSign, cRLSign
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always, issuer
nameConstraints        = critical, permitted;DNS:{domain}
"""
