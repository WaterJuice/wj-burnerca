# ----------------------------------------------------------------------------------------
#   verify.py
#   ---------
#
#   Chain verification for the issued cert. Wraps `openssl verify -CAfile`.
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

from pathlib import Path
from wj_burnerca import openssl

# ----------------------------------------------------------------------------------------
#   Exceptions
# ----------------------------------------------------------------------------------------


class VerificationError(RuntimeError):
    """Raised when the issued cert does not verify against the freshly generated root."""


# ----------------------------------------------------------------------------------------
#   Public API
# ----------------------------------------------------------------------------------------


# ----------------------------------------------------------------------------------------
def verify_chain(root_cert: Path, cert: Path) -> None:
    """Verify `cert` chains to `root_cert`. Raise on failure.

    `openssl verify` exits 0 only if the cert passed, and prints `<path>: OK` on stdout.
    We check both.
    """
    result = openssl.run([
        "verify",
        "-CAfile", str(root_cert),
        str(cert),
    ])  # fmt: skip
    last_line = result.stdout.strip().splitlines()[-1] if result.stdout else ""
    if not last_line.endswith(": OK"):
        raise VerificationError(
            f"openssl verify did not report OK for {cert.name}: {last_line or '(empty)'}"
        )
