# ----------------------------------------------------------------------------------------
#   openssl.py
#   ----------
#
#   Thin wrapper over the `openssl` subprocess. Exposes a single `run()` helper that
#   raises a structured error on non-zero exit, plus small x509-adjacent helpers
#   (`random_serial_hex`, `fit_name`) that both ca.py and leaf.py need.
#
#   Tested against macOS LibreSSL 3.3.x and OpenSSL 3.x. The wrapper sticks to the
#   common subset of subcommands (`genpkey`, `req`, `x509`, `verify`) so both
#   implementations work without flag-shimming.
#
#   (c) 2026 WaterJuice — Unlicense; see LICENSE in the project root.
#
#   Version History
#   ---------------
#   May 2026 - Created
#   Nov 2026 - Added fit_name() for the 64-character X.509 name limit
# ----------------------------------------------------------------------------------------

# ----------------------------------------------------------------------------------------
#   Imports
# ----------------------------------------------------------------------------------------

import secrets
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

# ----------------------------------------------------------------------------------------
#   Constants
# ----------------------------------------------------------------------------------------

# X.509 caps commonName and organizationName at 64 characters (RFC 5280's
# ub-common-name and ub-organization-name), and openssl refuses longer values with
# `string too long`.
MAX_NAME_LEN = 64

# ----------------------------------------------------------------------------------------
#   Module state
# ----------------------------------------------------------------------------------------

# Resolved openssl path, cached on first lookup. None until find_openssl() runs.
_openssl_path: str | None = None

# ----------------------------------------------------------------------------------------
#   Exceptions
# ----------------------------------------------------------------------------------------


class OpenSSLNotFoundError(RuntimeError):
    """Raised when no `openssl` binary can be found on PATH."""


@dataclass
class OpenSSLError(RuntimeError):
    """Raised when an `openssl` subprocess exits non-zero."""

    argv: list[str]
    returncode: int
    stdout: str
    stderr: str

    def __str__(self) -> str:
        cmd = " ".join(self.argv)
        return (
            f"openssl exited {self.returncode}\n"
            f"  command: {cmd}\n"
            f"  stderr:  {self.stderr.strip() or '(empty)'}"
        )


# ----------------------------------------------------------------------------------------
#   Discovery
# ----------------------------------------------------------------------------------------


# ----------------------------------------------------------------------------------------
def find_openssl() -> str:
    """Locate (and cache) the `openssl` binary on PATH.

    Returns the absolute path. Raises OpenSSLNotFoundError if not present.
    """
    global _openssl_path
    if _openssl_path is None:
        path = shutil.which("openssl")
        if path is None:
            raise OpenSSLNotFoundError(
                "Could not find `openssl` on PATH. Install it (macOS: "
                "`brew install openssl` or use the system /usr/bin/openssl; "
                "Linux: your distro's `openssl` package)."
            )
        _openssl_path = path
    return _openssl_path


# ----------------------------------------------------------------------------------------
#   Helpers
# ----------------------------------------------------------------------------------------


# ----------------------------------------------------------------------------------------
def random_serial_hex() -> str:
    """Return a random 159-bit positive integer hex-encoded for `-set_serial`.

    159 bits keeps the high bit clear so the DER encoding is unambiguously positive.
    """
    return f"{secrets.randbits(159):040x}"


# ----------------------------------------------------------------------------------------
def fit_name(prefix: str, domain: str, suffix: str = "") -> str:
    """Return `prefix + domain + suffix`, shortened to fit an X.509 name field.

    If it's over MAX_NAME_LEN, the start of the domain is replaced with `...`, which
    keeps the more recognisable right-hand end. This is only for display names (CN
    and O): the SANs and name constraints always carry the full domain.
    """
    room = MAX_NAME_LEN - len(prefix) - len(suffix)
    if len(domain) > room:
        domain = "..." + domain[-(room - 3) :]
    return f"{prefix}{domain}{suffix}"


# ----------------------------------------------------------------------------------------
#   Runner
# ----------------------------------------------------------------------------------------


@dataclass
class OpenSSLResult:
    """Captured output from a successful openssl invocation."""

    stdout: str
    stderr: str


# ----------------------------------------------------------------------------------------
def run(
    args: list[str],
    *,
    cwd: Path | None = None,
    stdin: str | None = None,
) -> OpenSSLResult:
    """Run `openssl <args...>` and return captured stdout/stderr.

    Parameters:
        args:  Arguments to pass to openssl (without the binary name itself).
        cwd:   Working directory for the subprocess. Defaults to the current directory.
        stdin: Optional string to write to the subprocess stdin.

    Returns:
        OpenSSLResult with decoded stdout and stderr.

    Raises:
        OpenSSLError on non-zero exit.
    """
    argv = [find_openssl(), *args]
    proc = subprocess.run(
        argv,
        cwd=cwd,
        input=stdin,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise OpenSSLError(
            argv=argv,
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
        )
    return OpenSSLResult(stdout=proc.stdout, stderr=proc.stderr)
