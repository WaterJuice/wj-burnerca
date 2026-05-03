# ----------------------------------------------------------------------------------------
#   destroy.py
#   ----------
#
#   Platform-aware secure deletion of the CA private key.
#
#   Linux:   `shred -u -z`             (overwrite + final zero pass, then unlink)
#   macOS:   `rm -P`                   (overwrite three times, then unlink)
#   Other:   plain `Path.unlink()`     (with caveat printed by the caller)
#
#   On modern SSDs with TRIM, "secure" overwrite is best-effort regardless of OS.
#   The leaf cert is the persistent risk surface, not the destroyed root; the
#   security model accepts this.
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

import shutil
import subprocess
import sys
from pathlib import Path

# ----------------------------------------------------------------------------------------
#   Module state
# ----------------------------------------------------------------------------------------

# Resolve the platform-appropriate shredder argv prefix once, at module load.
#
# `_PLATFORM: str` (rather than letting it inherit `Literal[...]` from sys.platform)
# stops pyright from narrowing the cross-platform branches to dead code on a given
# build host — every branch needs to be reachable on its own OS at runtime.
_PLATFORM: str = sys.platform


# ----------------------------------------------------------------------------------------
def _resolve_shred_prefix() -> list[str] | None:
    """Argv prefix (without the path) to invoke a real shredder, or None."""
    if _PLATFORM == "linux" and shutil.which("shred"):
        return ["shred", "-u", "-z"]
    if _PLATFORM == "darwin" and shutil.which("rm"):
        # macOS `rm -P` overwrites with three passes (0xff, 0x00, 0xff) before unlinking.
        return ["rm", "-P"]
    return None


_SHRED_PREFIX: list[str] | None = _resolve_shred_prefix()

# ----------------------------------------------------------------------------------------
#   Public API
# ----------------------------------------------------------------------------------------


# ----------------------------------------------------------------------------------------
def shred_file(path: Path) -> None:
    """Securely delete a single file.

    Picks the best available tool for the host OS and falls back to a plain
    unlink. Raises RuntimeError if the file still exists after the attempt (the
    caller treats that as exit code 5).
    """
    if _SHRED_PREFIX is not None:
        _run([*_SHRED_PREFIX, str(path)])
    else:
        path.unlink()

    if path.exists():
        raise RuntimeError(f"shred attempt completed but file still present: {path}")


# ----------------------------------------------------------------------------------------
def secure_deletion_caveat() -> str | None:
    """Return a one-line caveat string if the host can't do better than unlink.

    Returns None on Linux/macOS where we have a real shredder.
    """
    if _SHRED_PREFIX is not None:
        return None
    return (
        "Note: secure overwrite is not available on this platform; "
        "the CA key was unlinked but its blocks may remain on disk."
    )


# ----------------------------------------------------------------------------------------
#   Internal
# ----------------------------------------------------------------------------------------


# ----------------------------------------------------------------------------------------
def _run(argv: list[str]) -> None:
    """Run a shred-equivalent subprocess; raise on non-zero exit."""
    proc = subprocess.run(argv, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(
            f"{argv[0]} exited {proc.returncode}: {proc.stderr.strip() or proc.stdout.strip()}"
        )
