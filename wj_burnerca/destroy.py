# ----------------------------------------------------------------------------------------
#   destroy.py
#   ----------
#
#   Overwrite-then-unlink for the CA private key.
#
#   The file is opened in place (no truncate), overwritten with one block-aligned
#   write of `secrets.token_bytes`, fsynced, and unlinked.
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

import os
import secrets
from pathlib import Path

# ----------------------------------------------------------------------------------------
#   Constants
# ----------------------------------------------------------------------------------------

# Fallback if `os.statvfs` fails (it shouldn't on macOS/Linux, but be defensive).
_FALLBACK_BLOCK_SIZE = 4096

# ----------------------------------------------------------------------------------------
#   Public API
# ----------------------------------------------------------------------------------------


# ----------------------------------------------------------------------------------------
def shred_file(path: Path) -> None:
    """Overwrite `path` with random bytes, fsync, then unlink it.

    Raises FileNotFoundError if `path` doesn't exist. Raises RuntimeError if the
    file still exists after the unlink (the caller treats that as exit code 5).
    """
    block_size = _block_size_for(path)
    file_size = path.stat().st_size
    write_size = max(_round_up(file_size, block_size), block_size)

    fd = os.open(path, os.O_WRONLY)
    try:
        os.write(fd, secrets.token_bytes(write_size))
        os.fsync(fd)
    finally:
        os.close(fd)

    path.unlink()

    if path.exists():
        raise RuntimeError(f"unlink completed but file still present: {path}")


# ----------------------------------------------------------------------------------------
#   Internal
# ----------------------------------------------------------------------------------------


# ----------------------------------------------------------------------------------------
def _block_size_for(path: Path) -> int:
    """Return the filesystem's preferred I/O block size for `path`.

    Falls back to `_FALLBACK_BLOCK_SIZE` if `statvfs` is unavailable or returns
    something nonsensical.
    """
    try:
        bsize = os.statvfs(path).f_bsize
    except OSError:
        return _FALLBACK_BLOCK_SIZE
    return bsize if bsize > 0 else _FALLBACK_BLOCK_SIZE


# ----------------------------------------------------------------------------------------
def _round_up(value: int, multiple: int) -> int:
    """Smallest multiple of `multiple` that is >= `value`. Treats 0 as 0."""
    if value <= 0:
        return 0
    return ((value + multiple - 1) // multiple) * multiple
