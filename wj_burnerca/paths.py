# ----------------------------------------------------------------------------------------
#   paths.py
#   --------
#
#   Tempdir, output-dir, and atomic-staging helpers.
#
#   The invariant this module exists to defend: nothing is written to the user's
#   `--out` directory until the chain has been verified and the tempdir is ready to be
#   moved into place wholesale. If anything fails before that point, the tempdir is
#   shredded and `--out` is left untouched.
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
import tempfile
from pathlib import Path

# ----------------------------------------------------------------------------------------
#   Constants
# ----------------------------------------------------------------------------------------

TEMPDIR_PREFIX = "wj-burnerca-"

# File extensions that are intermediates of openssl invocation and should never land
# in --out (CSRs, openssl config files, per-leaf extension files).
INTERMEDIATE_SUFFIXES: tuple[str, ...] = (".csr", ".cnf")

# ----------------------------------------------------------------------------------------
#   Tempdir
# ----------------------------------------------------------------------------------------


# ----------------------------------------------------------------------------------------
def make_workdir() -> Path:
    """Create a fresh tempdir for an in-progress burner run and return its path."""
    return Path(tempfile.mkdtemp(prefix=TEMPDIR_PREFIX))


# ----------------------------------------------------------------------------------------
def shred_workdir(workdir: Path) -> None:
    """Best-effort recursive removal of the tempdir.

    Sensitive key material is shredded by `destroy.shred_file()` before this is
    called; this just nukes the directory tree.
    """
    shutil.rmtree(workdir, ignore_errors=True)


# ----------------------------------------------------------------------------------------
#   Output dir
# ----------------------------------------------------------------------------------------


# ----------------------------------------------------------------------------------------
def output_dir_is_blocked(out: Path, *, force: bool) -> bool:
    """True if `out` exists, is non-empty, and `--force` was not passed."""
    if force:
        return False
    if not out.exists():
        return False
    if not out.is_dir():
        return True
    return any(out.iterdir())


# ----------------------------------------------------------------------------------------
def clean_intermediates(workdir: Path) -> None:
    """Remove openssl scratch files (.csr, .cnf) from the workdir before staging.

    These are needed to drive openssl but have no business landing in the user's
    output directory. Called after verification + manifest, before stage_outputs.
    """
    for item in workdir.iterdir():
        if item.is_file() and item.suffix in INTERMEDIATE_SUFFIXES:
            item.unlink()


# ----------------------------------------------------------------------------------------
def stage_outputs(workdir: Path, out: Path, *, force: bool) -> None:
    """Move every regular file from `workdir` into `out`.

    Called only after chain verification has succeeded, after intermediates have
    been cleaned, and after the CA private key has been removed from `workdir`.
    If `out` does not exist, it is created. If `out` exists and `force=True`, it
    is wiped first.
    """
    if out.exists() and force:
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)
    for item in sorted(workdir.iterdir()):
        if not item.is_file():
            continue
        dest = out / item.name
        shutil.move(str(item), str(dest))
