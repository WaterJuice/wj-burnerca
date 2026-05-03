# ----------------------------------------------------------------------------------------
#   conftest.py
#   -----------
#
#   Shared pytest fixtures and helpers.
#
#   (c) 2026 WaterJuice — Unlicense.
# ----------------------------------------------------------------------------------------

from __future__ import annotations
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path
import pytest


# ----------------------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _require_openssl() -> None:
    """Skip the suite if openssl isn't available."""
    if shutil.which("openssl") is None:
        pytest.skip("openssl not on PATH")


# ----------------------------------------------------------------------------------------
@pytest.fixture
def tmp_out(tmp_path: Path) -> Iterator[Path]:
    """Yield a fresh, non-existent output directory under pytest's tmp_path."""
    out = tmp_path / "burner-out"
    yield out


# ----------------------------------------------------------------------------------------
def openssl_text(cert: Path) -> str:
    """Return `openssl x509 -in cert -text -noout` output (test helper)."""
    proc = subprocess.run(
        ["openssl", "x509", "-in", str(cert), "-text", "-noout"],
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout
