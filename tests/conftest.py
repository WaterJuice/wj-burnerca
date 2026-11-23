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


# ----------------------------------------------------------------------------------------
def cert_sans(cert: Path) -> list[str]:
    """Return the cert's DNS subjectAltNames, in order."""
    lines = openssl_text(cert).splitlines()
    for i, line in enumerate(lines):
        if "X509v3 Subject Alternative Name" in line:
            return [s.strip().removeprefix("DNS:") for s in lines[i + 1].split(",")]
    return []


# ----------------------------------------------------------------------------------------
def permitted_names(cert: Path) -> list[str]:
    """Return the DNS names the cert's name constraints permit, in order."""
    names: list[str] = []
    in_permitted = False
    for line in openssl_text(cert).splitlines():
        stripped = line.strip()
        if stripped == "Permitted:":
            in_permitted = True
        elif in_permitted and stripped.startswith("DNS:"):
            names.append(stripped.removeprefix("DNS:"))
        elif in_permitted:
            break
    return names


# ----------------------------------------------------------------------------------------
def subject_cn(cert: Path) -> str:
    """Return the cert's subject commonName."""
    proc = subprocess.run(
        ["openssl", "x509", "-in", str(cert), "-noout", "-subject"]
        + ["-nameopt", "multiline"],
        capture_output=True,
        text=True,
        check=True,
    )
    for line in proc.stdout.splitlines():
        if line.strip().startswith("commonName"):
            return line.split("=", 1)[1].strip()
    raise AssertionError(f"no commonName in {proc.stdout!r}")


# ----------------------------------------------------------------------------------------
def domain_of_length(length: int) -> str:
    """Return a valid domain exactly `length` characters long, ending in `.test`."""
    labels: list[str] = []
    budget = length - len("test")  # room for the labels, each followed by a dot
    while budget > 0:
        size = min(63, budget - 1)
        assert size > 0, f"can't build a domain of length {length}"
        labels.append("a" * size)
        budget -= size + 1
    domain = ".".join([*labels, "test"])
    assert len(domain) == length, (length, domain)
    return domain
