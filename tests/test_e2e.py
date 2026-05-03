# ----------------------------------------------------------------------------------------
#   test_e2e.py
#   -----------
#
#   End-to-end happy path: run the CLI for one domain and check the outputs are
#   well-formed, the chain verifies, the cert covers `domain` + `*.domain`, and the
#   CA key is gone.
#
#   (c) 2026 WaterJuice — Unlicense.
# ----------------------------------------------------------------------------------------

from __future__ import annotations
import subprocess
from pathlib import Path
from wj_burnerca.cli import main
from .conftest import openssl_text


# ----------------------------------------------------------------------------------------
def test_happy_path(tmp_out: Path) -> None:
    rc = main(["example.test", "--out", str(tmp_out)])
    assert rc == 0, f"main exited {rc}"

    root = tmp_out / "rootCA-example.test.crt"
    cert = tmp_out / "example.test.crt"
    key = tmp_out / "example.test.key"
    assert root.is_file()
    assert cert.is_file()
    assert key.is_file()
    assert (tmp_out / "MANIFEST.txt").is_file()
    assert (tmp_out / "trust-instructions.md").is_file()

    # CA private key is GONE.
    assert not (tmp_out / "rootCA.key").exists()

    # Chain verifies.
    proc = subprocess.run(
        ["openssl", "verify", "-CAfile", str(root), str(cert)],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "OK" in proc.stdout

    # Cert has both SANs (bare + wildcard).
    text = openssl_text(cert)
    assert "DNS:example.test" in text
    assert "DNS:*.example.test" in text


# ----------------------------------------------------------------------------------------
def test_output_dir_contents_are_exact(tmp_out: Path) -> None:
    rc = main(["example.test", "--out", str(tmp_out)])
    assert rc == 0
    actual = sorted(p.name for p in tmp_out.iterdir())
    expected = sorted(
        [
            "rootCA-example.test.crt",
            "example.test.crt",
            "example.test.key",
            "MANIFEST.txt",
            "trust-instructions.md",
        ]
    )
    assert actual == expected, actual


# ----------------------------------------------------------------------------------------
def test_default_out_is_domain_dir(tmp_path: Path, monkeypatch) -> None:
    """When --out is not passed, output goes to ./<domain>/ relative to CWD."""
    monkeypatch.chdir(tmp_path)
    rc = main(["example.test"])
    assert rc == 0
    assert (tmp_path / "example.test" / "rootCA-example.test.crt").is_file()
    assert (tmp_path / "example.test" / "example.test.crt").is_file()


# ----------------------------------------------------------------------------------------
def test_ca_and_cert_share_validity(tmp_out: Path) -> None:
    """The CA must expire on the same day as the cert it signed."""
    rc = main(["example.test", "--days", "30", "--out", str(tmp_out)])
    assert rc == 0
    root_after = _not_after(tmp_out / "rootCA-example.test.crt")
    cert_after = _not_after(tmp_out / "example.test.crt")
    assert root_after == cert_after, (root_after, cert_after)


# ----------------------------------------------------------------------------------------
def _not_after(cert: Path) -> str:
    proc = subprocess.run(
        ["openssl", "x509", "-in", str(cert), "-noout", "-enddate"],
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout.strip().split("=", 1)[1]
