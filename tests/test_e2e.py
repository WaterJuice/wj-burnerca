# ----------------------------------------------------------------------------------------
#   test_e2e.py
#   -----------
#
#   End-to-end happy path: run the CLI for one or more domains and check the outputs
#   are well-formed, the chain verifies, the cert covers each `domain` + `*.domain`,
#   and the CA key is gone.
#
#   (c) 2026 WaterJuice — Unlicense.
# ----------------------------------------------------------------------------------------

from __future__ import annotations
import subprocess
from datetime import datetime
from datetime import timedelta
from pathlib import Path
from wj_burnerca.cli import main
from .conftest import cert_sans
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
def test_ec_keys_use_named_curve_encoding(tmp_out: Path) -> None:
    """Both certs' SubjectPublicKeyInfo must use the named-curve OID, not explicit
    parameters. macOS Security.framework refuses to load EC keys with explicit
    parameters (errSecInvalidKeyRef, -67712), which makes the CA un-importable. See
    the comment in ca.py."""
    rc = main(["example.test", "--out", str(tmp_out)])
    assert rc == 0
    for cert in ("rootCA-example.test.crt", "example.test.crt"):
        text = openssl_text(tmp_out / cert)
        assert "ASN1 OID: prime256v1" in text, (cert, text)
        # An explicit-parameters dump contains a Generator field; named-curve doesn't.
        assert "Generator" not in text, (cert, text)


# ----------------------------------------------------------------------------------------
def test_ca_and_cert_share_validity(tmp_out: Path) -> None:
    """The CA must expire on the same day as the cert it signed."""
    rc = main(["example.test", "--days", "30", "--out", str(tmp_out)])
    assert rc == 0
    root_after = _validity(tmp_out / "rootCA-example.test.crt")[1]
    cert_after = _validity(tmp_out / "example.test.crt")[1]
    assert root_after == cert_after, (root_after, cert_after)


# ----------------------------------------------------------------------------------------
def test_default_validity_is_one_week(tmp_out: Path) -> None:
    """Without --days, the CA and the cert are both valid for 7 days."""
    rc = main(["example.test", "--out", str(tmp_out)])
    assert rc == 0
    for name in ("rootCA-example.test.crt", "example.test.crt"):
        not_before, not_after = _validity(tmp_out / name)
        assert not_after - not_before == timedelta(days=7), name


# ----------------------------------------------------------------------------------------
def test_several_domains_share_one_ca_and_cert(tmp_out: Path) -> None:
    """One CA and one cert cover every domain, with the files named after the first."""
    rc = main(["a.test", "b.test", "c.test", "--out", str(tmp_out)])
    assert rc == 0, f"main exited {rc}"

    actual = sorted(p.name for p in tmp_out.iterdir())
    expected = sorted(
        [
            "rootCA-a.test.crt",
            "a.test.crt",
            "a.test.key",
            "MANIFEST.txt",
            "trust-instructions.md",
        ]
    )
    assert actual == expected, actual

    root = tmp_out / "rootCA-a.test.crt"
    cert = tmp_out / "a.test.crt"
    proc = subprocess.run(
        ["openssl", "verify", "-CAfile", str(root), str(cert)],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "OK" in proc.stdout
    assert cert_sans(cert) == [
        "a.test",
        "*.a.test",
        "b.test",
        "*.b.test",
        "c.test",
        "*.c.test",
    ]

    manifest = (tmp_out / "MANIFEST.txt").read_text()
    assert "Domains: a.test, b.test, c.test" in manifest
    for domain in ("a.test", "b.test", "c.test"):
        assert f"permitted DNS: {domain}\n" in manifest


# ----------------------------------------------------------------------------------------
def test_domains_are_lowercased_and_deduplicated(tmp_out: Path) -> None:
    rc = main(["Example.TEST", "b.test", "example.test", "--out", str(tmp_out)])
    assert rc == 0
    cert = tmp_out / "example.test.crt"
    assert cert_sans(cert) == ["example.test", "*.example.test", "b.test", "*.b.test"]


# ----------------------------------------------------------------------------------------
def _validity(cert: Path) -> tuple[datetime, datetime]:
    """Return the cert's (notBefore, notAfter)."""
    proc = subprocess.run(
        ["openssl", "x509", "-in", str(cert), "-noout", "-startdate", "-enddate"],
        capture_output=True,
        text=True,
        check=True,
    )
    dates = dict(line.split("=", 1) for line in proc.stdout.splitlines())
    fmt = "%b %d %H:%M:%S %Y %Z"
    return (
        datetime.strptime(dates["notBefore"], fmt),
        datetime.strptime(dates["notAfter"], fmt),
    )
