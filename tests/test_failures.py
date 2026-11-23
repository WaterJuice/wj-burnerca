# ----------------------------------------------------------------------------------------
#   test_failures.py
#   ----------------
#
#   Validation-layer failures: missing or malformed args, bad domains, out-of-range
#   --days. All of them must exit with EXIT_USAGE and write nothing.
#
#   (c) 2026 WaterJuice — Unlicense.
# ----------------------------------------------------------------------------------------

from __future__ import annotations
from pathlib import Path
from wj_burnerca.cli import EXIT_OK
from wj_burnerca.cli import EXIT_USAGE
from wj_burnerca.cli import main


# ----------------------------------------------------------------------------------------
def test_missing_domain_is_usage_error() -> None:
    # argparse itself exits 2 here, which must not leak out as EXIT_OPENSSL.
    rc = main([])
    assert rc == EXIT_USAGE


# ----------------------------------------------------------------------------------------
def test_non_numeric_days_is_usage_error(tmp_out: Path) -> None:
    rc = main(["example.test", "--out", str(tmp_out), "--days", "abc"])
    assert rc == EXIT_USAGE
    assert not tmp_out.exists()


# ----------------------------------------------------------------------------------------
def test_help_exits_ok() -> None:
    assert main(["--help"]) == EXIT_OK


# ----------------------------------------------------------------------------------------
def test_one_bad_domain_rejects_the_run(tmp_out: Path) -> None:
    rc = main(["a.test", "not a domain!", "--out", str(tmp_out)])
    assert rc == EXIT_USAGE
    assert not tmp_out.exists()


# ----------------------------------------------------------------------------------------
def test_days_too_high(tmp_out: Path) -> None:
    rc = main(["example.test", "--out", str(tmp_out), "--days", "9999"])
    assert rc == EXIT_USAGE
    assert not tmp_out.exists()


# ----------------------------------------------------------------------------------------
def test_days_zero(tmp_out: Path) -> None:
    rc = main(["example.test", "--out", str(tmp_out), "--days", "0"])
    assert rc == EXIT_USAGE


# ----------------------------------------------------------------------------------------
def test_wildcard_domain_rejected(tmp_out: Path) -> None:
    """Don't pass a wildcard — the wildcard SAN is added automatically."""
    rc = main(["*.example.test", "--out", str(tmp_out)])
    assert rc == EXIT_USAGE


# ----------------------------------------------------------------------------------------
def test_garbage_domain_rejected(tmp_out: Path) -> None:
    rc = main(["not a domain!", "--out", str(tmp_out)])
    assert rc == EXIT_USAGE


# ----------------------------------------------------------------------------------------
def test_empty_label_rejected(tmp_out: Path) -> None:
    rc = main(["foo..bar", "--out", str(tmp_out)])
    assert rc == EXIT_USAGE


# ----------------------------------------------------------------------------------------
def test_label_too_long_rejected(tmp_out: Path) -> None:
    long_label = "a" * 64
    rc = main([f"{long_label}.example.test", "--out", str(tmp_out)])
    assert rc == EXIT_USAGE


# ----------------------------------------------------------------------------------------
def test_label_with_leading_hyphen_rejected(tmp_out: Path) -> None:
    # The hyphen has to be on a non-first label or argparse will try to parse it as a flag.
    rc = main(["foo.-bar.example.test", "--out", str(tmp_out)])
    assert rc == EXIT_USAGE


# ----------------------------------------------------------------------------------------
def test_label_with_trailing_hyphen_rejected(tmp_out: Path) -> None:
    rc = main(["foo-.example.test", "--out", str(tmp_out)])
    assert rc == EXIT_USAGE


# ----------------------------------------------------------------------------------------
def test_non_ascii_domain_rejected(tmp_out: Path) -> None:
    """A raw `ä` would land in a DNS SAN and fail verification; punycode works."""
    rc = main(["exämple.test", "--out", str(tmp_out)])
    assert rc == EXIT_USAGE
    assert not tmp_out.exists()

    punycode = "exämple.test".encode("idna").decode()  # xn--exmple-cua.test
    assert main([punycode, "--out", str(tmp_out)]) == EXIT_OK


# ----------------------------------------------------------------------------------------
def test_ipv4_address_rejected(tmp_out: Path) -> None:
    """IPs need an `IP:` SAN type, not `DNS:` — refuse rather than mis-issue."""
    rc = main(["192.168.1.1", "--out", str(tmp_out)])
    assert rc == EXIT_USAGE


# ----------------------------------------------------------------------------------------
def test_max_days_accepted(tmp_out: Path) -> None:
    """`--days 365` is the documented maximum and must be accepted."""
    rc = main(["example.test", "--out", str(tmp_out), "--days", "365"])
    assert rc == EXIT_OK
