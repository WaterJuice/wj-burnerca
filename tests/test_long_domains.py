# ----------------------------------------------------------------------------------------
#   test_long_domains.py
#   --------------------
#
#   Before 1.1.0, any domain over 51 characters failed: the CA's name
#   (`wj-burnerca: <domain>`) went over X.509's 64-character limit and openssl
#   refused it. Names are now shortened in the subjects only, while the SANs and
#   name constraints keep the full domain. Also covers the length limits that remain.
#
#   (c) 2026 WaterJuice — Unlicense.
# ----------------------------------------------------------------------------------------

from __future__ import annotations
from pathlib import Path
import pytest
from wj_burnerca.cli import EXIT_OK
from wj_burnerca.cli import EXIT_USAGE
from wj_burnerca.cli import MAX_DOMAIN_LEN
from wj_burnerca.cli import MAX_FIRST_DOMAIN_LEN
from wj_burnerca.cli import main
from .conftest import cert_sans
from .conftest import domain_of_length
from .conftest import permitted_names
from .conftest import subject_cn


# ----------------------------------------------------------------------------------------
@pytest.mark.parametrize("length", [52, 100])
def test_long_domain_is_issued(tmp_out: Path, length: int) -> None:
    """52 is the shortest length 1.0 failed on; 100 also pushes the cert's CN over 64."""
    domain = domain_of_length(length)
    rc = main([domain, "--out", str(tmp_out)])
    assert rc == EXIT_OK

    root = tmp_out / f"rootCA-{domain}.crt"
    cert = tmp_out / f"{domain}.crt"

    # The SANs and the name constraint carry the full domain...
    assert cert_sans(cert) == [domain, f"*.{domain}"]
    assert permitted_names(root) == [domain]

    # ...while the subjects are shortened from the left to fit 64 characters.
    assert subject_cn(root) == "wj-burnerca: ..." + domain[-48:]
    assert subject_cn(cert) == (domain if length <= 64 else "..." + domain[-61:])


# ----------------------------------------------------------------------------------------
def test_longest_allowed_domains_are_issued(tmp_out: Path) -> None:
    first = domain_of_length(MAX_FIRST_DOMAIN_LEN)
    other = domain_of_length(MAX_DOMAIN_LEN)
    rc = main([first, other, "--out", str(tmp_out)])
    assert rc == EXIT_OK

    assert permitted_names(tmp_out / f"rootCA-{first}.crt") == [first, other]
    assert cert_sans(tmp_out / f"{first}.crt") == [
        first,
        f"*.{first}",
        other,
        f"*.{other}",
    ]


# ----------------------------------------------------------------------------------------
def test_domain_over_length_limit_rejected(tmp_out: Path) -> None:
    rc = main(["a.test", domain_of_length(MAX_DOMAIN_LEN + 1), "--out", str(tmp_out)])
    assert rc == EXIT_USAGE
    assert not tmp_out.exists()


# ----------------------------------------------------------------------------------------
def test_first_domain_too_long_for_filenames_rejected(tmp_out: Path) -> None:
    """Too long to name the output files, but fine anywhere after the first domain."""
    long = domain_of_length(MAX_FIRST_DOMAIN_LEN + 1)
    assert main([long, "--out", str(tmp_out)]) == EXIT_USAGE
    assert not tmp_out.exists()
    assert main(["a.test", long, "--out", str(tmp_out)]) == EXIT_OK
