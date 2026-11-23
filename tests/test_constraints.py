# ----------------------------------------------------------------------------------------
#   test_constraints.py
#   -------------------
#
#   Asserts the X509v3 Name Constraints extension is present on the root, marked
#   critical, and scoped to the user's domains. Load-bearing security property.
#
#   (c) 2026 WaterJuice — Unlicense.
# ----------------------------------------------------------------------------------------

from __future__ import annotations
from pathlib import Path
import pytest
from wj_burnerca import ca
from wj_burnerca import leaf
from wj_burnerca import openssl
from wj_burnerca import verify
from wj_burnerca.cli import main
from .conftest import openssl_text
from .conftest import permitted_names
from .conftest import subject_cn


# ----------------------------------------------------------------------------------------
def test_name_constraints_present_critical_and_scoped_to_domain(tmp_out: Path) -> None:
    rc = main(["example.test", "--out", str(tmp_out)])
    assert rc == 0

    text = openssl_text(tmp_out / "rootCA-example.test.crt")

    assert "X509v3 Name Constraints" in text, text
    constraints_idx = text.index("X509v3 Name Constraints")
    nearby = text[constraints_idx : constraints_idx + 200]
    assert "critical" in nearby, nearby
    assert "DNS:example.test" in nearby, nearby


# ----------------------------------------------------------------------------------------
def test_ca_subject_is_wj_burnerca_colon_domain(tmp_out: Path) -> None:
    rc = main(["example.test", "--out", str(tmp_out)])
    assert rc == 0
    text = openssl_text(tmp_out / "rootCA-example.test.crt")
    # CN should be "wj-burnerca: example.test".
    assert "CN = wj-burnerca: example.test" in text or (
        "CN=wj-burnerca: example.test" in text
    ), text


# ----------------------------------------------------------------------------------------
def test_name_constraints_list_every_domain(tmp_out: Path) -> None:
    rc = main(["a.test", "b.test", "--out", str(tmp_out)])
    assert rc == 0

    root = tmp_out / "rootCA-a.test.crt"
    assert permitted_names(root) == ["a.test", "b.test"]

    text = openssl_text(root)
    constraints_idx = text.index("X509v3 Name Constraints")
    assert "critical" in text[constraints_idx : constraints_idx + 200]


# ----------------------------------------------------------------------------------------
def test_ca_subject_counts_extra_domains(tmp_out: Path) -> None:
    rc = main(["a.test", "b.test", "c.test", "--out", str(tmp_out)])
    assert rc == 0
    assert subject_cn(tmp_out / "rootCA-a.test.crt") == "wj-burnerca: a.test (+2 more)"


# ----------------------------------------------------------------------------------------
def test_ca_refuses_names_outside_its_domains(tmp_path: Path) -> None:
    """A CA constrained to several domains must still reject any other domain.

    The CLI destroys the CA key, so this drives ca/leaf/verify directly to sign more
    than one cert with the same CA.
    """
    root = ca.generate_root_ca(tmp_path, domains=["a.test", "b.test"], days=1)

    inside = leaf.issue_cert(tmp_path, root, domains=["b.test"], days=1)
    verify.verify_chain(root.cert_path, inside.cert_path)

    # One name outside the constraints is enough to fail the whole cert.
    for domains in (["c.test"], ["a.test", "c.test"]):
        outside = leaf.issue_cert(tmp_path, root, domains=domains, days=1)
        with pytest.raises((openssl.OpenSSLError, verify.VerificationError)):
            verify.verify_chain(root.cert_path, outside.cert_path)
