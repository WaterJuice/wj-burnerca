# ----------------------------------------------------------------------------------------
#   test_constraints.py
#   -------------------
#
#   Asserts the X509v3 Name Constraints extension is present on the root, marked
#   critical, and scoped to the user's domain. Load-bearing security property.
#
#   (c) 2026 WaterJuice — Unlicense.
# ----------------------------------------------------------------------------------------

from __future__ import annotations
from pathlib import Path
from wj_burnerca.cli import main
from .conftest import openssl_text


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
