# ----------------------------------------------------------------------------------------
#   test_destroy.py
#   ---------------
#
#   The CA private key is always destroyed before exit. There is no escape hatch.
#
#   (c) 2026 WaterJuice — Unlicense.
# ----------------------------------------------------------------------------------------

from __future__ import annotations
from pathlib import Path
from wj_burnerca.cli import main


# ----------------------------------------------------------------------------------------
def test_ca_key_destroyed(tmp_out: Path) -> None:
    rc = main(["example.test", "--out", str(tmp_out)])
    assert rc == 0
    assert not (tmp_out / "rootCA-example.test.key").exists(), (
        "rootCA-example.test.key must not exist after a normal run"
    )


# ----------------------------------------------------------------------------------------
def test_manifest_records_destruction(tmp_out: Path) -> None:
    rc = main(["example.test", "--out", str(tmp_out)])
    assert rc == 0
    manifest = (tmp_out / "MANIFEST.txt").read_text()
    assert "DESTROYED" in manifest
