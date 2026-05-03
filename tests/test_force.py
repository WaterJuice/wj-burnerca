# ----------------------------------------------------------------------------------------
#   test_force.py
#   -------------
#
#   Output-directory handling: refuses non-empty --out without --force; accepts
#   it with --force; accepts a missing --out; accepts an empty --out.
#
#   (c) 2026 WaterJuice — Unlicense.
# ----------------------------------------------------------------------------------------

from __future__ import annotations
from pathlib import Path
from wj_burnerca.cli import EXIT_OK
from wj_burnerca.cli import EXIT_OUT_BLOCKED
from wj_burnerca.cli import main


# ----------------------------------------------------------------------------------------
def test_refuses_non_empty_out_without_force(tmp_out: Path) -> None:
    tmp_out.mkdir()
    (tmp_out / "stale.txt").write_text("hi")

    rc = main(["example.test", "--out", str(tmp_out)])
    assert rc == EXIT_OUT_BLOCKED
    # The stale file must be untouched.
    assert (tmp_out / "stale.txt").exists()


# ----------------------------------------------------------------------------------------
def test_force_overwrites_existing(tmp_out: Path) -> None:
    tmp_out.mkdir()
    (tmp_out / "stale.txt").write_text("hi")

    rc = main(["example.test", "--out", str(tmp_out), "--force"])
    assert rc == EXIT_OK
    assert not (tmp_out / "stale.txt").exists()
    assert (tmp_out / "rootCA-example.test.crt").is_file()


# ----------------------------------------------------------------------------------------
def test_empty_out_dir_is_fine(tmp_out: Path) -> None:
    tmp_out.mkdir()
    rc = main(["example.test", "--out", str(tmp_out)])
    assert rc == EXIT_OK


# ----------------------------------------------------------------------------------------
def test_out_parent_does_not_exist_is_created(tmp_path: Path) -> None:
    """`--out` is created with `parents=True` if its parent doesn't exist."""
    nested = tmp_path / "does" / "not" / "exist" / "burner-out"
    rc = main(["example.test", "--out", str(nested)])
    assert rc == EXIT_OK
    assert (nested / "rootCA-example.test.crt").is_file()
