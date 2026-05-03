# ----------------------------------------------------------------------------------------
#   __main__.py
#   -----------
#
#   Entry point for `python -m wj_burnerca`.
#
#   (c) 2026 WaterJuice — Unlicense; see LICENSE in the project root.
#
#   Version History
#   ---------------
#   May 2026 - Created
# ----------------------------------------------------------------------------------------

import sys

MIN_PYTHON = (3, 14)
if sys.version_info < MIN_PYTHON:
    print(f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ is required.", file=sys.stderr)
    sys.exit(1)

from wj_burnerca.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
