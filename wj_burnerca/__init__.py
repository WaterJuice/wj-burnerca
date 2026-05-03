# ----------------------------------------------------------------------------------------
#   __init__.py
#   -----------
#
#   wj-burnerca package initialisation.
#
#   (c) 2026 WaterJuice — Unlicense; see LICENSE in the project root.
#
#   Version History
#   ---------------
#   May 2026 - Created
# ----------------------------------------------------------------------------------------

"""wj-burnerca: single-shot, name-constrained, self-destroying CA for local dev TLS.

Generates a name-constrained root Certificate Authority, issues one or more leaf
certificates, verifies the chain, and then destroys the CA private key. Designed for
developer laptops where you need real TLS but want a strictly bounded blast radius.
"""

from wj_burnerca.version import VERSION_STR

__all__ = ["__version__"]

__version__ = VERSION_STR
