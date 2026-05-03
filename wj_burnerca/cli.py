# ----------------------------------------------------------------------------------------
#   cli.py
#   ------
#
#   Command-line interface and orchestration for wj-burnerca.
#
#   Surface area is intentionally tiny: one positional `domain`, one optional
#   `--days`, plus `--out` and `--force`. The CA's name and constraint are derived
#   from the domain; the cert covers `domain` and `*.domain` automatically; both the
#   CA and the cert get the same validity period (so the burner CA expires when its
#   only cert does); the CA private key is always destroyed before exit.
#
#   Responsibilities:
#   - Parse and validate args.
#   - Drive the burner pipeline: tempdir → root CA → cert → verify → manifest →
#     atomic move into --out → destroy CA key.
#   - Map exceptions to the spec's exit codes (0..5).
#   - Guarantee that nothing is written to --out unless verification succeeded, and
#     that the CA key is never copied out of the tempdir.
#
#   (c) 2026 WaterJuice — Unlicense; see LICENSE in the project root.
#
#   Version History
#   ---------------
#   May 2026 - Created
# ----------------------------------------------------------------------------------------

# ----------------------------------------------------------------------------------------
#   Imports
# ----------------------------------------------------------------------------------------

import sys
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import cast
from wj_burnerca import ca
from wj_burnerca import destroy
from wj_burnerca import leaf
from wj_burnerca import manifest
from wj_burnerca import openssl
from wj_burnerca import paths
from wj_burnerca import verify
from wj_burnerca.version import VERSION_STR
from .argbuilder import ArgsParser
from .argbuilder import Namespace

# ----------------------------------------------------------------------------------------
#   Constants
# ----------------------------------------------------------------------------------------

DEFAULT_DAYS = 365
MAX_DAYS = 365

# Exit codes (per spec section 5).
EXIT_OK = 0
EXIT_USAGE = 1
EXIT_OPENSSL = 2
EXIT_VERIFY = 3
EXIT_OUT_BLOCKED = 4
EXIT_DESTROY = 5

LICENSE_TEXT = """\
This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <https://unlicense.org>"""

# ----------------------------------------------------------------------------------------
#   Resolved options
# ----------------------------------------------------------------------------------------


@dataclass
class Options:
    """Validated options derived from argv."""

    domain: str
    days: int
    out: Path
    force: bool


# ----------------------------------------------------------------------------------------
#   Argparse
# ----------------------------------------------------------------------------------------


# ----------------------------------------------------------------------------------------
def parse_args(argv: list[str]) -> Namespace:
    """Parse command-line arguments using the WaterJuice argbuilder helper."""
    p = ArgsParser(
        prog="wj-burnerca",
        description=(
            f"wj-burnerca: {VERSION_STR}\n"
            "(c) 2026 WaterJuice. Unlicense.\n\n"
            "Generate a name-constrained, self-destroying CA for one domain. "
            "Issues a single cert covering both `<domain>` and `*.<domain>`, "
            "verifies the chain, then destroys the CA key."
        ),
        version=f"wj-burnerca: {VERSION_STR}\npython: {sys.version.split()[0]}",
    )
    p.add_argument(
        "domain",
        help=(
            "The domain this burner CA exists to serve (e.g. 'example.test'). "
            "The CA is name-constrained to this domain and the issued cert covers "
            "both the bare name and its wildcard."
        ),
    )
    p.add_argument(
        "--days",
        type=int,
        default=DEFAULT_DAYS,
        metavar="N",
        help=f"Validity in days, 1..{MAX_DAYS} (default: {DEFAULT_DAYS}).",
    )
    p.add_argument(
        "--out",
        default=None,
        metavar="DIR",
        help="Output directory (default: ./<domain>/).",
    )
    p.add_argument(
        "--force",
        action="store_true",
        help="Overwrite an existing non-empty --out directory.",
    )
    p.add_argument(
        "--license",
        action="version",
        version=LICENSE_TEXT,
        help="Show licence and exit.",
    )
    return p.parse(argv)


# ----------------------------------------------------------------------------------------
def resolve_options(ns: Namespace) -> Options:
    """Validate parsed args and produce the typed Options the rest of the tool uses."""
    domain = cast("str", ns.domain).strip()
    _validate_domain(domain)

    days = cast("int", ns.days)
    if days < 1 or days > MAX_DAYS:
        raise SystemExit(f"--days must be between 1 and {MAX_DAYS}, got {days}")

    out_raw = cast("str | None", ns.out)
    out = Path(out_raw if out_raw is not None else f"./{domain}").resolve()

    return Options(
        domain=domain,
        days=days,
        out=out,
        force=bool(ns.force),
    )


# ----------------------------------------------------------------------------------------
def _validate_domain(name: str) -> None:
    """Reject anything that isn't a syntactically reasonable bare DNS name.

    No leading wildcard is allowed: the CLI takes a single bare domain and
    automatically issues for both `<domain>` and `*.<domain>`. An IP address
    is also rejected — it would need a `subjectAltName=IP:` SAN, not `DNS:`.
    """
    if not name:
        raise SystemExit("domain is empty")
    if name.startswith("*."):
        raise SystemExit(
            "pass a bare domain (e.g. 'example.test'); the wildcard SAN is added automatically"
        )
    if "/" in name or " " in name:
        raise SystemExit(f"domain looks invalid: {name!r}")
    labels = name.split(".")
    for label in labels:
        if not label:
            raise SystemExit(f"domain {name!r} has an empty label")
        if len(label) > 63:
            raise SystemExit(f"domain {name!r} has a label longer than 63 chars")
        if label.startswith("-") or label.endswith("-"):
            raise SystemExit(f"domain {name!r} has a label starting or ending with '-'")
        for ch in label:
            if not (ch.isalnum() or ch == "-"):
                raise SystemExit(f"domain {name!r} contains invalid character {ch!r}")
    # Reject IPv4 dotted-quad shape: an all-numeric, four-label name would otherwise
    # land in a `subjectAltName=DNS:` SAN, which is the wrong SAN type for an IP.
    if all(label.isdigit() for label in labels):
        raise SystemExit(
            f"{name!r} looks like an IP address; wj-burnerca only issues for DNS names"
        )


# ----------------------------------------------------------------------------------------
#   Entry points
# ----------------------------------------------------------------------------------------


# ----------------------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    """Main entry point for the wj-burnerca CLI."""
    if argv is None:
        argv = sys.argv[1:]
    try:
        ns = parse_args(argv)
        opts = resolve_options(ns)
        return _run(opts)
    except KeyboardInterrupt:
        print("\n---- Manually Terminated ----\n", file=sys.stderr)
        return EXIT_USAGE
    except SystemExit as e:
        # argbuilder/argparse and resolve_options raise SystemExit with usage messages.
        if isinstance(e.code, int):
            return e.code
        if e.code:
            print(f"Error: {e.code}", file=sys.stderr)
        return EXIT_USAGE
    except openssl.OpenSSLNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return EXIT_USAGE
    except BaseException as e:
        msg = (
            "-----------------------------------------------------------------------------\n"
            "UNHANDLED EXCEPTION OCCURRED!!\n"
            "\n"
            f"{traceback.format_exc()}\n"
            f"EXCEPTION: {type(e)} {e}\n"
            "-----------------------------------------------------------------------------\n"
        )
        print(msg, file=sys.stderr)
        return EXIT_USAGE


# ----------------------------------------------------------------------------------------
def _run(opts: Options) -> int:
    """Run the burner pipeline. Returns the spec's exit code."""
    # Pre-flight: openssl present? Reject early so the user never sees a half-cleanup.
    openssl.find_openssl()

    # Pre-flight: --out usable?
    if paths.output_dir_is_blocked(opts.out, force=opts.force):
        print(
            f"Error: --out directory exists and is non-empty: {opts.out}\n"
            "Pass --force to overwrite, or pick a different --out.",
            file=sys.stderr,
        )
        return EXIT_OUT_BLOCKED

    workdir = paths.make_workdir()
    try:
        return _run_in_workdir(opts, workdir)
    finally:
        paths.shred_workdir(workdir)


# ----------------------------------------------------------------------------------------
def _run_in_workdir(opts: Options, workdir: Path) -> int:
    """The body of `_run`, separated so the workdir cleanup can be in `finally`."""
    print(f"wj-burnerca: {opts.domain}")
    print(f"  Validity: {opts.days} days   (CA and cert both expire together)")

    # Step 1: root CA.
    try:
        root = ca.generate_root_ca(workdir, domain=opts.domain, days=opts.days)
    except openssl.OpenSSLError as e:
        print(f"Error: openssl failed during root CA generation:\n{e}", file=sys.stderr)
        return EXIT_OPENSSL
    print("✓ Root CA generated (constrained to this domain)")

    # Step 2: leaf cert.
    try:
        cert = leaf.issue_cert(workdir, root, domain=opts.domain, days=opts.days)
    except openssl.OpenSSLError as e:
        print(f"Error: openssl failed during cert issuance:\n{e}", file=sys.stderr)
        return EXIT_OPENSSL
    print(f"✓ Cert issued for {opts.domain} and *.{opts.domain}")

    # Step 3: verify.
    try:
        verify.verify_chain(root.cert_path, cert.cert_path)
    except (verify.VerificationError, openssl.OpenSSLError) as e:
        print(f"Error: chain verification failed:\n{e}", file=sys.stderr)
        return EXIT_VERIFY
    print("✓ Chain verified")

    # Step 4: manifest + trust instructions.
    manifest.write_manifest(workdir, root, cert)
    manifest.write_trust_instructions(workdir, root)

    # Step 5: destroy the CA key. Always — there is no escape hatch.
    try:
        destroy.shred_file(root.key_path)
    except (FileNotFoundError, RuntimeError) as e:
        print(
            "Error: could not destroy the CA private key.\n"
            f"  Path: {root.key_path}\n"
            f"  Detail: {e}\n"
            "Delete it manually before doing anything else.",
            file=sys.stderr,
        )
        return EXIT_DESTROY
    print("✓ CA private key destroyed")
    caveat = destroy.secure_deletion_caveat()
    if caveat:
        print(f"  {caveat}")

    # Step 6: drop openssl scratch files, then stage outputs into --out. Atomic-ish:
    # --out is empty (or wiped via --force) before any files land in it.
    paths.clean_intermediates(workdir)
    paths.stage_outputs(workdir, opts.out, force=opts.force)

    # Step 7: summary.
    print(f"✓ Outputs written to {opts.out}/")
    print()
    print(f"  rootCA: {opts.out}/{root.cert_path.name}")
    print(f"  cert:   {opts.out}/{cert.cert_path.name}")
    print(f"  key:    {opts.out}/{cert.key_path.name}")
    print()
    print(f"Trust instructions: {opts.out}/trust-instructions.md")
    return EXIT_OK
