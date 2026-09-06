#!/usr/bin/env python3
"""X5 — MITM & Spoofing Attack Suite (LAB ONLY).

Backward-compatible script entry point for the ``mitm_suite`` package.

New usage (see README):

    python3 firmware/mitm_suite.py self-test          # offline (default with no args)
    python3 firmware/mitm_suite.py arp --iface wlan0 \
        --gateway 192.0.2.1 192.0.2.50                 # dry-run preview
    python3 firmware/mitm_suite.py http --iface wlan0  # dry-run preview
    python3 firmware/mitm_suite.py restore --dry-run   # cleanup preview

Legacy flags are mapped safely: ``--simulate`` runs the offline self-test
and ``--run`` refuses to do anything destructive without a subcommand and
explicit ``--apply``.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))

from mitm_suite import __version__            # noqa: E402  (package preferred over this shim)
from mitm_suite.cli import main               # noqa: E402

LAB_BANNER = """
============================================================
  [LAB RANGE]  AUTHORIZED TESTING ONLY
  [LAB RANGE]  Do NOT run on production networks
  [LAB RANGE]  Dry-run by default; live requires --apply
============================================================
"""


def _legacy_argv(argv):
    args = list(argv)
    if not args or "--simulate" in args:
        print(LAB_BANNER)
        print(f"mitm_suite v{__version__} — offline simulation/self-test\n")
        return ["self-test"]
    if "--run" in args:
        print(LAB_BANNER)
        print(
            "[!] Legacy --run is not supported. Live operations now require a "
            "subcommand AND explicit --apply:"
        )
        print(
            "    python3 firmware/mitm_suite.py arp --iface wlan0 "
            "--gateway 192.0.2.1 --apply 192.0.2.50"
        )
        print("    python3 firmware/mitm_suite.py restore   # guaranteed cleanup")
        return None
    return args


def main_legacy():
    argv = _legacy_argv(sys.argv[1:])
    if argv is None:
        return 1
    return main(argv)


if __name__ == "__main__":
    sys.exit(main_legacy())