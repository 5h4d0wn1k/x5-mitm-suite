"""Operational planning: iptables, sysctl, root checks, OpPlan.

Every rule that the suite inserts carries the marker comment
``x5-mitm-suite:<op>`` so ``mitm restore`` can identify and remove exactly
the rules we added — never the operator's own rules.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

MARKER = "x5-mitm-suite"
IP_FORWARD_PROC = Path("/proc/sys/net/ipv4/ip_forward")


class NotRootError(Exception):
    """Raised when an apply-step needs root but we are not running as root."""


def is_root() -> bool:
    try:
        return __import__("os").geteuid() == 0
    except AttributeError:  # pragma: no cover - non-POSIX
        return False


def require_root() -> None:
    if not is_root():
        raise NotRootError(
            "live apply requires root (sudo). Preview/dry-run does not."
        )


def iface_exists(iface: str) -> bool:
    return Path("/sys/class/net", iface).exists()


def iface_mac(iface: str) -> Optional[str]:
    """Return the interface MAC as ``aa:bb:cc:dd:ee:ff`` or None."""
    path = Path("/sys/class/net", iface, "address")
    try:
        txt = path.read_text().strip().lower()
    except OSError:
        return None
    return txt if txt and txt != "00:00:00:00:00:00" else None


def read_ip_forward() -> Optional[str]:
    try:
        return IP_FORWARD_PROC.read_text().strip()
    except OSError:
        return None


def set_ip_forward(value: str) -> None:
    require_root()
    IP_FORWARD_PROC.write_text(value + "\n")


def run(argv: List[str]) -> int:
    """Run a privileged helper, returning its returncode."""
    try:
        proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except FileNotFoundError:
        return 127
    return proc.returncode


def iptables_redirect_argv(
    iface: str,
    proto: str,
    dport: int,
    to_port: int,
    op: str,
    table: str = "nat",
) -> List[str]:
    return [
        "iptables",
        "-t", table,
        "-I", "PREROUTING",
        "-i", iface,
        "-m", "comment", "--comment", f"{MARKER}:{op}",
        "-p", proto,
        "--dport", str(dport),
        "-j", "REDIRECT",
        "--to-ports", str(to_port),
    ]


class OpPlan:
    """A preview-able, apply-able sequence of privileged steps.

    * ``preview()``  prints every step without executing anything.
    * ``apply()``    requires root, executes non-message steps in order and
                      returns the list of executed steps for rollback.
    * ``rollback()`` executes the stored `rollback` lists in reverse order.
    """

    def __init__(self, description: str) -> None:
        self.description = description
        self.steps: List[Dict[str, Any]] = []

    def add_step(
        self,
        kind: str,
        desc: str,
        argv: Optional[List[str]] = None,
        rollback: Optional[List[str]] = None,
    ) -> None:
        self.steps.append(
            {"kind": kind, "desc": desc, "argv": argv, "rollback": rollback}
        )

    def add_iptables(self, desc: str, argv: List[str], rollback: Optional[List[str]] = None) -> None:
        self.add_step("iptables", desc, argv or None, rollback)

    def add_sysctl(self, desc: str, argv: List[str], rollback: Optional[List[str]] = None) -> None:
        self.add_step("sysctl", desc, argv or None, rollback)

    def add_message(self, desc: str) -> None:
        self.add_step("message", desc, None, None)

    def preview(self, log=None) -> None:
        print(f"[preview] plan: {self.description}")
        for step in self.steps:
            line = f"[preview]   - {step['desc']}"
            if step["argv"]:
                line += f"\n            $ {' '.join(step['argv'])}"
            if step["rollback"]:
                line += (
                    "\n            (undo: " 
                    + "; ".join(" ".join(r) for r in step["rollback"])
                    + ")"
                )
            print(line)
            if log:
                log.info("preview: %s", step["desc"])

    def apply(self, log=None) -> List[Dict[str, Any]]:
        require_root()
        applied: List[Dict[str, Any]] = []
        for step in self.steps:
            if step["kind"] == "message":
                continue
            argv = step["argv"]
            if not argv:
                continue
            if log:
                log.info("apply: %s", step["desc"])
            rc = run(argv)
            if rc != 0:
                raise RuntimeError(f"step failed ({rc}): {' '.join(argv)}")
            applied.append(step)
        return applied

    def rollback(self, applied: List[Dict[str, Any]], log=None) -> None:
        for step in reversed(applied):
            rb = step.get("rollback")
            if not rb:
                continue
            for argv in reversed(rb):
                if log:
                    log.info("rollback: %s", step["desc"])
                run(argv)