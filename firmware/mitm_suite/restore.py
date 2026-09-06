"""Guaranteed cleanup: ``mitm restore``.

Removes exactly the iptables rules tagged with the ``x5-mitm-suite`` marker
comment, restores ``ip_forward`` to the value recorded at apply-time, clears
the persistent state file and best-effort flushes ARP/neighbour entries for
the affected IPs. Idempotent and safe to run repeatedly.
"""

from __future__ import annotations

import os
import subprocess
from typing import Any, Dict, List, Optional

from .netplan import MARKER, NotRootError, is_root, run
from .statefile import DEFAULT_STATE_FILE, LabState


def validate_restore_args(iface: Optional[str]) -> List[str]:
    """Return a list of argument-validation errors (empty == ok)."""
    errors: List[str] = []
    if iface:
        from .netplan import iface_exists

        if not iface_exists(iface):
            errors.append(f"interface '{iface}' not present on this host")
    return errors


def scan_marker_rules() -> List[str]:
    """Return the raw ``-A`` rule lines present that carry the marker."""
    try:
        proc = subprocess.run(
            ["iptables", "-t", "nat", "-S", "PREROUTING"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError:
        return []
    if proc.returncode != 0:
        return []
    return [
        line.strip()
        for line in proc.stdout.decode("utf-8", "replace").splitlines()
        if MARKER in line
    ]


def delete_rule_for(line: str) -> Optional[List[str]]:
    """Convert ``-A CHAIN rest...`` into an ``iptables -t nat -D CHAIN rest...`` argv."""
    stripped = line.strip()
    if not stripped.startswith("-A "):
        return None
    rest = stripped[3:].strip()
    return ["iptables", "-t", "nat", "-D", *rest.split()]


def restore_iptables(iface: Optional[str] = None) -> int:
    """Delete all marker-tagged nat rules. Returns number deleted."""
    rules = scan_marker_rules()
    if iface:
        rules = [r for r in rules if f"-i {iface}" in r]
    deleted = 0
    for rule in rules:
        argv = delete_rule_for(rule)
        if argv:
            rc = run(argv)
            if rc == 0:
                deleted += 1
    return deleted


def restore_ip_forward(prior: Optional[str]) -> None:
    if prior is not None and prior in ("0", "1"):
        run(["sysctl", "-w", f"net.ipv4.ip_forward={prior}"])


def flush_neigh(ip: Optional[str]) -> None:
    if not ip:
        return
    for argv in (
        ["ip", "neigh", "del", ip],
        ["arp", "-d", ip],
    ):
        run(argv)


def build_restore_plan(iface: Optional[str]) -> Dict[str, Any]:
    """Non-committing inspection used by preview/--dry-run."""
    pending = scan_marker_rules()
    if iface:
        pending = [r for r in pending if f"-i {iface}" in r]
    state = LabState().load()
    return {
        "marker_rules_pending": pending,
        "ip_forward_prior": (state or {}).get("ip_forward_prior"),
        "state_file": DEFAULT_STATE_FILE if os.path.exists(DEFAULT_STATE_FILE) else None,
        "iface": iface,
    }


def preview_restore(iface: Optional[str], log=None) -> None:
    plan = build_restore_plan(iface)
    print("[preview] restore plan")
    if plan["marker_rules_pending"]:
        for rule in plan["marker_rules_pending"]:
            print(f"[preview]   delete nat rule: {rule}")
    else:
        print("[preview]   no x5-mitm-suite marked rules found (nothing to delete)")
    if plan["ip_forward_prior"] is not None:
        print(f"[preview]   restore net.ipv4.ip_forward={plan['ip_forward_prior']}")
    if not is_root():
        print("[preview]   NOTE: running restore that touches iptables requires root")

    if log:
        log.info("restore preview: %s", plan)


def execute_restore(
    iface: Optional[str] = None,
    dry_run: bool = False,
    log=None,
) -> Dict[str, Any]:
    """Execute guaranteed cleanup. Returns a summary dict."""
    if dry_run:
        preview_restore(iface, log)
        return {"deleted": 0, "dry_run": True}

    if not is_root():
        raise NotRootError(
            "live restore needs root (sudo mitm restore). Use --dry-run for a "
            "non-privileged preview."
        )

    state = LabState().load()
    deleted = restore_iptables(iface)
    prior = (state or {}).get("ip_forward_prior")
    restore_ip_forward(prior)

    if state:
        extras = (state or {}).get("extra") or {}
        for ip in extras.get("flush_ips", []):
            flush_neigh(str(ip))

    LabState().clear()

    summary = {
        "deleted_rules": deleted,
        "ip_forward_restored": prior if prior is not None else False,
        "state_cleared": state is not None,
    }
    if log:
        log.info("restore complete: %s", summary)
    return summary