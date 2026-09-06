"""Offline self-test. No root required, no network touched, < 15 seconds.

Validates: config parsing & default placeholders, CLI argument handling,
JSONL event formatting, SQLite store round-trip.
"""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import config as config_mod
from .logsetup import EventWriter
from .store import ResultStore


class SelfTestError(Exception):
    pass


def _check(name: str, ok: bool, detail: str = "") -> List[str]:
    status = "PASS" if ok else "FAIL"
    print(f"[selftest] {status}: {name}" + (f" — {detail}" if detail else ""))
    return [] if ok else [name]


def test_config_parse(argv_config: Optional[str]) -> List[str]:
    failures: List[str] = []
    default_ok = True
    for key, expected_type in (
        ("gateway", str),
        ("target", str),
        ("iface", str),
        ("ssid", str),
        ("dns_port", int),
        ("proxy_port", int),
        ("arp_interval", (int, float)),
        ("db_path", str),
    ):
        value = config_mod.DEFAULT_CONFIG.get(key)
        if value is None or not isinstance(value, expected_type):
            default_ok = False
            failures += _check(f"default config key '{key}' typed", False, repr(value))
    ok, errors, _warnings = config_mod.validate_config(dict(config_mod.DEFAULT_CONFIG))
    if not default_ok or not ok:
        failures += _check(
            "default config valid (documentation-lab placeholders)", False,
            "; ".join(errors),
        )
    else:
        failures += _check("default config valid (documentation-lab placeholders)", True)

    # Placeholder policy: no real-world addresses/SSIDs in shipped defaults.
    for key in ("gateway", "target", "dns_upstream"):
        if config_mod.DEFAULT_CONFIG[key] not in (
            "192.0.2.1", "192.0.2.50", "192.0.2.53", "198.51.100.1",
            "203.0.113.1",
        ):
            failures += _check(
                f"default '{key}' is a documentation-lab placeholder", False
            )
    if config_mod.DEFAULT_CONFIG["iface"] != "wlan0":
        failures += _check("default iface is 'wlan0' placeholder", False)
    if config_mod.DEFAULT_CONFIG["ssid"] != "lab-ap":
        failures += _check("default ssid is 'lab-ap' placeholder", False)

    # Config file parse (shipped YAML subset or JSON).
    probe = argv_config or config_mod.resolve_config_path()
    if probe and Path(probe).is_file():
        try:
            cfg = config_mod.load_config(probe)
            for key in ("gateway", "target", "iface", "ssid"):
                if key not in cfg:
                    failures += _check(f"config file contains '{key}'", False)
            failures += _check("config file parsed + validated", True, str(probe))
        except Exception as exc:
            failures += _check("config file parsed + validated", False, str(exc))
    else:
        try:
            config_mod.load_config(argv_config)
            failures += _check("config parse (defaults fallback)", True, "config not found; default validated")
        except Exception as exc:
            failures += _check("config parse (defaults fallback)", False, str(exc))
    return failures


def test_cli_parser() -> List[str]:
    from .cli import build_parser  # deferred to avoid import cycle

    failures: List[str] = []

    def expect_ok(name: str, argv: List[str]) -> Dict[str, Any]:
        try:
            ns = build_parser().parse_args(argv)
            return ns
        except SystemExit as exc:
            failures += _check(name, False, f"parser exited {exc.code}")
            return {}

    arp = expect_ok(
        "arp subcommand parses",
        ["arp", "--iface", "wlan0", "--gateway", "192.0.2.1", "192.0.2.50"],
    )
    if arp:
        failures += _check(
            "arp apply defaults to False (dry-run safe)",
            arp.apply is False and arp.target == "192.0.2.50" and arp.gateway == "192.0.2.1",
        )
    dns = expect_ok(
        "dns subcommand parses",
        ["dns", "--iface", "wlan0", "bank.lab", "192.0.2.53"],
    )
    if dns:
        failures += _check(
            "dns fqdn/redirect parsed",
            dns.fqdn == "bank.lab" and getattr(dns, "redirect_ip", None) == "192.0.2.53",
        )
    http = expect_ok("http subcommand parses", ["http", "--iface", "wlan0"])
    if http:
        failures += _check("http apply defaults to False", http.apply is False)
    monitor = expect_ok("monitor subcommand parses", ["monitor"])
    restore = expect_ok(
        "restore subcommand parses",
        ["restore", "--iface", "wlan0"],
    )
    if restore:
        failures += _check("restore parses --iface", restore.iface == "wlan0")

    with contextlib.redirect_stderr(io.StringIO()):
        try:
            build_parser().parse_args(["restore", "--bogus"])
            failures += _check("unknown restore flag rejected", False)
        except SystemExit:
            failures += _check("unknown restore flag rejected", True)
    return failures


def test_event_format() -> List[str]:
    failures: List[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        events_path = str(Path(tmp) / "events.jsonl")
        with EventWriter(events_path) as writer:
            record = writer.emit(
                "http", "credential_capture", "warn",
                {"kind": "form_post", "username": "lab", "url": "http://bank.lab/login"},
            )
        for key in ("ts", "module", "event", "level", "payload"):
            if key not in record:
                failures += _check(f"event record has '{key}'", False)
        line = Path(events_path).read_text().strip()
        try:
            parsed = json.loads(line)
            if (
                parsed.get("module") == "http"
                and parsed.get("event") == "credential_capture"
                and isinstance(parsed.get("payload"), dict)
            ):
                failures += _check("event emits parseable JSONL", True)
            else:
                failures += _check("event emits parseable JSONL", False, line)
        except Exception as exc:
            failures += _check("event emits parseable JSONL", False, str(exc))
    return failures


def test_store_roundtrip() -> List[str]:
    failures: List[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        db = str(Path(tmp) / "mitm.db")
        with ResultStore(db) as store:
            event_id = store.record_event(
                "selftest", "ping", "info", {"n": 1}
            )
            cap_id = store.record_capture(
                kind="form_post",
                username="admin",
                password="labpass",
                url="http://192.0.2.50/login",
                remote="192.0.2.60",
            )
            events = store.query_events("selftest")
            caps = store.query_captures()
        ok = (
            event_id >= 1
            and cap_id >= 1
            and len(events) == 1
            and events[0]["payload"].get("n") == 1
            and len(caps) == 1
            and caps[0]["username"] == "admin"
            and caps[0]["password"] == "labpass"
        )
        failures += _check("SQLite store round-trip", ok)
    return failures


def run_selftest(config_path: Optional[str] = None, log=None) -> int:
    print("== X5 MITM suite — offline self-test ==")
    print("(no root required, no network touched)")
    failures: List[str] = []
    failures += test_config_parse(config_path)
    failures += test_cli_parser()
    failures += test_event_format()
    failures += test_store_roundtrip()
    if failures:
        print(f"[selftest] FAILED: {len(failures)} check(s)")
        return 1
    print("[selftest] ALL CHECKS PASSED — exit 0")
    return 0