"""Command-line interface for the X5 MITM suite.

Every network-facing command is **dry-run by default**: nothing touches the
network, iptables or the kernel unless the operator explicitly passes
``--apply`` (and, for live actions, runs as root). ``mitm restore`` provides
guaranteed cleanup.

Exit codes:
    0  success (including dry-run previews, clean SIGINT restore)
    1  runtime / configuration error
    2  argparse usage error
    3  live apply requested but not running as root
"""

from __future__ import annotations

import atexit
import signal
import sys
import threading
from typing import Any, Callable, Dict, Optional

from . import __version__
from . import restore as restore_mod
from .config import ConfigError, load_config
from .logsetup import EventWriter, setup_logging

EXIT_OK = 0
EXIT_ERR = 1
EXIT_NOTROOT = 3

PROG = "mitm"
_EPILOG = (
    "LAB RANGE — authorized own-network testing only. Everything is dry-run "
    "unless --apply is given. Run `mitm restore` to guarantee cleanup."
)


def build_parser():
    import argparse

    parser = argparse.ArgumentParser(
        prog=PROG,
        description="X5 — MITM & Spoofing Attack Suite (LAB ONLY)",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("--config", metavar="PATH", help="YAML/JSON config file")
    parser.add_argument("--db", metavar="PATH", help="override SQLite database path")
    parser.add_argument(
        "--log-level",
        choices=("debug", "info", "warning", "error"),
        default="info",
        help="log verbosity (default: info)",
    )

    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    p_arp = sub.add_parser("arp", help="ARP cache spoofing (credential capture assist)")
    p_arp.add_argument("--iface", metavar="IF", help="interface (default: config)")
    p_arp.add_argument("--gateway", metavar="IP", help="gateway to impersonate")
    p_arp.add_argument("--interval", type=float, metavar="SEC", help="reply interval")
    p_arp.add_argument(
        "--count", type=int, metavar="N",
        help="reply pairs to send (0 = endless, default: config)",
    )
    p_arp.add_argument("--apply", action="store_true", help="live (requires root)")
    p_arp.add_argument("--no-pcap", action="store_true", help="disable pcap recording")
    p_arp.add_argument("target", metavar="TARGET", help="victim IP (own lab host)")
    p_arp.set_defaults(handler=cmd_arp)

    p_dns = sub.add_parser("dns", help="DNS spoof via a local fake resolver")
    p_dns.add_argument("--iface", metavar="IF", help="interface (default: config)")
    p_dns.add_argument("--port", type=int, metavar="PORT", help="fake resolver port")
    p_dns.add_argument("--upstream", metavar="IP", help="upstream resolver for other names")
    p_dns.add_argument("--apply", action="store_true", help="live (requires root)")
    p_dns.add_argument("fqdn", metavar="FQDN", help="domain to spoof")
    p_dns.add_argument(
        "redirect_ip", metavar="REDIRECT_IP", help="IP to redirect the FQDN to"
    )
    p_dns.set_defaults(handler=cmd_dns)

    p_http = sub.add_parser(
        "http", help="transparent HTTP credential capture proxy"
    )
    p_http.add_argument("--iface", metavar="IF", help="interface (default: config)")
    p_http.add_argument("--port", type=int, metavar="PORT", help="proxy listen port")
    p_http.add_argument("--duration", type=float, metavar="SEC", help="run for N seconds")
    p_http.add_argument("--apply", action="store_true", help="live (requires root)")
    p_http.add_argument("--no-pcap", action="store_true", help="disable pcap recording")
    p_http.set_defaults(handler=cmd_http, sslstrip=False)

    p_hs = sub.add_parser(
        "https-split",
        help="https-split (sslstrip-lite): HTTP creds + 443 redirect handling",
    )
    p_hs.add_argument("--iface", metavar="IF", help="interface (default: config)")
    p_hs.add_argument("--port", type=int, metavar="PORT", help="proxy listen port")
    p_hs.add_argument("--duration", type=float, metavar="SEC", help="run for N seconds")
    p_hs.add_argument("--apply", action="store_true", help="live (requires root)")
    p_hs.add_argument("--no-pcap", action="store_true", help="disable pcap recording")
    p_hs.set_defaults(handler=cmd_http, sslstrip=True)

    p_mon = sub.add_parser("monitor", help="passive ARP observation (inserts nothing)")
    p_mon.add_argument("--iface", metavar="IF", help="interface (default: config)")
    p_mon.add_argument("--duration", type=float, metavar="SEC", help="run for N seconds")
    p_mon.add_argument("--apply", action="store_true", help="live (requires root)")
    p_mon.add_argument("--no-pcap", action="store_true", help="disable pcap recording")
    p_mon.set_defaults(handler=cmd_monitor)

    p_res = sub.add_parser("restore", help="guaranteed cleanup of all changes")
    p_res.add_argument("--iface", metavar="IF", help="only clear rules for this interface")
    p_res.add_argument("--dry-run", action="store_true", help="preview without changing")
    p_res.set_defaults(handler=cmd_restore)

    p_met = sub.add_parser("metrics", help="capture/restore statistics from SQLite")
    p_met.add_argument("--db", metavar="PATH", dest="metrics_db", help="SQLite database")
    p_met.set_defaults(handler=cmd_metrics)

    p_sel = sub.add_parser("self-test", help="offline self-test (no root, no network)")
    p_sel.set_defaults(handler=cmd_selftest)

    return parser


# --------------------------------------------------------------------------
# live-run helpers
# --------------------------------------------------------------------------

def _arm_sigstop(log) -> threading.Event:
    """Register the SIGINT/SIGTERM handler that stops the live loop cleanly."""
    stop = threading.Event()

    def _handler(signum, _frame):
        log.warning("signal %d received — stopping and restoring", signum)
        stop.set()

    signal.signal(signal.SIGINT, _handler)
    signal.signal(signal.SIGTERM, _handler)
    return stop


def _save_state(cfg: Dict[str, Any], iface: str, command: str, markers, flush_ips) -> None:
    from .netplan import read_ip_forward
    from .statefile import LabState

    if command == "arp":
        prior = read_ip_forward()
        LabState().save(
            iface=iface,
            command=command,
            markers=markers,
            ip_forward_prior=prior,
            extra={"flush_ips": flush_ips},
        )
    else:
        LabState().save(
            iface=iface,
            command=command,
            markers=markers,
            ip_forward_prior=None,
            extra={"flush_ips": flush_ips},
        )


def _finalize(
    cfg: Dict[str, Any], iface: str, store, writer, log, ok: bool
) -> None:
    writer.close()
    store.close()
    if ok:
        log.info("clean exit")


def _run_apply_or_preview(
    cfg: Dict[str, Any],
    iface: str,
    command: str,
    markers,
    flush_ips,
    plan,
    apply: bool,
    log,
):
    """Shared gate: preview plan, or apply + state + cleanup registration."""
    from .netplan import NotRootError, is_root, require_root

    if not apply:
        plan.preview(log)
        print(
            "[dry-run] nothing changed. Re-run with --apply (root) for a live "
            "own-lab run; `mitm restore` cleans up afterwards."
        )
        return EXIT_OK

    try:
        require_root()
    except NotRootError as exc:
        log.error("%s", exc)
        print(f"[error] {exc}")
        return EXIT_NOTROOT

    _save_state(cfg, iface, command, markers, flush_ips)

    def _restore_on_exit() -> None:
        try:
            restore_mod.execute_restore(iface, dry_run=False, log=log)
        except Exception as exc:  # pragma: no cover - cleanup must never raise
            log.error("cleanup failed: %s", exc)

    atexit.register(_restore_on_exit)
    applied = plan.apply(log)
    return applied


# --------------------------------------------------------------------------
# command handlers
# --------------------------------------------------------------------------

def cmd_arp(args: Any, cfg: Dict[str, Any], log) -> int:
    from .arp import execute_arp, plan_arp
    from .pcap import PcapWriter
    from .store import ResultStore

    iface = args.iface or cfg["iface"]
    gateway = args.gateway or cfg["gateway"]
    target = args.target
    if args.count is None:
        count = int(cfg["arp_count"])
    else:
        count = args.count
    interval = args.interval or float(cfg["arp_interval"])

    plan = plan_arp(iface, gateway, target)
    applied = _run_apply_or_preview(
        cfg, iface, "arp", [], [gateway, target], plan, args.apply, log
    )
    if applied == EXIT_OK or applied == EXIT_NOTROOT:
        return applied

    store = ResultStore(cfg["db_path"])
    writer = EventWriter(cfg["events_path"])
    log.info(
        "arp live: target=%s gateway=%s iface=%s interval=%ss count=%s",
        target, gateway, iface, interval, count,
    )
    pcap = None
    if cfg["pcap_enabled"] and not args.no_pcap:
        pcap = PcapWriter(cfg["pcap_path"])
        log.info("pcap recording to %s", cfg["pcap_path"])
    stop = _arm_sigstop(log)
    summary = execute_arp(
        iface, gateway, target, interval, count, store, writer, log, pcap, stop
    )
    if pcap:
        pcap.close()
    if stop.is_set():
        restore_mod.execute_restore(iface, log=log)
    _finalize(cfg, iface, store, writer, log, not stop.is_set())
    print(f"[done] arp spoof: {summary}")
    return EXIT_OK


def cmd_dns(args: Any, cfg: Dict[str, Any], log) -> int:
    import time

    from .dns import FakeDnsServer, plan_dns
    from .store import ResultStore

    iface = args.iface or cfg["iface"]
    port = args.port if args.port is not None else int(cfg["dns_port"])
    upstream = args.upstream or cfg["dns_upstream"]
    plan = plan_dns(iface, args.fqdn, args.redirect_ip, port, upstream)
    applied = _run_apply_or_preview(
        cfg, iface, "dns", [f"x5-mitm-suite:dns"], [], plan, args.apply, log
    )
    if applied == EXIT_OK or applied == EXIT_NOTROOT:
        return applied

    store = ResultStore(cfg["db_path"])
    writer = EventWriter(cfg["events_path"])
    server = FakeDnsServer(port, args.fqdn, args.redirect_ip, upstream, store, writer, log)
    thread = threading.Thread(target=server.serve, daemon=True)
    thread.start()
    stop = _arm_sigstop(log)
    try:
        while not stop.is_set():
            time.sleep(0.5)
    finally:
        server.stop()
        thread.join(timeout=3)
        if stop.is_set():
            restore_mod.execute_restore(iface, log=log)
    summary = server.summary()
    store.record_event("dns", "dns_server_stop", "info", summary)
    writer.emit("dns", "dns_server_stop", "info", summary)
    _finalize(cfg, iface, store, writer, log, not stop.is_set())
    print(f"[done] dns: {summary}")
    return EXIT_OK


def cmd_http(args: Any, cfg: Dict[str, Any], log) -> int:
    import time

    from .http import plan_http, run_proxy, stop_proxy
    from .pcap import PcapWriter
    from .store import ResultStore

    iface = args.iface or cfg["iface"]
    port = args.port if args.port is not None else int(cfg["proxy_port"])
    sslstrip = bool(getattr(args, "sslstrip", False))
    duration = getattr(args, "duration", None)

    plan = plan_http(iface, port, sslstrip)
    op = "https-split" if sslstrip else "http"
    markers = [f"x5-mitm-suite:{op}"]
    if sslstrip:
        markers.append("x5-mitm-suite:http")
    applied = _run_apply_or_preview(cfg, iface, op, markers, [], plan, args.apply, log)
    if applied == EXIT_OK or applied == EXIT_NOTROOT:
        return applied

    store = ResultStore(cfg["db_path"])
    writer = EventWriter(cfg["events_path"])
    pcap = None
    if cfg["pcap_enabled"] and not args.no_pcap:
        pcap = PcapWriter(cfg["pcap_path"])
        log.info("pcap recording to %s", cfg["pcap_path"])
    server = run_proxy(
        cfg["proxy_host"], port, store, writer, log, pcap, sslstrip
    )
    stop = _arm_sigstop(log)

    start = time.time()
    try:
        while not stop.is_set():
            if duration and time.time() - start >= duration:
                break
            time.sleep(0.5)
    finally:
        stop_proxy(server)
        if pcap:
            pcap.close()
        if stop.is_set() or duration:
            restore_mod.execute_restore(iface, log=log)

    summary = {
        "requests": server.requests,
        "captures": server.captures,
        "sslstrip": sslstrip,
        "duration_s": round(time.time() - start, 1),
    }
    store.record_event(op, "http_proxy_stop", "info", summary)
    writer.emit(op, "http_proxy_stop", "info", summary)
    _finalize(cfg, iface, store, writer, log, not stop.is_set())
    print(f"[done] {op}: {summary}")
    return EXIT_OK


def cmd_monitor(args: Any, cfg: Dict[str, Any], log) -> int:
    from .monitor import plan_monitor, run_monitor
    from .pcap import PcapWriter
    from .store import ResultStore

    iface = args.iface or cfg["iface"]
    duration = getattr(args, "duration", None)
    plan = plan_monitor(iface, duration)
    applied = _run_apply_or_preview(
        cfg, iface, "monitor", [], [], plan, args.apply, log
    )
    if applied == EXIT_OK or applied == EXIT_NOTROOT:
        return applied

    store = ResultStore(cfg["db_path"])
    writer = EventWriter(cfg["events_path"])
    pcap = None
    if cfg["pcap_enabled"] and not args.no_pcap:
        pcap = PcapWriter(cfg["pcap_path"])
        log.info("pcap recording to %s", cfg["pcap_path"])
    stop = _arm_sigstop(log)
    summary = run_monitor(iface, duration, store, writer, log, pcap, stop)
    if pcap:
        pcap.close()
    if stop.is_set():
        restore_mod.execute_restore(iface, log=log)
    _finalize(cfg, iface, store, writer, log, not stop.is_set())
    print(f"[done] monitor: {summary}")
    return EXIT_OK


def cmd_restore(args: Any, cfg: Dict[str, Any], log) -> int:
    from .netplan import is_root

    errors = restore_mod.validate_restore_args(args.iface)
    if errors:
        for err in errors:
            log.error("%s", err)
            print(f"[error] {err}")
        return EXIT_ERR

    if args.dry_run:
        restore_mod.preview_restore(args.iface, log)
        return EXIT_OK
    if not is_root():
        print(
            "[error] live restore needs root: `sudo mitm restore`. "
            "Use `mitm restore --dry-run` for a non-privileged preview."
        )
        log.error("restore requires root")
        return EXIT_NOTROOT
    summary = restore_mod.execute_restore(args.iface, dry_run=False, log=log)
    print(f"[restore] complete: {summary}")
    return EXIT_OK


def cmd_metrics(args: Any, cfg: Dict[str, Any], log) -> int:
    from .metrics import compute_metrics, print_metrics
    from .store import ResultStore

    db = args.metrics_db or args.db or cfg["db_path"]
    try:
        with ResultStore(db) as store:
            metrics = compute_metrics(store, int(cfg["metrics_bucket_seconds"]))
    except Exception as exc:
        log.error("metrics failed: %s", exc)
        print(f"[error] metrics: {exc}")
        return EXIT_ERR
    print_metrics(metrics)
    return EXIT_OK


def cmd_selftest(args: Any, cfg: Dict[str, Any], log) -> int:
    from .selftest import run_selftest

    return run_selftest(args.config, log)


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------

def main(argv: Optional[list] = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        cfg = load_config(getattr(args, "config", None))
    except ConfigError as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return EXIT_ERR

    log = setup_logging(cfg["log_path"], args.log_level)
    if args.db:
        cfg = dict(cfg)
        cfg["db_path"] = args.db

    log.info("%s v%s starting (command=%s)", PROG, __version__, args.command)
    try:
        handler: Optional[Callable] = getattr(args, "handler", None)
        if handler is None:
            build_parser().print_help()
            return EXIT_OK
        return handler(args, cfg, log)
    except KeyboardInterrupt:
        log.warning("interrupted")
        print("\n[interrupted] nothing was left applied")
        return EXIT_OK
    except SystemExit as exc:
        raise exc
    except Exception as exc:  # noqa: BLE001 — top-level safety net
        log.exception("command failed")
        print(f"[error] {exc}", file=sys.stderr)
        return EXIT_ERR


if __name__ == "__main__":
    sys.exit(main())