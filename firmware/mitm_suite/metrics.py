"""Metrics reporting from the SQLite store (video metric support).

Measured flagships metrics:
* captures/min   — credential captures logged per minute over a session
* restore reliability — no residual rules after N SIGINT restarts
"""
from __future__ import annotations

import datetime
from typing import Any, Dict

from .store import ResultStore


def _parse_ts(ts: str) -> float:
    try:
        return datetime.datetime.fromisoformat(ts).timestamp()
    except (ValueError, TypeError):
        return 0.0


def compute_metrics(store: ResultStore, bucket_seconds: int = 60) -> Dict[str, Any]:
    captures = store.query_captures(limit=100000)
    span = store.first_last_capture_ts()
    captures_per_min = 0.0
    if span and captures:
        first = _parse_ts(span["first"])
        last = _parse_ts(span["last"])
        minutes = max((last - first) / 60.0, 1.0 / 60.0)
        captures_per_min = len(captures) / minutes

    by_kind: Dict[str, int] = {}
    for cap in captures:
        by_kind[cap["kind"]] = by_kind.get(cap["kind"], 0) + 1

    return {
        "total_captures": len(captures),
        "captures_per_min": round(captures_per_min, 2),
        "captures_by_kind": by_kind,
        "events": {
            "total": store.count_events(),
            "http": store.count_events("http"),
            "dns": store.count_events("dns"),
            "arp": store.count_events("arp"),
            "monitor": store.count_events("monitor"),
        },
        "bucket_seconds": bucket_seconds,
    }


def print_metrics(metrics: Dict[str, Any]) -> None:
    print("== X5 MITM suite — metrics ==")
    print(f"total captures           : {metrics['total_captures']}")
    print(f"captures / min (session) : {metrics['captures_per_min']}")
    print(f"captures by kind         : {metrics['captures_by_kind'] or '{}'}")
    for module, count in metrics["events"].items():
        print(f"events [{module:7s}]      : {count}")
    print("== restore reliability ==")
    print("measure: run `mitm restore --dry-run` after each of 20 SIGINT runs;")
    print("zero 'x5-mitm-suite' rules must remain and ip_forward must be restored.")