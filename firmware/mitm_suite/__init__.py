"""X5 — MITM & Spoofing Attack Suite (LAB ONLY).

Production-grade network MITM toolkit for authorized own-lab testing:

* ``mitm arp``        — ARP cache spoofing (credential capture assist)
* ``mitm dns``        — DNS spoofing via a local fake resolver
* ``mitm http``       — transparent HTTP credential capture proxy
* ``mitm https-split``— HTTP-redirect sslstrip-lite mode
* ``mitm monitor``    — passive ARP/DNS observation
* ``mitm restore``    — guaranteed cleanup of all applied changes
* ``mitm metrics``    — capture/restore statistics from the SQLite store
* ``mitm self-test``  — offline self-test (no root, no network)

Everything is dry-run by default; live operations require the explicit
``--apply`` flag and are intended exclusively for a network you own.
"""

__version__ = "2.0.0"
__all__ = [
    "__version__",
    "config",
    "store",
    "cli",
]