"""TLS/SSL helpers for the https-split (sslstrip-lite) mode."""

from __future__ import annotations

from typing import Optional


def is_tls_client_hello(data: bytes) -> bool:
    """Heuristic TLS ClientHello detection on first bytes.

    A TLS record starts with content type 0x16 (handshake), followed by the
    record version (0x03 xx). Used to detect that https-split cannot decrypt a
    session without an installed MITM CA certificate on the lab victim.
    """
    if len(data) < 3:
        return False
    return data[0] == 0x16 and data[1:2] == b"\x03"


def rewrite_https_location(data: bytes) -> bytes:
    """Rewrite ``Location: https://`` to ``Location: http://`` (sslstrip-lite).

    Operates case-insensitively on header lines of an HTTP response body.
    """
    return _rewrite_header(data, b"Location", b"https://", b"http://")


def rewrite_refresh_url(data: bytes, host: Optional[str] = None) -> bytes:
    out = data.replace(b"https://", b"http://")
    if host:
        out = out.replace(("https://" + host).encode(), ("http://" + host).encode())
    return out


def _rewrite_header(data: bytes, name: bytes, old: bytes, new: bytes) -> bytes:
    lines = data.split(b"\r\n")
    rebuilt: list = []
    for line in lines:
        lower = line.lower()
        if lower.startswith(name.lower() + b":"):
            line = line.replace(old, new)
        rebuilt.append(line)
    return b"\r\n".join(rebuilt)