"""DNS spoofing module: a local fake resolver fed by iptables REDIRECT.

Under ``--apply`` the suite redirects UDP/53 on the interface to a local
fake resolver; the configured FQDN resolves to the redirect IP, everything
else is forwarded to the lab upstream resolver (``dns_upstream``).
"""

from __future__ import annotations

import ipaddress
import select
import socket
import struct
import threading
from typing import Dict, List, Optional, Tuple

from .netplan import OpPlan, iptables_redirect_argv

DNS_PORT = 53


def parse_dns_query(data: bytes) -> Optional[Tuple[int, str, int, int]]:
    """Return ``(txid, qname, qtype, qclass)`` for a single-question query."""
    if len(data) < 12:
        return None
    txid, flags, qdcount = struct.unpack("!HHH", data[:6])
    if qdcount != 1:
        return None
    offset = 12
    labels: List[bytes] = []
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:  # compression pointer not expected in query
            offset += 2
            break
        offset += 1
        labels.append(data[offset : offset + length])
        offset += length
    else:
        return None
    if len(data) < offset + 4:
        return None
    qname = ".".join(l.decode("ascii", "replace") for l in labels)
    qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])
    return (txid, qname, qtype, qclass)


def build_a_response(query: Tuple[int, str, int, int], rdata_ip: str, ttl: int = 60) -> bytes:
    txid, qname, qtype, qclass = query
    question = encode_qname(qname) + struct.pack("!HH", qtype, qclass)
    answer = (
        b"\xc0\x0c"                            # pointer to qname
        + struct.pack("!HHIH", 1, 1, ttl, 4)   # A, IN, ttl, rdlength=4
        + socket.inet_aton(rdata_ip)
    )
    header = struct.pack(
        "!HHHHHH",
        txid,
        0x8180,  # response, recursion desired+available, no error
        1,       # qdcount
        1,       # ancount
        0,
        0,
    )
    return header + question + answer


def encode_qname(qname: str) -> bytes:
    out = bytearray()
    for label in qname.rstrip(".").split("."):
        enc = label.encode("ascii", "replace")
        out.append(len(enc))
        out.extend(enc)
    out.append(0)
    return bytes(out)


class FakeDnsServer:
    """UDP responder answering the spoofed FQDN, forwarding the rest."""

    def __init__(
        self,
        port: int,
        fqdn: str,
        redirect_ip: str,
        upstream: str,
        store,
        writer,
        log,
    ) -> None:
        self.fqdn = fqdn.lower().rstrip(".")
        self.redirect_ip = str(ipaddress.ip_address(redirect_ip))
        self.upstream = upstream
        self.port = port
        self.store = store
        self.writer = writer
        self.log = log
        self._stop = threading.Event()
        self._sock: Optional[socket.socket] = None
        self.answered = 0
        self.forwarded = 0
        self.queries = 0

    def serve(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", self.port))
        sock.settimeout(0.5)
        self._sock = sock
        self.log.info("fake DNS server listening on 0.0.0.0:%d", self.port)
        while not self._stop.is_set():
            try:
                ready, _, _ = select.select([sock], [], [], 0.5)
            except OSError:
                break
            if not ready:
                continue
            try:
                data, addr = sock.recvfrom(4096)
            except OSError:
                break
            threading.Thread(
                target=self._handle, args=(data, addr), daemon=True
            ).start()
        try:
            sock.close()
        except OSError:
            pass

    def _handle(self, data: bytes, addr: Tuple[str, int]) -> None:
        self.queries += 1
        parsed = parse_dns_query(data)
        if parsed is None:
            return
        txid, qname, qtype, _qclass = parsed
        payload = {"client": addr[0], "qname": qname, "qtype": qtype}
        self.store.record_event("dns", "dns_query", "info", payload)
        self.writer.emit("dns", "dns_query", "info", payload)
        if qname.lower() == self.fqdn:
            self.answered += 1
            resp = build_a_response(parsed, self.redirect_ip)
            payload = {"client": addr[0], "qname": qname, "redirect": self.redirect_ip}
            self.store.record_event("dns", "dns_spoof", "info", payload)
            self.writer.emit("dns", "dns_spoof", "info", payload)
            self.log.info("spoofed %s -> %s for %s", qname, self.redirect_ip, addr[0])
        else:
            self.forwarded += 1
            resp = self._forward(data)

        if resp and self._sock:
            try:
                self._sock.sendto(resp, addr)
            except OSError:
                pass

    def _forward(self, data: bytes) -> Optional[bytes]:
        try:
            up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            up.settimeout(3.0)
            up.sendto(data, (self.upstream, DNS_PORT))
            resp, _ = up.recvfrom(4096)
            up.close()
            return resp
        except OSError:
            return None

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass

    def summary(self) -> Dict[str, int]:
        return {
            "queries": self.queries,
            "answered_spoofed": self.answered,
            "forwarded": self.forwarded,
        }


def plan_dns(
    iface: str, fqdn: str, redirect_ip: str, port: int, upstream: str
) -> OpPlan:
    plan = OpPlan(f"DNS spoof: {fqdn} -> {redirect_ip} on {iface}")
    plan.add_message(f"fake resolver answers {fqdn} -> {redirect_ip} on UDP/{port}")
    plan.add_message(f"all other queries forwarded to upstream {upstream}")
    plan.add_iptables(
        f"redirect UDP/53 on {iface} to local fake resolver UDP/{port}",
        iptables_redirect_argv(iface, "udp", 53, port, "dns"),
        rollback=None,
    )
    return plan