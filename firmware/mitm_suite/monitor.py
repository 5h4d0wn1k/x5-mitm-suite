"""Passive monitor: observes ARP/DNS traffic on an interface.

Fully passive — inserts nothing. ``--apply`` only starts the sniffing socket
(which still needs root); preview without ``--apply`` prints what a live
session would observe.
"""

from __future__ import annotations

import socket
import struct
import threading
import time
from typing import Dict, Optional

from .arp import ETH_P_ALL, ARP_TYPE, mac_to_str
from .netplan import OpPlan, iface_exists


def parse_arp_packet(data: bytes) -> Optional[Dict[str, object]]:
    if len(data) < 28:
        return None
    htype, ptype, hlen, plen, opcode = struct.unpack("!HHBBH", data[:8])
    sender_mac = mac_to_str(data[8:14])
    sender_ip = ".".join(str(b) for b in data[14:18])
    target_mac = mac_to_str(data[18:24])
    target_ip = ".".join(str(b) for b in data[24:28])
    return {
        "htype": htype,
        "opcode": opcode,
        "sender_mac": sender_mac,
        "sender_ip": sender_ip,
        "target_mac": target_mac,
        "target_ip": target_ip,
    }


def plan_monitor(iface: str, duration: Optional[float]) -> OpPlan:
    plan = OpPlan(f"passive monitor on {iface}")
    if not iface_exists(iface):
        plan.add_message(f"WARNING: interface '{iface}' not present on this host")
    plan.add_message(
        "listen for ARP packets on the interface; log new IP<->MAC pairs, "
        "gratuitous announcements and repeated reply floods (no insertion)"
    )
    plan.add_message(
        "duration: " + (f"{duration}s" if duration else "endless until SIGINT")
    )
    return plan


def run_monitor(
    iface: str,
    duration: Optional[float],
    store,
    writer,
    log,
    pcap=None,
    stop: Optional[threading.Event] = None,
) -> Dict[str, object]:
    stop = stop or threading.Event()
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    sock.bind((iface, 0))
    sock.settimeout(0.5)

    seen_pairs: set = set()
    reply_counts: Dict[str, int] = {}
    frames = 0
    grat = 0
    start = time.time()

    writer.emit("monitor", "monitor_start", "info", {"iface": iface})
    store.record_event("monitor", "monitor_start", "info", {"iface": iface})
    log.info("monitor started on %s", iface)

    try:
        while not stop.is_set():
            if duration and time.time() - start >= duration:
                break
            try:
                data = sock.recv(65535)
            except socket.timeout:
                continue
            if len(data) < 14:
                continue
            ether_type = struct.unpack("!H", data[12:14])[0]
            if ether_type != ARP_TYPE:
                continue
            arp = parse_arp_packet(data[14:])
            if not arp:
                continue
            frames += 1
            if pcap:
                pcap.write(data)
            key = (arp["sender_ip"], arp["sender_mac"])
            payload = dict(arp)
            if arp["sender_ip"] == "0.0.0.0":
                grat += 1
                event = "gratuitous_arp"
            elif key not in seen_pairs:
                seen_pairs.add(key)
                event = "arp_pair_seen"
            else:
                reply_counts[key] = reply_counts.get(key, 0) + 1
                event = "arp_reply"
            store.record_event("monitor", event, "info", payload)
            writer.emit("monitor", event, "info", payload)
            log.info("monitor: %s %s is-at %s", event, arp["sender_ip"], arp["sender_mac"])
    finally:
        sock.close()

    summary = {
        "iface": iface,
        "frames": frames,
        "gratuitous": grat,
        "distinct_pairs": len(seen_pairs),
        "duration_s": round(time.time() - start, 1),
    }
    store.record_event("monitor", "monitor_stop", "info", summary)
    writer.emit("monitor", "monitor_stop", "info", summary)
    log.info("monitor stopped: %s", summary)
    return summary