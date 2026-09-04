# X5 — MITM and Spoofing Attack Suite

Lab-only scripted local-network MITM attack toolkit implementing ARP spoof, DHCP starvation, DNS spoof, and SSL-strip with scapy-based offline simulation mode.

## Overview

This project demonstrates classic man-in-the-middle and spoofing attacks in a controlled lab environment:
- **ARP Spoof + Credential Capture**: Poison ARP cache and sniff credentials from HTTP traffic
- **DHCP Starvation**: Exhaust DHCP pool by flooding DISCOVER requests with random MACs
- **DNS Spoof**: Redirect DNS resolution by spoofing responses for a target domain
- **SSL-Strip Setup**: Downgrade HTTPS to HTTP by intercepting TLS handshakes
- **Offline Simulation**: Replays sample frames as raw bytes to demonstrate detection logic without live traffic

## Features

- **ARP Spoof Attack**: Gratuitous ARP reply injection to redirect traffic via attacker
- **DHCP Starvation**: MAC-rotation starvation attack against local DHCP servers
- **DNS Spoof**: Fake DNS A-record responses for arbitrary domains
- **SSL-Strip**: HTTPS downgrade interception demonstration
- **Simulation Mode**: Offline PCAP-equivalent frame replay for detection logic testing
- **Consent Banner**: Loud "LAB RANGE" banner on every attack module requiring explicit arming

## Installation

```bash
# Scapy is optional — simulation mode works without it
pip install scapy 2>/dev/null || true
```

## Usage

```bash
# Dry-run simulation (default, no live traffic)
python3 mitm_suite.py

# Full simulation self-test (offline frames)
python3 mitm_suite.py --simulate

# Live attack (requires --run flag AND lab network)
python3 mitm_suite.py --run --target 192.168.1.0/24 --gateway 192.168.1.1
```

## Example Output

```
============================================================
  X5 — MITM & Spoofing Attack Suite (LAB ONLY)
============================================================

[!] LAB RANGE — Authorized testing only
[!] Scapy available: True

--- ARP Spoof Simulation ---
  [LAB] Constructing gratuitous ARP reply for 192.168.1.100
  [LAB] Simulated 5 ARP frames sent, 12 HTTP packets sniffed
  [LAB] Extracted credential: admin / s3cretP@ss

--- DHCP Starvation Simulation ---
  [LAB] Generated 256 DISCOVER frames with random MACs
  [LAB] Simulated DHCP OFFER count dropped to 0
  [LAB] Pool exhaustion achieved after 256 requests

--- DNS Spoof Simulation ---
  [LAB] Intercepted DNS query for example.com
  [LAB] Injected spoofed A-record: 10.0.0.99
  [LAB] Simulated 8 queries redirected to attacker

--- SSL Strip Simulation ---
  [LAB] Intercepted HTTPS redirect for secure.example.com
  [LAB] Stripped 302 redirect, downgraded to HTTP
  [LAB] Simulated 4 page loads intercepted in plain text

All simulations complete. No live traffic was generated.
```

## IMPORTANT: Read before use.

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized man-in-the-middle attacks violate federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test
- All attacks must be performed within a physically isolated lab range

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized interception of network traffic is a federal crime
- **Wiretap Act (18 USC 2511)**: Intercepting electronic communications is illegal without authorization
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Capturing credentials may expose personal data subject to privacy regulations

### Acceptable Use
- Testing network security on your own lab infrastructure
- Authorized penetration testing with written scope and rules of engagement
- Academic research in controlled isolated environments
- Security education and training demonstrations

### Prohibited Use
- Performing MITM attacks on any network without explicit authorization
- Capturing credentials from systems you do not own
- Using this tool for any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the network owner/ administrator privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept
4. Never exfiltrate real credential data during testing

## License

MIT
