# X5 — MITM and Spoofing Attack Suite

Lab-only, own-network MITM toolkit implementing ARP spoof, DNS spoof, HTTP credential capture, and https-split (sslstrip-lite), with structured logging, a SQLite result store, a self-test that needs neither root nor a network, and a guaranteed-restore command.

## Overview

This project demonstrates classic man-in-the-middle and spoofing attacks in a controlled lab environment **against the network you own**:

- **ARP Spoof + Credential Capture**: Poison the ARP cache between your own gateway and your own victim host
- **DNS Spoof**: Redirect a chosen FQDN to a local fake resolver via iptables REDIRECT
- **HTTP Credential Capture**: Transparent proxy that harvests form POSTs and Basic-auth credentials
- **https-split**: sslstrip-lite mode (https→http redirect rewrite) + TLS-session detection
- **Passive Monitor**: Observe ARP pairs / gratuitous announcements without inserting anything
- **Guaranteed Restore**: `mitm restore` removes exactly the rules the suite added
- **Offline Self-Test**: `mitm self-test` validates config, CLI, events, and the SQLite store — no root, no network, < 15s

Everything is **dry-run by default**. Live operations require an explicit `--apply` flag and root, and are intended exclusively for networks you own.

## Features

- **`mitm arp`** — GRATUITOUS ARP reply injection (endless until SIGINT, or `--count N`)
- **`mitm dns`** — local fake resolver answers `FQDN -> REDIRECT_IP`, forwarding all other queries to your lab upstream
- **`mitm http`** — transparent HTTP credential-capture proxy (POST forms + Basic auth) fed by iptables REDIRECT
- **`mitm https-split`** — 443 also redirected; TLS sessions logged as `tls_blocked`; plaintext 3xx `Location:` http-rewrite
- **`mitm monitor`** — passive ARP observation (no insertion)
- **`mitm restore`** — guaranteed cleanup of suite-added iptables rules + ip_forward restore
- **`mitm metrics`** — captures/min and restore-reliability reporting from the SQLite store
- **`mitm self-test`** — offline, rootless, networkless verification; exit code 0
- **Consent Banner**: loud "LAB RANGE" banner; every live action requires the explicit `--apply` flag

## Installation

```bash
# Core is Python stdlib only (Linux). Optionally:
pip install PyYAML   # full YAML config (built-in subset parser otherwise)
# pip install scapy  # optional packet tooling (raw AF_PACKET is the default)

# Install as a package (console script `mitm`):
pip install .
# or run without installing:
python3 firmware/mitm_suite.py           # legacy entry (no args = self-test)
PYTHONPATH=firmware python3 -m mitm_suite.cli ...
```

## Usage

All commands are **dry-run by default** — they print the exact iptables/kernel

operations they would perform and change nothing. Re-run with `--apply`

(as root) only on your own lab AP + your own victim machine.

```bash
# Offline self-test (no root, no network):
mitm self-test

# ARP spoof preview (192.0.2.x = RFC 5737 documentation-lab placeholders):
mitm arp --iface wlan0 --gateway 192.0.2.1 192.0.2.50

# DNS spoof preview:
mitm dns --iface wlan0 bank.lab 192.0.2.53

# HTTP credential-capture proxy preview:
mitm http --iface wlan0

# https-split (also redirects 443) preview:
mitm https-split --iface wlan0

# Passive monitor preview:
mitm monitor --iface wlan0 --duration 60

# Restore preview, then the real guaranteed cleanup:
mitm restore --dry-run
sudo mitm restore

# Metrics from the SQLite store:
mitm metrics
```

### Live lab run (own AP + own victim only)

```bash
# 1. ARP spoof (ten reply-pair rounds, then stop):
sudo mitm arp --iface wlan0 --gateway <lab-gw> --count 10 --apply <victim-ip>

# 2. DNS spoof (endless until Ctrl+C, then auto-restore):
sudo mitm dns --iface wlan0 --apply bank.lab <lab-landing-page-ip>

# 3. HTTP credential capture (endless; Ctrl+C restores):
sudo mitm http --iface wlan0 --apply

# 4. Verify capture + restore state:
mitm metrics
sudo mitm restore --dry-run   # must show zero x5-mitm-suite rules
```

Configuration lives in `config/mitm.yaml` (defaults are documentation-lab
placeholders only — replace them with your own lab values; never commit real
IPs/MACs/SSIDs). Override with `--config`, or `MITM_CONFIG`. Logs go to
`logs/mitm.log`, events as JSONL to `logs/mitm-events.jsonl`, captures to
`logs/mitm.db`, and traffic to `captures/*.pcap` — all gitignored.

## Metrics

The flagship video metric proves a live lab session out of artifacts:

| Metric | Definition | Gate |
|--------|-----------|------|
| **captures/min** | credential-capture events logged per minute during an `http` run (`mitm metrics` reports it) | `>= 1` credential shown mid-run |
| **restore reliability (20 restarts)** | run `arp`/`http`/`dns --apply`, SIGINT 20×; after each, `mitm restore --dry-run` reports **zero** `x5-mitm-suite` rules and `net.ipv4.ip_forward` returns to its prior value | 20/20 clean restores |

Record the metric on-screen (terminal showing `mitm metrics` + `mitm restore
--dry-run` after each restart) and archive the video under `videos/`. Numbers
land in `METRICS.md`.

## Live Lab Test Plan

Prerequisites: your own AP (`lab-ap`), your own victim laptop, attacker host on
the same lab network, root on the attacker.

1. Baseline — note `net.ipv4.ip_forward` and `iptables -t nat -S PREROUTING | grep x5-mitm-suite` (must be empty).
2. `mitm self-test` → exit 0 (offline gate).
3. ARP: `arp --apply` toward the lab gateway + victim; from the victim verify its ARP table shows the attacker MAC for the gateway.
4. DNS: `dns --apply bank.lab <landing>`; on the victim resolve `bank.lab` → landing IP; other names still resolve via the lab upstream.
5. HTTP: `http --apply`; open our lab login page on the victim, submit; verify `credential_capture` in `logs/mitm-events.jsonl`, `mitm.db`, and the terminal.
6. https-split: repeat with `https-split --apply`; verify 302 `Location:` is rewritten to http for plaintext flows and TLS sessions are logged `tls_blocked` (full decryption needs a MITM CA on the victim — out of scope).
7. Restore: SIGINT the active session (or `sudo mitm restore`); verify step-1 baseline is unchanged.
8. Metric run: capture/min over the session + **20 SIGINT restarts** with zero residual rules each (record to `METRICS.md`, video under `videos/`).

## Safety / Restore Guarantee

- **Dry-run by default.** Not one iptables rule is inserted, no ip_forward change, no packet is sent, unless `--apply` is given.
- **Root required for live.** `--apply` without root aborts (exit 3).
- **Marker-tagged rules only.** Every rule inserted carries the comment `x5-mitm-suite:<op>`. `mitm restore` deletes exactly those rules — never your own.
- **State file.** On apply, the suite records the prior `net.ipv4.ip_forward` value and applied markers in `logs/.mitm-state.json` (gitignored); restore reads it and undoes precisely those changes, then clears it.
- **SIGINT/SIGTERM restore-on-exit.** Any live session stops on Ctrl+C, runs restore, and exits cleanly. `atexit` runs the same cleanup as a safety net.
- **Idempotent.** Restore is safe to run repeatedly and with nothing to undo.
- **Endless modes** (`arp_count: 0`, `http`, `dns`, `monitor`) run until SIGINT, then restore — this is what the 20-restart metric exercises.
- **iptables side effects** are limited to the `nat` table's `PREROUTING` chain on the chosen interface, plus a `net.ipv4.ip_forward` toggle only when the ARP mode needs relaying. Everything else is untouched.

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