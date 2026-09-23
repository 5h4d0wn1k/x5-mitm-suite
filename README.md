> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# X5 — MITM and Spoofing Suite

![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![GitHub Stars](https://img.shields.io/github/stars/5h4d0wn1k/x5-mitm-suite)
![Last Commit](https://img.shields.io/github/last-commit/5h4d0wn1k/x5-mitm-suite)
![GitHub Issues](https://img.shields.io/github/issues/5h4d0wn1k/x5-mitm-suite)

> **Lab-only MITM & spoofing suite** — ARP spoof, DNS spoof, HTTP credential
> capture, https-split (sslstrip-lite), passive monitoring, and a guaranteed
> restore command, with structured logging and a SQLite event store for network
> security training on networks you own.

## Why

Man-in-the-middle attacks are the textbook way credentials and traffic get
intercepted, and every blue team needs to recognize — and safely rehearse —
those techniques. X5 packages the classic set (ARP cache poisoning, DNS
redirect, transparent HTTP credential capture, and an https-split 3xx-rewrite
mode) behind one CLI that is **dry-run by default**: without `--apply --root`
nothing is inserted or sent. A guaranteed `restore` removes exactly the
suite-tagged iptables rules, and an offline `self-test` validates config, CLI,
events, and the SQLite store with no root and no network. Everything is scoped
to the documentation range `192.0.2.0/24` and your own lab AP + victim machine.

## Features

- **`mitm arp`** — gratuitous ARP reply injection (`--count N` or endless).
- **`mitm dns`** — local fake resolver answering `FQDN -> REDIRECT_IP` via
  iptables REDIRECT.
- **`mitm http`** — transparent credential-capture proxy (POST forms + Basic).
- **`mitm https-split`** — 443 redirect + plaintext `Location:` http-rewrite,
  TLS sessions logged as `tls_blocked`.
- **`mitm monitor`** — passive ARP observation, no insertion.
- **`mitm restore`** — guaranteed cleanup of suite-added rules + `ip_forward`.
- **`mitm metrics`** — captures/min and restore reliability from the SQLite DB.
- **`mitm self-test`** — offline, rootless, networkless gate (exit 0).
- **Safety rails** — dry-run by default, `--apply` requires root, marker-tagged
  rules only, SIGINT auto-restore.

## Quickstart

```bash
pip install .                          # provides the `mitm` console script
# or run without installing: PYTHONPATH=firmware python3 -m mitm_suite.cli ...

mitm self-test                         # offline, no root/network

# Preview-only (changes nothing):
mitm arp --iface wlan0 --gateway 192.0.2.1 192.0.2.50
mitm dns --iface wlan0 bank.lab 192.0.2.53
mitm http --iface wlan0
mitm https-split --iface wlan0
mitm monitor --iface wlan0 --duration 60
mitm restore --dry-run

# Live lab run (your own AP + victim only):
sudo mitm arp --iface wlan0 --gateway 192.0.2.1 --count 10 --apply 192.0.2.50
sudo mitm dns --iface wlan0 --apply bank.lab 192.0.2.53
sudo mitm http --iface wlan0 --apply
mitm metrics
sudo mitm restore
```

Configuration: `config/mitm.yaml` (documentation placeholders only — replace
with your own lab values). Logs: `logs/mitm.log`, events `logs/mitm-events.jsonl`,
DB `logs/mitm.db`, captures `captures/*.pcap` — all gitignored. Live runs
require the config default IPs replaced with your own lab addresses.

## Tests

```bash
python3 -m unittest discover -s tests
```

## Project structure

```
firmware/mitm_suite.cli/   # subcommand modules (arp/dns/http/monitor/restore)
firmware/mitm_suite.py     # legacy entry + offline self-test
config/mitm.yaml           # config (lab placeholders)
tests/                     # offline unit tests
```

## Documentation

- [ETHICS.md](ETHICS.md) — ethical-use policy, read first
- [SCOPE.md](SCOPE.md) — authorized-scope definition
- [LEGAL.md](LEGAL.md) — legal framework
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to contribute
- [SECURITY.md](SECURITY.md) — vulnerability reporting

## Contributing

New capture plugins, restore guarantees, and self-test coverage are welcome.
See [CONTRIBUTING.md](CONTRIBUTING.md); live features must stay dry-run by
default and restore-tagged.

## License

MIT — see [LICENSE](LICENSE).