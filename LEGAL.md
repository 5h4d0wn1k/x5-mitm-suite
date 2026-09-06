# LEGAL

This project (x5-mitm-suite) is a **red-team / offensive security tool** and is
provided strictly for **educational and authorized security testing** in a
self-owned, physically isolated lab environment.

## Obligations for anyone using this software

1. **Authorization required.** Only run against networks/systems you own or
   hold written authorization to test. Unauthorized interception or spoofing
   violates the CFAA, the Wiretap Act (18 USC 2511), state computer-crime
   statutes, and privacy regulations (e.g., GDPR/CCPA).
2. **Own-lab only.** Live testing is limited to your own AP (`lab-ap`), your
   own victim hardware, and documentation-lab address ranges
   (`192.0.2.0/24` RFC 5737) unless replaced with your own private lab values.
3. **No credential exfiltration.** Captured credentials in the SQLite/log
   stores exist only to demonstrate capture mechanics; never exfiltrate and
   never use them against a third party.
4. **iptables side effects.** Live `--apply` runs modify the `nat` table
   (`PREROUTING`) on the chosen interface and may toggle
   `net.ipv4.ip_forward`. `mitm restore` is the guaranteed cleanup; verify it
   with `mitm restore --dry-run` after every session.
5. **No identity leaks.** Do not commit real IPs, MACs, SSIDs, names, or
   personal data to this repository. Defaults are documentation-lab
   placeholders only.

See `README.md` — `## IMPORTANT: Read before use.` — and `LICENSE` (MIT) for
the full legal and responsible-disclosure statements. This software is
provided "AS IS" without warranty; the author is not responsible for misuse.