# X5 MITM Suite — Metrics

Pending own-lab live run. Record numbers here after executing the Live Lab
Test Plan (see README) and archive the metric video under `videos/`.

## captures/min  (live `mitm http --apply` session)

| Date | Session start | Duration (min) | Captures | Captures/min | Video |
|------|---------------|----------------|----------|--------------|-------|
| _pending_ | | | | | |

## restore reliability (20 restarts)

Protocol: run `mitm arp` / `mitm http` / `mitm dns` with `--apply`, SIGINT 20x.
After every restart: `mitm restore --dry-run` must report zero
`x5-mitm-suite` rules and `net.ipv4.ip_forward` restored to its prior value.

| Run # | Residual x5-mitm-suite rules | ip_forward restored | Clean |
|-------|------------------------------|---------------------|-------|
| 1..20 | _pending_ | _pending_ | _pending_ |

Result: **pending** / 20 clean restores.

## Commands used

```bash
mitm self-test                  # offline gate (must exit 0)
mitm metrics                    # captures/min from logs/mitm.db
mitm restore --dry-run          # residual-rule check after each SIGINT
```