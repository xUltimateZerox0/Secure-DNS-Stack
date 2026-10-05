# Debugging

Incident reports land here after production runs (symptom, cause, fix, evidence).

<<<<<<< HEAD
## 2026-09-12 — `dietpi.conf` vs `pi-hole.conf` (ThinkerBoard, DietPi)

- **Symptom:** `./install.sh` stopped at `Phase unbound` with `unbound-checkconf rejected the config`, leaving a broken `pi-hole.conf` on disk next to DietPi's `dietpi.conf`.
- **Cause:** the installer only checked same-path overwrites and validated *after* deploying, so the duplicate root `forward-zone "."` (one per file) was never caught upfront — and `checkconf` stderr was swallowed, hiding the real error.
- **Fix:** sibling scan for root forward-zones (comment-aware, include-aware) with backup + prompt before touching anything; protected names (`dietpi.conf`, `pi-hole.conf`) always ask, even with `--yes`; visible `checkconf` output; auto-revert of the just-deployed file when the full check fails.
=======
## 2026-10-05 — MagicDNS names (station.tail1234.ts.net) unresolvable via Pi-hole

**Symptom.** Clients using Pi-hole as resolver got NXDOMAIN for
`station.tail1234.ts.net` (EDE 3, Stale Answer). The HTTPS endpoint
`https://station.tail1234.ts.net` was unreachable by name.

**Evidence.**
- `dig @100.111.y.z station.tail1234.ts.net` → NXDOMAIN; public DoH
  query for the same name → NXDOMAIN (Status 3): the name does not exist in
  public DNS.
- `dig @100.100.100.100 station.tail1234.ts.net` (workstation) → NOERROR,
  A 100.111.y.z, flags `aa`, 0 ms: only the per-host resolver inside
  `tailscaled` knows the tailnet zone.
- On the server itself, `dig @100.100.100.100 ...` timed out: the DNS-leak
  firewall dropped outbound :53 to anything but loopback, including the
  server's own MagicDNS resolver.
- `ts.net` has no DS record → the tailnet zone is unsigned, no DNSSEC chain to
  validate.

**Cause.** Pi-hole forwards everything to Unbound, which resolves via Quad9
DoT/root; neither knows the private tailnet zone. Tailscale's official pattern
for Unbound (OPNsense integration doc) is a query-forward entry for the
MagicDNS zone to `100.100.100.100`, which was missing.

**Fix.**
1. Unbound forward zone for the tailnet (`<tailnet>.ts.net.` →
   `100.100.100.100` plus `domain-insecure`). This file is **per-tailnet** and it is  managed by `install.sh`
   `/etc/unbound/unbound.conf.d/99-tailscale-magicdns.conf` is created at install time from the local `tailscaled` state (`tailscale dns status --json`, falling back to `tailscale status --json`, field `CurrentTailnet.MagicDNSSuffix`), then
   validates it with `unbound-checkconf` before reloading. Re-run the installer
   after joining the tailnet or renaming it.
2. `configs/etc/nftables.conf`: accept UDP/TCP `100.100.100.100:53` before the
   drops (destination-scoped, no `skuid`, to avoid clashing with the
   recursive-mode exemption logic and the installer's live-rule whitelist).
3. Flush Pi-hole's negative cache (`systemctl restart pihole-FTL`) so the
   stale NXDOMAIN is not served.

**Verification.** `dig @127.0.0.1 <host>.<tailnet>.ts.net` →
the device tailnet IP; public names unchanged; recursive↔dot switch leaves the
new forward and firewall rule intact (verified: in recursive the generic
`skuid` exemption is added and the scoped rule stays; in dot the generic
exemption is removed and the scoped rule stays); `dig @127.0.0.1
nonexistent.<tailnet>.ts.net` answers immediately (4 ms, no timeout → no loop).
>>>>>>> c041a61 (fix(MagicDNS): The architecture now manages the tailnet domain, that before was not resolved due to unbound global resolution.)
