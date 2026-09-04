# Secure-DNS-Stack (WIP)

Bare metal DNS infrastructure featuring Pi-hole and Unbound, usable by any device through a Tailscale VPN, providing either recursive or DoT (DNS-over-TLS) resolution mode. State management is provided by a custom bash script.

## Status

🟢 Production: Running on personal bare-metal Debian server since June 2026.

## Architecture Overview

Unlike standard Docker deployments, this stack is built directly on bare-metal to enforce strict, process-level network security.

```text
                 [ Tailscale VPN ]
                        |  (Encrypted)
                        v
                 [ Pi-hole :53 ] (DNS Sinkhole)
                        |  (Filtered)
                        v
                [ Unbound :5335 ] (Resolver)
                        |
========================|=========================================
 nftables Firewall      | (DROP outbound 53/UDP+TCP) 
                        +-- ALLOW if meta skuid == 102 (unbound uid)
========================|=========================================
                        |
       +----------------+----------------+
       |                                 |
 [ DoT Mode ]                    [ Recursive Mode ]
 Quad9 (Port 853)                Root Servers (Port 53)
 (Encrypted)                     (Cleartext)
 ```

*   **DNS Sinkhole & Resolver** - Pi-hole handles aggressive ad-blocking and telemetry filtering, forwarding allowed queries to a hardened local Unbound daemon.
*   **Dynamic Resolution Modes** - A custom CLI tool allows atomic switching between **DNS-over-TLS (Quad9)** for query encryption, or **Iterative Root Resolution** for direct recursive querying.
*   **Kernel-Level Leak Prevention** - An `nftables` firewall drops all outbound cleartext DNS traffic (port 53, UDP and TCP), featuring a `skuid` (Socket UID) exemption exclusively for the Unbound process. 
*   **Secure Remote Access** - Bound directly to Tailscale interfaces, allowing encrypted DNS resolution from any authorized remote device without exposing ports to the public internet.

## Security Posture & Threat Model

**🛡️ In-Scope (Mitigated Threats):**
*   **Client-Side Threats & Telemetry (Pi-hole):** Protects all LAN and VPN clients from known malware domains, phishing, and device telemetry at the network level, before queries ever leave the local environment.
*   **Active DNS Tampering (Unbound & DNSSEC):** The local Unbound daemon cryptographically validates all signed DNS responses. This prevents DNS spoofing and cache poisoning, ensuring a malicious actor or ISP cannot forge replies for DNSSEC-signed zones to redirect traffic to rogue IPs.
*   **Passive Query Snooping (DoT Mode):** When utilizing DNS-over-TLS, queries between the local Unbound daemon and the upstream provider (Quad9) are encrypted, preventing the ISP from reading the DNS payload in transit.
*   **Local Process Exfiltration (nftables):** The `skuid` ruleset ensures that if a local process or a misconfigured container attempts to bypass Pi-hole by querying external DNS servers on port 53, the traffic is instantly dropped.

**⚠️ Out-of-Scope (Known Limitations):**
*   **SNI Leaks & Traffic Analysis:** Even with DoT encrypting the DNS lookup, the ISP **can still determine** which websites are visited via the plaintext SNI (Server Name Indication) in subsequent HTTPS connections. This stack does **not** provide Tor-like anonymity.
*   **Recursive Mode Cleartext:** When switching to Iterative Root Resolution, queries to authoritative servers are made in cleartext (port 53). While this makes the resolution independent from any third-party DNS provider, and uses DNSSEC for signed zones to ensure integrity, confidentiality from the ISP is lost.
*   **Encrypted DNS Bypass (DoH and Local DoT Clients):** Applications using hard-coded DNS-over-HTTPS, or any local process reaching port 853 directly, bypass Pi-hole entirely. The firewall governs cleartext DNS on port 53 only; endpoint control of such clients is outside this stack.

## Operations & State Management

Manually editing DNS daemon configurations is complex, error-prone, and can lead to silent resolution failures. For this reason the stack is entirely managed by `unbound-manage`, a custom bash tool that controls the operational state of the DNS infrastructure, allowing automatic switching between the two resolution modes with just one command.

**Key Engineering Properties:**
*   **Atomic Transitions:** Configurations are generated into temporary files, validated via `unbound-checkconf`, and applied atomically. The daemon is never restarted with a broken config.
*   **Firewall Synchronization:** When switching to `recursive` mode, the script dynamically injects the `skuid` exemption directly into the `nftables` ruleset, and securely removes it when switching back to `dot`.
*   **Idempotency (Fast-Path):** Re-applying the current active mode is a fast-path no-op. The script detects the running state and leaves the daemon untouched, saving resources.
*   **Fail-Forward Design:** If validation fails post-reload, the script intentionally avoids automatic rollbacks (which can cause looping failures) and instead prints the exact manual recovery commands alongside the retained configuration backup.
*   **Persistent Default:** Boot default is dot. With `--persistent` the mode is saved to `/var/lib/unbound-manage/mode` and reapplied at boot by `unbound-manage-restore.service`.

Runs ONLY on the Pi-hole + Unbound server (auto-guarded). Full reference: `unbound-manage --help`.

| Command | Purpose | Time |
|---|---|---|
| `dot [--persistent]` | Switch Unbound to DoT forwarding → Quad9 only (removes non-Quad9 upstreams, DNSSEC stays on) | ~3-5s |
| `recursive [--persistent]` | Switch to full recursion (root hints + anchor + qname minimisation, no forwarders) | ~3-5s |
| `default [dot\|recursive\|clear\|show]` | Save boot default mode, like `--persistent` but without switching. | instant |
| `status` | Full diagnostic (mode, services, Tailscale, listeners, connectivity, resolv.conf, upstream, resolution, blocking, DNSSEC, DoT activity, firewall) | ~5-8s |
| `fix-resolv` | Point /etc/resolv.conf to 127.0.0.1 (Pi-hole) | ~1-2s |
| `--debug` | First-or-last-argument flag showing every command + raw output | — |


## Verification & Evidence

To prove the operational status and security boundaries of the stack, the custom `status` command provides a full diagnostic output. This empirically validates DNSSEC, Pi-hole sinkholing, Tailscale connectivity, and the active `nftables` leak protection in real-time.

```text
$ sudo unbound-manage status

━━━ Environment ━━━
 ✔ Running on Station (Pi-hole + Unbound server)
 → unbound port: 5335

━━━ Mode ━━━
  MODE: DOT (DoT forwarding)
  defining file: /etc/unbound/unbound.conf.d/unbound-manage.conf
 ✔ upstream: 9.9.9.9@853#dns.quad9.net (Quad9)
 ✔ upstream: 149.112.112.112@853#dns.quad9.net (Quad9)
 ✔ DNSSEC root anchor: /var/lib/unbound/root.key

━━━ Services ━━━
 ✔ unbound: active (enabled)
 ✔ pihole-FTL: active (enabled)
 ✔ tailscaled: active (enabled)

━━━ Tailscale ━━━
 ✔ this node: 100.111.xxx.xxx
 ✔ interface reachable (tailscale0)
 ✔ peers: 3

━━━ Listeners ━━━
 ✔ port 53: listening (Pi-hole)
 ✔ port 5335: listening (Unbound)

━━━ Connectivity ━━━
 ✔ gateway 192.168.1.1 reachable
 ✔ internet: 9.9.9.9 reachable
 ✔ DoT: TCP 9.9.9.9:853 open

━━━ resolv.conf ━━━
 ✔ nameserver 127.0.0.1 (Pi-hole)

━━━ Pi-hole upstream ━━━
 ✔ upstreams: [ 127.0.0.1#5335 ] (→ unbound :5335)
 ✔ gravity: 493887 blocked domains

━━━ Resolution ━━━
 ✔ pihole :53 → 142.251.27.138
 ✔ unbound :5335 → 142.251.27.102
 → tailscale 100.111.xxx.xxx:53 no response (expected: dropped by DNS-leak firewall)

━━━ Blocking ━━━
 ✔ doubleclick.net → 0.0.0.0 (blocked)

━━━ DNSSEC ━━━
 ✔ dnssec-failed.org → SERVFAIL (validation active)
 ✔ www.ietf.org → NOERROR

━━━ DoT activity ━━━
 ✔ 2 live TLS connection(s) to Quad9:853

━━━ DNS-leak firewall ━━━
 ✔ nftables: 8 rule(s) for port 53 (cleartext DNS blocked)

 ✔ All checks passed (3592ms)
```

## Debugging notes

Incident trail (symptom → cause → fix) is collected in [docs/debugging.md](docs/debugging.md) as production runs teach new ones.

## Installation & Deployment

⚠️ **Environment Warning:** This stack is designed exclusively for dedicated bare-metal hardware. The installation **deeply** modifies system network states. **Do not deploy this on a daily-driver machine**

The repository includes a deployment script (`install.sh`) that converges a Debian-family machine to the configs in this repo. It is idempotent, backs up every replaced file under `/var/backups/secure-dns-stack` with checksums, and refuses to silently replace customized firewalls or configs without `--takeover`.

**Supported Operating Systems:**
*   Debian 13 "trixie" (tested on production server)
*   Raspberry Pi OS and Armbian (Debian-family, same package set)
*   Other systems are not covered by my tests; `--allow-unsupported` lets you try anyway and report back

**Remote access (optional, independent):** remote DNS over Tailscale needs a joined tailnet, configured separately with `sudo tailscale up`. Without it the stack serves the LAN only.

**What the script does:**
1.  Preflight checks (root, systemd, OS family, free disk, port holders) with `--dry-run` available.
2.  Installs core dependencies (`unbound`, `nftables`, `dns-root-data`, `bind9-dnsutils`, `ca-certificates`, `curl`, `sqlite3`, `iproute2`).
3.  Disables `systemd-resolved`/`resolvconf` stubs when present and locks `/etc/resolv.conf` to `127.0.0.1`, shielded from NetworkManager.
4.  Deploys the `nftables` leak-prevention ruleset without touching other tables, plus Unbound base tuned to installed RAM.
5.  Installs Pi-hole with the official installer when missing (network identity detected, confirmed, never changed), then enforces upstream `127.0.0.1#5335`, HTTPS-only admin and blocklists on any install.
6.  Installs `unbound-manage` in `/usr/local/bin` and enables the boot restore service, then adds UFW DNS allows only.
7.  Verifies everything with `unbound-manage status`.

### Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/xUltimateZerox0/Secure-DNS-Stack.git
cd Secure-DNS-Stack

# 2. Review the installer (root privileges needed, do not execute blindly)
less install.sh

# 3. Preview without changing anything
sudo ./install.sh --dry-run

# 4. Execute deployment (add --takeover only to replace customized configs)
sudo ./install.sh

# 5. Verify the deployment
sudo unbound-manage status
```

### After Install

> **IMPORTANT**
> *   Set the web password yourself with `pihole setpassword` — the installer never touches personal credentials/secrets.
> *   On DHCP networks reserve a static address for the server on the router, otherwise clients pointing at it lose DNS when the lease changes.

## License

Distributed under the MIT License. See the `LICENSE` file for more information.
