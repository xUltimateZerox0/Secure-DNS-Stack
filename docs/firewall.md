# Firewall

## Scope

DNS-only packet filter. Outbound leak prevention with nftables,
inbound DNS allowlist with UFW.

## Outbound

File `configs/etc/nftables.conf` at `/etc/nftables.conf`.

- Chain `inet filter output`, policy accept.
- Drop UDP and TCP to port 53 unless destination is loopback.
- IPv4 loopback `127.0.0.0/8` keeps Pi-hole to Unbound on `127.0.0.1:5335`.
- IPv6 loopback `::1` for the same local path.
- `destroy table inet filter` before rebuild keeps reload idempotent.
- Recursive mode adds temporary `skuid unbound it (eg. 102)` accepts above drops, removed when returning to DoT mode.

## Inbound

Allow DNS queries to Pi-hole only from trusted networks:

- `192.168.1.0/24` on `eno1`, UDP and TCP port 53.
- `100.64.0.0/10` on `tailscale0`, UDP and TCP port 53.
- Default incoming deny, loopback allowed.

Admin HTTPS on port 443 follows the same interfaces.

## Verification

- Double reload keeps four drop rules with no duplicates.
- DOT mode: queries from any local user to external port 53 time out,
  Pi-hole on `127.0.0.1` still resolves.
- Recursive mode: Unbound UID bypasses the drops while other users
  remain blocked, order is two accepts above four drops.
- Base rules persist after reboot.

## Design notes

- Port 53 scope: drops apply to cleartext DNS, loopback stays
  allowed for Pi-hole to Unbound. Upstream TLS uses port 853
  and is defined in the Unbound config.
- Boot default: after boot the host enforces dot until
  the operator selects recursive. A persistent choice can be saved with
  `sudo unbound-manage recursive|dot --persistent` or
  `sudo unbound-manage default recursive|dot`.
- Backup storage: backups under `/var/backups/secure-dns-stack` are root-only
  `0700`, not encrypted. Encrypt the volume on shared hardware.
