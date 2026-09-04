#!/bin/bash
# Secure-DNS-Stack installer for Debian-family bare metal (Debian, Raspberry Pi OS, Armbian/TinkerOS).
# Idempotent: re-running applies only missing state. Safe default is interactive;
# automation uses --yes. Nothing changes with --dry-run.
#
# Order: preflight -> backup -> packages -> resolver lock -> nftables ->
# unbound -> pihole (incl. managed keys) -> unbound-manage -> ufw -> verify.
# Each phase verifies before the next starts. On failure the script stops
# and prints restore paths, it never auto-rolls back a running DNS server.
set -uo pipefail

VERSION="0.1.0"
# Repo root is the script directory, never the caller CWD.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DRY_RUN=0
ASSUME_YES=0
ALLOW_UNSUPPORTED=0
TAKEOVER=0
LOG="/var/log/secure-dns-install.log"
BACKUP_ROOT="/var/backups/secure-dns-stack"
BACKUP_DIR=""
KEEP_BACKUPS=5

log() { echo "[install] $*"; }
warn() { echo "[install] WARNING: $*"; }
run_log() { echo "[install] $*" >> "$LOG" 2>/dev/null || true; }

# All mutations go through here: with --dry-run print and skip.
mutate() {
    if (( DRY_RUN )); then
        log "DRY-RUN skip: $*"
        return 0
    fi
    run_log "run: $*"
    "$@"
}

confirm_or_exit() {
    local prompt="${1:-Continue?}"
    (( ASSUME_YES || DRY_RUN )) && return 0
    local answer
    echo -n "$prompt [y/N] "
    read -r answer </dev/tty 2>/dev/null || read -r answer
    [[ "${answer:-N}" =~ ^[yY]$ ]] && return 0
    log "Aborted by user."
    if [[ -n "${BACKUP_DIR:-}" && -d "$BACKUP_DIR" ]]; then
        log "Partials keep backups in $BACKUP_DIR, restore with: sudo cp -a $BACKUP_DIR/<path> <path>"
    fi
    exit 1
}

usage() {
    cat << EOF
Usage: sudo ./install.sh [--dry-run] [--yes] [--allow-unsupported] [--takeover]

  --dry-run            Print actions, change nothing. Safe on any machine.
  --yes                Skip confirmations. Only for fresh dedicated hardware.
  --allow-unsupported  Run on non-Debian-family OS at your own risk.
  --takeover           Replace customized configs (backup kept).
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run) DRY_RUN=1 ;;
            --yes) ASSUME_YES=1 ;;
            --allow-unsupported) ALLOW_UNSUPPORTED=1 ;;
            --takeover) TAKEOVER=1 ;;
            -h|--help) usage; exit 0 ;;
            *) log "Unknown argument: $1"; usage; exit 1 ;;
        esac
        shift
    done
    if (( DRY_RUN )); then LOG="/tmp/secure-dns-install-dryrun.log"; fi
}

# --- Preflight: refuse to break the wrong machine ---

preflight() {
    log "Preflight checks"
    [[ "$(id -u)" -eq 0 ]] || { log "Must run as root."; exit 1; }
    command -v systemctl >/dev/null || { log "systemd required."; exit 1; }
    pidof systemd >/dev/null 2>&1 || { log "systemd not running."; exit 1; }
    # Danger flags are loud; --yes never implies them, each stays explicit.
    # Confirms happen below at informed points, warnings print now.
    (( ALLOW_UNSUPPORTED )) && warn "Unsupported OS bypass active: verified for Debian-family only."
    (( TAKEOVER )) && warn "Takeover mode: customized firewalls and configs get replaced, backups kept."
    (( ASSUME_YES )) && log "Unattended mode: confirmations skipped."

    # OS family allowlist, never assume apt-based. Parse, never source.
    local id="" like=""
    if [[ -f /etc/os-release ]]; then
        id=$(grep -E '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"' | head -1)
        like=$(grep -E '^ID_LIKE=' /etc/os-release | cut -d= -f2 | tr -d '"' | head -1)
    fi
    if [[ "$id" != "debian" && "$id" != "raspbian" && "$like" != *"debian"* ]]; then
        log "Unsupported OS: ${id:-unknown}."
        (( ALLOW_UNSUPPORTED )) || { log "Use --allow-unsupported to override."; exit 1; }
        warn "Anything may break on this OS, review every step."
        confirm_or_exit "Really continue on unsupported OS?"
    fi
    command -v apt-get >/dev/null || { log "apt-get required on this OS."; exit 1; }
    log "OS: ${id:-unknown} arch: $(dpkg --print-architecture 2>/dev/null || uname -m)"
    # Gravity plus packages need room, SD cards fill silently.
    local avail_kb
    avail_kb=$(df -k / 2>/dev/null | awk 'NR==2{print $4}')
    if [[ "$avail_kb" =~ ^[0-9]+$ ]] && (( avail_kb < 512000 )); then
        log "Less than 500MB free on /, aborting."
        exit 1
    fi

    # All repo sources must exist before any mutation, never fail mid-install.
    local src missing=0
    for src in configs/etc/resolv.conf \
               configs/etc/NetworkManager/conf.d/90-dns-none.conf \
               configs/etc/nftables.conf \
               configs/etc/systemd/system/nftables.service.d/override.conf \
               configs/etc/systemd/system/unbound-manage-restore.service \
               configs/etc/unbound/unbound.conf.d/pi-hole.conf \
               configs/etc/pihole/dns-managed.conf \
               configs/etc/pihole/adlists.txt \
               unbound-manage; do
        if [[ ! -f "${SCRIPT_DIR}/${src}" ]]; then
            log "Missing repo file: ${src} (run from a full clone, then git pull)."
            missing=1
        fi
    done
    (( missing )) && exit 1

    # Unknown listener on 53 means someone else owns DNS here.
    # Our own daemons are fine and never prompt on re-runs.
    local holder unknown
    holder=$(ss -tulpn 2>/dev/null | grep -E ':(53|5335) ' || true)
    if [[ -n "$holder" ]]; then
        unknown=$(echo "$holder" | grep -vE '"(pihole-FTL|unbound|pihole)"' || true)
        if [[ -n "$unknown" ]]; then
            log "Unknown DNS listener:"
            echo "$unknown"
            confirm_or_exit "Third-party DNS detected. Take over?"
        else
            log "Listeners are our own daemons, continuing."
        fi
    fi
    [[ -n "${SSH_CONNECTION:-}" ]] && log "Over SSH: network steps may drop you; reconnect and re-run."
    if (( TAKEOVER )); then
        warn "Takeover confirmed by flag: foreign firewalls and configs will be replaced."
        confirm_or_exit "Really replace customized configs?"
    fi
    confirm_or_exit "Install on THIS machine ($(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || uname -n))?"
}

# --- Backup: one timestamped root with manifest, rotated ---

make_backup_root() {
    BACKUP_DIR="${BACKUP_ROOT}/$(date +%Y%m%d-%H%M%S)"
    mutate mkdir -p "$BACKUP_DIR"
    # Backups may hold secrets (pihole.toml), root only.
    mutate chmod 0700 "$BACKUP_ROOT" "$BACKUP_DIR"
    log "Backups in $BACKUP_DIR (kept: $KEEP_BACKUPS)"
}

# Save one live path before first write, record checksum when possible.
backup_path() {
    local src="$1"
    [[ -e "$src" || -L "$src" ]] || return 0
    local dest="${BACKUP_DIR}${src}"
    if [[ -e "$dest" ]]; then return 0; fi
    mutate mkdir -p "$(dirname "$dest")"
    mutate cp -a "$src" "$dest"
    if (( DRY_RUN )); then
        log "DRY-RUN backup: $src"
        return 0
    fi
    if command -v sha256sum >/dev/null; then
        sha256sum "$src" 2>/dev/null >> "${BACKUP_DIR}/MANIFEST" || true
    fi
    log "Backed up $src"
}

prune_backups() {
    if (( DRY_RUN )); then return 0; fi
    ls -dt "${BACKUP_ROOT}"/*/ 2>/dev/null | tail -n +"$((KEEP_BACKUPS + 1))" \
        | xargs -r rm -rf
}

# --- Deploy primitive: atomic tmp + perms + move, backup first ---

# deploy_file SRC DST MODE, SRC relative to repo root.
# Uses install(1) for owner/mode/dir creation like Debian packaging does.
# Sets DEPLOY_CHANGED=1 when it writes.
DEPLOY_CHANGED=0
deploy_file() {
    local src="$1" dst="$2" mode="${3:-644}"
    [[ "$src" != /* ]] && src="${SCRIPT_DIR}/${src}"
    [[ -f "$src" ]] || { log "Missing source: $src"; return 1; }
    if cmp -s "$src" "$dst" 2>/dev/null; then
        log "Unchanged: $dst"
        return 0
    fi
    backup_path "$dst"
    mutate mkdir -p "$(dirname "$dst")"
    if (( DRY_RUN )); then
        log "DRY-RUN deploy: $src -> $dst ($mode)"
        return 0
    fi
    local tmp
    tmp=$(mktemp "$(dirname "$dst")/.deploy.XXXXXX") || return 1
    mutate install -m "$mode" -o root -g root "$src" "$tmp" || return 1
    mutate mv -f "$tmp" "$dst" || return 1
    DEPLOY_CHANGED=1
    log "Deployed: $dst"
}

# --- Packages: same names on amd64/arm64/armhf, retrocompat fallbacks ---

# True when dpkg knows the package as installed and configured.
pkg_installed() {
    dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"
}

# apt-get with lock wait: unattended-upgrades may hold the lock after boot.
apt_get_locked() {
    local tries=0
    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
        tries=$((tries + 1))
        if (( tries > 30 )); then
            log "apt lock held too long, aborting."
            return 1
        fi
        log "Waiting for apt lock (${tries}x10s)..."
        sleep 10
    done
    mutate env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@"
}

install_packages() {
    local missing=() pkg
    for pkg in "$@"; do
        if ! pkg_installed "$pkg"; then missing+=("$pkg"); fi
    done
    if (( ${#missing[@]} == 0 )); then
        log "Packages already present: $*"
        return 0
    fi
    log "Installing: ${missing[*]}"
    apt_get_locked "${missing[@]}"
}

# First package in the list that exists in apt cache (retrocompat).
first_available() {
    local pkg
    for pkg in "$@"; do
        if apt-cache show "$pkg" >/dev/null 2>&1; then
            echo "$pkg"
            return 0
        fi
    done
    return 1
}

# --- Resource profile: RAM decides unbound cache, never assume a big server ---

# Sets UNBOUND_THREADS/MSG_CACHE/RRSET_CACHE from MemTotal.
# Covers 512MB boards up to servers; caps are limits, not preallocation.
mem_profile() {
    local kb threads
    kb=$(awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null || echo 0)
    threads=$(nproc 2>/dev/null || echo 2)
    if (( kb > 0 && kb <= 1048576 )); then
        UNBOUND_THREADS=1; UNBOUND_MSG="32m";  UNBOUND_RRSET="64m"
    elif (( kb > 0 && kb <= 2097152 )); then
        UNBOUND_THREADS=1; UNBOUND_MSG="64m";  UNBOUND_RRSET="128m"
    else
        UNBOUND_THREADS=2; UNBOUND_MSG="128m"; UNBOUND_RRSET="256m"
        (( threads < 2 )) && UNBOUND_THREADS=1
    fi
    log "RAM profile: $((kb / 1024))MB -> threads=$UNBOUND_THREADS msg=$UNBOUND_MSG rrset=$UNBOUND_RRSET"
}

phase_packages() {
    log "Phase packages"
    mutate apt-get update -qq
    local dig_pkg
    # trixie: dnsutils is virtual, real name is bind9-dnsutils (all arches).
    # bookworm and older: bind9-dnsutils exists too, dnsutils as fallback.
    dig_pkg=$(first_available bind9-dnsutils dnsutils) \
        || { log "No dig package found."; return 1; }
    install_packages unbound dns-root-data nftables ca-certificates \
        curl sqlite3 iproute2 "$dig_pkg"
    mem_profile
}
phase_resolver() {
    log "Phase resolver lock"
    # systemd-resolved owns :53 via stub when present, it must go first.
    if systemctl list-unit-files systemd-resolved.service >/dev/null 2>&1 \
        && systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        log "systemd-resolved active, disabling stub listener."
        confirm_or_exit "Disable systemd-resolved?"
        mutate systemctl disable --now systemd-resolved
    fi
    # resolvconf rewrites resolv.conf on interface events, same fight.
    if systemctl is-active --quiet resolvconf.service 2>/dev/null \
        || systemctl is-active --quiet unbound-resolvconf.service 2>/dev/null; then
        log "resolvconf service active, disabling it."
        confirm_or_exit "Disable resolvconf?"
        mutate systemctl disable --now resolvconf.service
        mutate systemctl disable --now unbound-resolvconf.service
    fi
    if [[ -f /etc/unbound/unbound.conf.d/resolvconf_resolvers.conf ]]; then
        log "Stale resolvconf fragment found, removing."
        backup_path /etc/unbound/unbound.conf.d/resolvconf_resolvers.conf
        mutate rm -f /etc/unbound/unbound.conf.d/resolvconf_resolvers.conf
    fi
    if [[ -L /etc/resolv.conf ]]; then
        log "resolv.conf is a symlink, replacing with a static file."
        backup_path /etc/resolv.conf
        if (( ! DRY_RUN )); then rm -f /etc/resolv.conf; fi
    fi
    DEPLOY_CHANGED=0
    deploy_file configs/etc/resolv.conf /etc/resolv.conf 644
    if ! grep -q '^nameserver 127\.0\.0\.1' /etc/resolv.conf 2>/dev/null; then
        if (( DRY_RUN )); then
            log "DRY-RUN: resolv.conf would be fixed to 127.0.0.1."
        else
            log "resolv.conf does not point to Pi-hole after deploy."
            return 1
        fi
    fi
    # NetworkManager only: keep it from reclaiming resolv.conf later.
    if [[ -d /etc/NetworkManager ]] || command -v NetworkManager >/dev/null 2>&1; then
        DEPLOY_CHANGED=0
        deploy_file configs/etc/NetworkManager/conf.d/90-dns-none.conf \
            /etc/NetworkManager/conf.d/90-dns-none.conf 644
        if (( DEPLOY_CHANGED )) && systemctl is-active --quiet NetworkManager 2>/dev/null; then
            log "NetworkManager active: reload needed for dns=none."
            confirm_or_exit "Reload NetworkManager now?"
            mutate systemctl reload NetworkManager
        fi
    else
        log "No NetworkManager, skipping dns=none snippet."
    fi
}
phase_nftables() {
    log "Phase nftables"
    # Never silently replace someone else's firewall: only tables outside
    # our own "inet filter" count as foreign (UFW/Tailscale live in RAM,
    # not in this file). Backup is kept in every case.
    if [[ -f /etc/nftables.conf ]] \
        && ! cmp -s "${SCRIPT_DIR}/configs/etc/nftables.conf" /etc/nftables.conf 2>/dev/null; then
        local foreign
        foreign=$(grep -E '^[[:space:]]*table ' /etc/nftables.conf 2>/dev/null \
            | awk '{print $2, $3}' | grep -v -x "inet filter" || true)
        if [[ -n "$foreign" && "$TAKEOVER" -ne 1 ]]; then
            log "Foreign tables in /etc/nftables.conf: $foreign"
            log "Merge manually or re-run with --takeover (backup is kept)."
            return 1
        fi
        (( TAKEOVER )) && log "Takeover requested, replacing with backup kept."
    fi
    # Same for the live table we destroy: anything beyond our drops and
    # skuid accepts means someone else filters there.
    if (( ! TAKEOVER )); then
        local live rest
        live=$(nft list table inet filter 2>/dev/null || true)
        if [[ -n "$live" ]]; then
            rest=$(echo "$live" | tr ';{}' '\n\n\n' \
                | grep -vE "table inet filter|chain output|type filter hook output|policy (accept|drop)|dport 53 (ip|ip6)? ?daddr.*drop|meta skuid.*dport 53 accept|^[[:space:]]*$" || true)
            if [[ -n "$rest" ]]; then
                log "Foreign live rules in table inet filter:"
                echo "$rest" | head -5
                log "Re-run with --takeover to replace (backup is kept)."
                return 1
            fi
        fi
    fi
    local had_exempt="" uid
    if nft list table inet filter 2>/dev/null | grep -q "skuid"; then
        had_exempt=1
        uid=$(id -u unbound 2>/dev/null || true)
        log "Live recursive exemption found, will preserve it."
    fi
    DEPLOY_CHANGED=0
    deploy_file configs/etc/nftables.conf /etc/nftables.conf 644
    local base_changed=$DEPLOY_CHANGED
    deploy_file configs/etc/systemd/system/nftables.service.d/override.conf \
        /etc/systemd/system/nftables.service.d/override.conf 644
    if (( DEPLOY_CHANGED )) && (( ! DRY_RUN )); then
        mutate systemctl daemon-reload
    fi
    if ! nft -c -f /etc/nftables.conf 2>/dev/null; then
        if (( DRY_RUN )); then
            log "DRY-RUN: nftables check skipped."
        else
            log "nftables config invalid."
            return 1
        fi
    fi
    # Apply only on change or when drops are missing/duplicated.
    local drops
    drops=$(nft list table inet filter 2>/dev/null | grep -c "dport 53.*drop" || true)
    if (( base_changed )) || [[ "${drops:-0}" != "4" ]]; then
        log "Applying nftables base (drops found: ${drops:-0}, want 4)."
        mutate systemctl enable nftables
        if systemctl is-active --quiet nftables 2>/dev/null; then
            mutate systemctl reload nftables
        else
            mutate systemctl start nftables
        fi
        if [[ -n "$had_exempt" && -n "${uid:-}" ]] && (( ! DRY_RUN )); then
            nft insert rule inet filter output meta skuid "$uid" udp dport 53 accept 2>/dev/null || true
            nft insert rule inet filter output meta skuid "$uid" tcp dport 53 accept 2>/dev/null || true
            log "Recursive exemption preserved for uid $uid."
        fi
    else
        log "nftables base already correct, untouched."
    fi
    if (( ! DRY_RUN )); then
        drops=$(nft list table inet filter 2>/dev/null | grep -c "dport 53.*drop" || true)
        [[ "${drops:-0}" == "4" ]] || { log "Expected 4 drops, found ${drops:-0}."; return 1; }
        log "nftables verified: 4 drops, no duplicates."
    fi
}
phase_unbound() {
    log "Phase unbound"
    # Managed machines own their config via unbound-manage.conf, never
    # stack a second file declaring the same interface and port.
    if [[ -f /etc/unbound/unbound.conf.d/unbound-manage.conf ]]; then
        log "Managed by unbound-manage.conf, pi-hole.conf stays out."
        if (( DRY_RUN )); then return 0; fi
        systemctl is-active --quiet unbound 2>/dev/null \
            || { log "unbound not running."; return 1; }
        local r
        r=$(dig +short @127.0.0.1 -p 5335 google.com 2>/dev/null | grep -E '^[0-9.]+$' | head -1)
        [[ -n "$r" ]] || { log "unbound :5335 does not resolve."; return 1; }
        log "unbound :5335 resolves -> $r"
        return 0
    fi
    # Fresh machines get the rendered repo base for this RAM profile.
    # The first manual 'unbound-manage dot|recursive' later adopts it:
    # disables this file to *.disabled with backup, takes over the mode.
    local src="${SCRIPT_DIR}/configs/etc/unbound/unbound.conf.d/pi-hole.conf"
    [[ -f "$src" ]] || { log "Missing source: $src"; return 1; }
    local tmp
    tmp=$(mktemp /tmp/unbound-render.XXXXXX)
    sed -e "s/^\(\s*num-threads:\).*/\1 $UNBOUND_THREADS/" \
        -e "s/^\(\s*msg-cache-size:\).*/\1 $UNBOUND_MSG/" \
        -e "s/^\(\s*rrset-cache-size:\).*/\1 $UNBOUND_RRSET/" \
        "$src" > "$tmp"
    DEPLOY_CHANGED=0
    local dst="/etc/unbound/unbound.conf.d/pi-hole.conf"
    # A foreign pi-hole.conf without our marker is never overwritten blindly.
    if [[ -f "$dst" ]] && ! grep -q "Managed by secure-dns-stack" "$dst" 2>/dev/null \
        && (( ! TAKEOVER )); then
        log "Foreign $dst found, refusing to overwrite it."
        log "Merge manually or re-run with --takeover (backup is kept)."
        rm -f "$tmp"
        return 1
    fi
    if cmp -s "$tmp" "$dst" 2>/dev/null; then
        log "Unchanged: $dst"
    else
        backup_path "$dst"
        if (( DRY_RUN )); then
            log "DRY-RUN deploy: rendered pi-hole.conf -> $dst (threads=$UNBOUND_THREADS msg=$UNBOUND_MSG rrset=$UNBOUND_RRSET)"
        else
            local tmp2
            mutate mkdir -p "$(dirname "$dst")"
            tmp2=$(mktemp "$(dirname "$dst")/.deploy.XXXXXX") || { rm -f "$tmp"; return 1; }
            install -m 644 -o root -g root "$tmp" "$tmp2" || { rm -f "$tmp" "$tmp2"; return 1; }
            mv -f "$tmp2" "$dst" || { rm -f "$tmp" "$tmp2"; return 1; }
            DEPLOY_CHANGED=1
            log "Deployed: $dst"
        fi
    fi
    if (( DRY_RUN )); then rm -f "$tmp"; return 0; fi
    unbound-checkconf /etc/unbound/unbound.conf >/dev/null 2>&1 \
        || { rm -f "$tmp"; log "unbound-checkconf rejected the config."; return 1; }
    log "unbound-checkconf: full config valid"
    mutate systemctl enable unbound
    if (( DEPLOY_CHANGED )) || ! systemctl is-active --quiet unbound 2>/dev/null; then
        mutate systemctl restart unbound
        sleep 2
    fi
    systemctl is-active --quiet unbound 2>/dev/null \
        || { rm -f "$tmp"; log "unbound not running."; return 1; }
    local r
    r=$(dig +short @127.0.0.1 -p 5335 google.com 2>/dev/null | grep -E '^[0-9.]+$' | head -1)
    rm -f "$tmp"
    [[ -n "$r" ]] || { log "unbound :5335 does not resolve."; return 1; }
    log "unbound :5335 resolves -> $r"
}
phase_pihole() {
    log "Phase pihole"
    # Adopt-only: an existing Pi-hole keeps its install, we enforce only
    # our three keys plus blocklists. Fresh installs stay manual for now:
    # unattended setup needs static-IP decisions this script must not guess.
    local has_ftl=0 has_cli=0
    command -v pihole-FTL >/dev/null 2>&1 && has_ftl=1
    command -v pihole >/dev/null 2>&1 && has_cli=1
    if (( ! has_ftl && ! has_cli )); then
        log "No Pi-hole found. Install it first (official installer),"
        log "then re-run: this phase only adopts existing installs."
        return 1
    fi
    if [[ -f /etc/pihole/pihole.toml ]]; then
        backup_path /etc/pihole/pihole.toml
    fi
    if (( has_ftl )); then
        local kv key val current
        while read -r key val; do
            [[ "$key" =~ ^#.*$ || -z "$key" ]] && continue
            current=$(pihole-FTL --config "$key" 2>/dev/null || true)
            # FTL prints lists spaced as [ a, b ], compare spaceless.
            if [[ "$(tr -d ' []"' <<< "$current")" != "$(tr -d ' []"' <<< "$val")" ]] \
                && [[ -n "$current" ]] && (( ! TAKEOVER )); then
                log "Pi-hole $key is custom: '$current', want '$val'."
                confirm_or_exit "Overwrite $key?"
            fi
            log "Enforcing $key = $val"
            mutate pihole-FTL --config "$key" "$val" || return 1
        done < "${SCRIPT_DIR}/configs/etc/pihole/dns-managed.conf"
    else
        log "Pi-hole v5 layout detected, set upstream in the web UI to 127.0.0.1#5335."
    fi
    if [[ -f /etc/pihole/gravity.db ]]; then
        backup_path /etc/pihole/gravity.db
        local url
        while read -r url; do
            [[ "$url" =~ ^#.*$ || -z "$url" ]] && continue
            if (( ! DRY_RUN )); then
                sqlite3 /etc/pihole/gravity.db \
                    "INSERT OR IGNORE INTO adlist (address, enabled, comment) VALUES ('$url', 1, 'secure-dns-stack');" \
                    2>/dev/null || log "Adlist insert skipped: $url"
            else
                log "DRY-RUN adlist: $url"
            fi
        done < "${SCRIPT_DIR}/configs/etc/pihole/adlists.txt"
        log "Refreshing gravity (downloads blocklists, may take minutes)."
        confirm_or_exit "Run pihole gravity update now?"
        mutate pihole -g
    fi
    if (( DRY_RUN )); then return 0; fi
    local r
    r=$(dig +short @127.0.0.1 google.com 2>/dev/null | grep -E '^[0-9.]+$' | head -1)
    [[ -n "$r" ]] || { log "Pi-hole :53 does not resolve."; return 1; }
    log "Pi-hole :53 resolves -> $r"
}
phase_manager() {
    log "Phase unbound-manage"
    local bin="/usr/local/bin/unbound-manage"
    if [[ -f "$bin" ]] && ! grep -q "unbound-manage - Unbound mode manager" "$bin" 2>/dev/null \
        && (( ! TAKEOVER )); then
        log "Foreign $bin found, refusing to overwrite it."
        log "Merge manually or re-run with --takeover (backup is kept)."
        return 1
    fi
    DEPLOY_CHANGED=0
    deploy_file unbound-manage "$bin" 755
    deploy_file configs/etc/systemd/system/unbound-manage-restore.service \
        /etc/systemd/system/unbound-manage-restore.service 644
    if (( DEPLOY_CHANGED )) && (( ! DRY_RUN )); then
        mutate systemctl daemon-reload
    fi
    mutate systemctl enable unbound-manage-restore.service
    if (( DRY_RUN )); then return 0; fi
    "$bin" help >/dev/null 2>&1 || { log "Installed manager does not run."; return 1; }
    systemctl is-enabled --quiet unbound-manage-restore.service 2>/dev/null \
        || { log "Restore unit not enabled."; return 1; }
    log "Manager installed and restore unit enabled."
}
# Network address of a CIDR, pure bash so no extra dependency.
net_of() {
    local cidr="$1"
    local ip="${cidr%%/*}"
    local pfx="${cidr##*/}"
    local a b c d n m
    IFS=. read -r a b c d <<< "$ip"
    n=$(( (a << 24) | (b << 16) | (c << 8) | d ))
    m=$(( (0xFFFFFFFF << (32 - pfx)) & 0xFFFFFFFF ))
    n=$(( n & m ))
    printf "%d.%d.%d.%d/%d" \
        $(( (n >> 24) & 255 )) $(( (n >> 16) & 255 )) \
        $(( (n >> 8) & 255 )) $(( n & 255 )) "$pfx"
}
phase_ufw() {
    log "Phase ufw"
    # Allow-only: never reset, delete or change defaults here. Enabling a
    # firewall remotely can lock out SSH, so an inactive UFW stays off
    # with a loud note instead of --force enable.
    command -v ufw >/dev/null 2>&1 || { log "No ufw, skipping inbound rules."; return 0; }
    if ! ufw status 2>/dev/null | grep -q "Status: active"; then
        log "UFW inactive: DNS allowlist not applied."
        log "When ready run: sudo ufw allow in on <iface> to any port 53 && sudo ufw enable"
        return 0
    fi
    # Interfaces are detected, never hardcoded: LAN via default route,
    # tailnet only when tailscale answers.
    local lan_iface="" lan_net="" rules_added=0
    lan_iface=$(ip -4 route get 1.1.1.1 2>/dev/null \
        | awk '{for (i = 1; i < NF; i++) if ($i == "dev") {print $(i + 1); exit}}')
    if [[ -n "$lan_iface" ]]; then
        local cidr
        cidr=$(ip -4 addr show "$lan_iface" 2>/dev/null | awk '/inet /{print $2; exit}')
        [[ -n "$cidr" ]] && lan_net=$(net_of "$cidr")
    fi
    local iface net proto spec existing
    for spec in "$lan_iface|$lan_net" "tailscale0|100.64.0.0/10"; do
        iface="${spec%%|*}"; net="${spec#*|}"
        [[ -n "$iface" && -n "$net" ]] || continue
        ip link show "$iface" >/dev/null 2>&1 || continue
        existing=$(ufw status numbered 2>/dev/null || true)
        for proto in udp tcp; do
            # Real UFW shape: "53/udp ... on <iface>", or bare "53 ... on <iface>" covering both.
            if grep -qE "53/${proto}[^0-9].*on ${iface}([^a-zA-Z0-9]|$)" <<< "$existing" \
                || grep -qE "(^|[[:space:]])53([[:space:]]).*on ${iface}([^a-zA-Z0-9]|$)" <<< "$existing"; then
                log "UFW already allows $proto/53 on $iface."
                continue
            fi
            log "Allowing $proto/53 on $iface from $net."
            mutate ufw allow in on "$iface" to any port 53 proto "$proto" \
                from "$net" comment "Pi-hole DNS"
            rules_added=1
        done
    done
    if (( rules_added )) && (( ! DRY_RUN )); then
        ufw status numbered 2>/dev/null | grep -E "53" || true
    fi
}
phase_verify() {
    log "Phase verify"
    if (( DRY_RUN )); then
        log "DRY-RUN: live status check skipped."
        return 0
    fi
    if [[ -x /usr/local/bin/unbound-manage ]]; then
        /usr/local/bin/unbound-manage status
        return $?
    fi
    log "unbound-manage not installed, nothing to verify with."
    return 1
}

print_rollback() {
    if (( DRY_RUN )); then
        log "DRY-RUN done, no backups were written."
        return 0
    fi
    cat << EOF

Rollback: originals are in $BACKUP_DIR with MANIFEST checksums.
  1. Compare: diff -r $BACKUP_DIR/etc <path>
  2. Restore one file: sudo cp -a $BACKUP_DIR/<path> <path>
  3. Reload affected service only, then run: sudo unbound-manage status
EOF
}

main() {
    parse_args "$@"
    log "Secure-DNS-Stack installer v$VERSION"
    # No set -e (arithmetic guards would abort it): each phase stops the
    # run on failure and prints rollback paths, never cascading on breakage.
    preflight || { print_rollback; exit 1; }
    make_backup_root || { print_rollback; exit 1; }
    phase_packages || { print_rollback; exit 1; }
    phase_resolver || { print_rollback; exit 1; }
    phase_nftables || { print_rollback; exit 1; }
    phase_unbound || { print_rollback; exit 1; }
    phase_pihole || { print_rollback; exit 1; }
    phase_manager || { print_rollback; exit 1; }
    phase_ufw || { print_rollback; exit 1; }
    phase_verify || { print_rollback; exit 1; }
    prune_backups || exit 1
    log "Done. Backups: $BACKUP_DIR"
    print_rollback
}

main "$@"
