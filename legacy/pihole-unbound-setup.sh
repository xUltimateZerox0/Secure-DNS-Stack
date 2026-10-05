#!/bin/bash
# ============================================================
# Pi-hole + Unbound DoT Setup Script for Debian
# Version: 3.0.0
# ------------------------------------------------------------
# Configures Pi-hole (adblock/tracker/malware filtering) +
# Unbound forwarding DNS-over-TLS to Quad9/Cloudflare.
#
# Tests each step before proceeding to the next.
# Safe to re-run: idempotent where possible.
# Designed for Debian minimal headless installations.
# ============================================================

set -euo pipefail

# ---- Version ----
SCRIPT_VERSION="3.0.0"

# ---- Configuration defaults ----
UNBOUND_PORT="5335"
OISD_BIG_URL="https://big.oisd.nl"
PIHOLE_UPSTREAM="127.0.0.1#${UNBOUND_PORT}"

# ---- Colors ----
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

# ---- Global state ----
DETECTED_IFACE=""
DETECTED_GATEWAY=""
DETECTED_CURRENT_IP=""
DETECTED_CIDR=""
DETECTED_NETWORK_SYSTEM=""
STATIC_IP=""
STATIC_CIDR=""
STATIC_GATEWAY=""
PIHOLE_VERSION=""

# ============================================================
# Helper Functions
# ============================================================

log_info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*" >&2; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_step()  { echo ""; echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; echo -e "${BOLD}  $*${NC}"; echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }

die() {
    log_error "$*"
    exit 1
}

confirm_or_exit() {
    local prompt="${1:-Continue?}"
    echo -en "${YELLOW}${prompt} [Y/n]${NC} "
    local answer
    if read -r answer </dev/tty 2>/dev/null; then
        :
    else
        read -r answer
    fi
    case "${answer:-Y}" in
        y|Y|yes|YES|"") return 0 ;;
        *) die "Aborted by user." ;;
    esac
}

require_root() {
    if [[ $EUID -ne 0 ]]; then
        die "This script must be run as root (sudo)."
    fi
}

detect_pihole_version() {
    if command -v pihole-FTL >/dev/null 2>&1; then
        PIHOLE_VERSION="6"
    elif command -v pihole >/dev/null 2>&1; then
        PIHOLE_VERSION="5"
    else
        PIHOLE_VERSION=""
    fi
}

random_string() {
    local len="${1:-16}"
    tr -dc 'A-Za-z0-9' < /dev/urandom | head -c "$len"
}

backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        local backup="${file}.backup.$(date +%Y%m%d-%H%M%S)"
        cp "$file" "$backup"
        log_info "Backed up $file -> $backup"
    fi
}

validate_ip() {
    local ip="$1"
    local octets
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -r -a octets <<< "$ip"
        for octet in "${octets[@]}"; do
            if [[ "$octet" -gt 255 ]]; then
                return 1
            fi
        done
        return 0
    fi
    return 1
}

check_command() {
    command -v "$1" >/dev/null 2>&1
}

install_packages() {
    local missing=()
    local pkg
    for pkg in "$@"; do
        if ! dpkg -s "$pkg" >/dev/null 2>&1; then
            missing+=("$pkg")
        elif dpkg -s "$pkg" 2>/dev/null | grep -q "Status: deinstall"; then
            missing+=("$pkg")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_info "Installing: ${missing[*]}"
        DEBIAN_FRONTEND=noninteractive apt install -y "${missing[@]}" || \
            die "Failed to install: ${missing[*]}"
        log_ok "Installed: ${missing[*]}"
    fi
}

# ============================================================
# 1. PRE-FLIGHT CHECKS
# ============================================================

preflight_checks() {
    log_step "Step 1: Pre-flight checks"

    require_root
    log_ok "Running as root"

    # Systemd check
    if pidof systemd >/dev/null 2>&1; then
        log_ok "Init system: systemd"
    else
        die "This script requires systemd."
    fi

    # Update package lists before anything
    DEBIAN_FRONTEND=noninteractive apt update -qq || \
        die "apt update failed. Check internet connection."

    # Install ALL essential packages upfront (before any tool is used)
    install_packages \
        dnsutils \
        curl \
        sqlite3 \
        tcpdump \
        nftables \
        whiptail \
        ca-certificates \
        coreutils \
        systemd

    log_ok "Essential packages installed"

    # OS check
    local OS_ID=""
    if [[ -f /etc/os-release ]]; then
        OS_ID=$(. /etc/os-release && echo "${ID:-}")
    fi
    if [[ "${OS_ID}" != "debian" ]]; then
        die "This script is designed for Debian. Detected: ${OS_ID:-unknown}"
    fi
    log_ok "OS: Debian"

    # Internet connectivity
    if ! ping -c 2 -W 3 1.1.1.1 >/dev/null 2>&1; then
        if ! curl -s -o /dev/null --connect-timeout 5 http://1.1.1.1; then
            die "No internet connectivity."
        fi
    fi
    log_ok "Internet connectivity: OK"

    # DNS resolution
    if ! dig +short google.com @1.1.1.1 >/dev/null 2>&1; then
        if ! host google.com 1.1.1.1 >/dev/null 2>&1; then
            die "DNS resolution not working."
        fi
    fi
    log_ok "DNS resolution: OK"

    # Check existing installations
    detect_pihole_version
    if [[ -n "${PIHOLE_VERSION}" ]]; then
        log_warn "Pi-hole v${PIHOLE_VERSION} already installed."
        confirm_or_exit "Reconfigure existing Pi-hole installation?"
    fi

    if systemctl is-active --quiet unbound 2>/dev/null; then
        log_warn "Unbound already running."
        confirm_or_exit "Reconfigure existing Unbound installation?"
    fi

    # Warn about SSH if restarting network
    if [[ -n "${SSH_CONNECTION:-}" ]]; then
        log_warn "Running over SSH. Network restart may disconnect you!"
        log_info "If the script loses connectivity, reconnect to the configured IP."
        confirm_or_exit "Continue over SSH?"
    fi

    log_ok "Pre-flight checks passed"
}

# ============================================================
# 2. NETWORK DETECTION & STATIC IP
# ============================================================

detect_network() {
    log_step "Step 2a: Network detection"

    local route_line
    route_line=$(ip route get 1.1.1.1 2>/dev/null || true)
    DETECTED_IFACE=$(echo "${route_line}" | awk '{print $5; exit}')

    if [[ -z "${DETECTED_IFACE}" ]]; then
        # Fallback: pick first non-loopback interface
        DETECTED_IFACE=$(ip -4 route show default | awk '{print $5; exit}')
    fi
    if [[ -z "${DETECTED_IFACE}" ]]; then
        die "Could not detect default network interface."
    fi
    log_ok "Default interface: ${DETECTED_IFACE}"

    # Gateway detection
    if echo "${route_line}" | grep -q "via"; then
        DETECTED_GATEWAY=$(echo "${route_line}" | awk '{print $3}')
    else
        local base
        base=$(ip -4 addr show "${DETECTED_IFACE}" 2>/dev/null | awk '/inet / {print $2}' | cut -d/ -f1 | cut -d. -f1-3 || true)
        DETECTED_GATEWAY="${base}.1"
        log_warn "No gateway detected. Assuming ${DETECTED_GATEWAY}"
    fi

    DETECTED_CURRENT_IP=$(ip -4 addr show "${DETECTED_IFACE}" 2>/dev/null | awk '/inet / {print $2}' | cut -d/ -f1 || true)
    DETECTED_CIDR=$(ip -4 addr show "${DETECTED_IFACE}" 2>/dev/null | awk '/inet / {print $2}' | cut -d/ -f2 || true)

    if [[ -z "${DETECTED_CURRENT_IP}" ]]; then
        die "Could not detect current IP on ${DETECTED_IFACE}."
    fi
    log_ok "Current IP: ${DETECTED_CURRENT_IP}/${DETECTED_CIDR:-24}"

    # Detect networking system
    if ls /etc/netplan/*.yaml >/dev/null 2>&1; then
        DETECTED_NETWORK_SYSTEM="netplan"
    elif [[ -f /etc/network/interfaces ]] && check_command ifup; then
        DETECTED_NETWORK_SYSTEM="ifupdown"
    elif systemctl is-active --quiet systemd-networkd 2>/dev/null; then
        DETECTED_NETWORK_SYSTEM="systemd-networkd"
    elif systemctl is-active --quiet NetworkManager 2>/dev/null; then
        DETECTED_NETWORK_SYSTEM="networkmanager"
    else
        die "Could not detect networking system."
    fi
    log_ok "Networking system: ${DETECTED_NETWORK_SYSTEM}"

    echo ""
    echo "  Interface  : ${DETECTED_IFACE}"
    echo "  Current IP : ${DETECTED_CURRENT_IP}/${DETECTED_CIDR:-24}"
    echo "  Gateway    : ${DETECTED_GATEWAY}"
    echo "  System     : ${DETECTED_NETWORK_SYSTEM}"
    echo ""
}

configure_static_ip() {
    log_step "Step 2b: Static IP configuration"

    local subnet_base
    subnet_base=$(echo "${DETECTED_CURRENT_IP}" | cut -d. -f1-3)
    local suggested_ip="${subnet_base}.2"

    echo -en "Enter desired static IP for the server [${suggested_ip}]: "
    local input_ip=""
    if read -r input_ip </dev/tty 2>/dev/null; then :; else read -r input_ip; fi
    STATIC_IP="${input_ip:-${suggested_ip}}"

    if ! validate_ip "${STATIC_IP}"; then
        die "Invalid IP address: ${STATIC_IP}"
    fi

    echo -en "Enter CIDR prefix length [${DETECTED_CIDR:-24}]: "
    local input_cidr=""
    if read -r input_cidr </dev/tty 2>/dev/null; then :; else read -r input_cidr; fi
    STATIC_CIDR="${input_cidr:-${DETECTED_CIDR:-24}}"

    echo -en "Enter gateway IP [${DETECTED_GATEWAY}]: "
    local input_gw=""
    if read -r input_gw </dev/tty 2>/dev/null; then :; else read -r input_gw; fi
    STATIC_GATEWAY="${input_gw:-${DETECTED_GATEWAY}}"

    if ! validate_ip "${STATIC_GATEWAY}"; then
        die "Invalid gateway IP: ${STATIC_GATEWAY}"
    fi
    if [[ "${STATIC_IP}" == "${STATIC_GATEWAY}" ]]; then
        die "Static IP cannot be same as gateway: ${STATIC_IP}"
    fi

    echo ""
    echo "  Static IP : ${STATIC_IP}/${STATIC_CIDR}"
    echo "  Gateway   : ${STATIC_GATEWAY}"
    echo ""
    confirm_or_exit "Apply this static IP configuration?"

    # Backups
    if [[ "${DETECTED_NETWORK_SYSTEM}" == "ifupdown" ]]; then
        backup_file "/etc/network/interfaces"
    fi
    for f in /etc/netplan/*.yaml; do
        [[ -f "$f" ]] && backup_file "$f"
    done

    case "${DETECTED_NETWORK_SYSTEM}" in
        ifupdown)         configure_static_ip_ifupdown ;;
        netplan)          configure_static_ip_netplan ;;
        systemd-networkd) configure_static_ip_systemd_networkd ;;
        networkmanager)   configure_static_ip_nmcli ;;
    esac

    sleep 3

    if ! ping -c 2 -W 5 1.1.1.1 >/dev/null 2>&1; then
        log_warn "Internet connectivity lost after static IP change."
        confirm_or_exit "Continue anyway?"
    fi
    log_ok "Internet connectivity verified"
}

configure_static_ip_ifupdown() {
    local iface_file="/etc/network/interfaces"

    # Remove any existing block between markers
    sed -i '/# --- BEGIN PI-HOLE SETUP ---/,/# --- END PI-HOLE SETUP ---/d' "${iface_file}" 2>/dev/null || true
    # Remove plain auto/iface dhcp blocks for this interface
    sed -i "/^auto ${DETECTED_IFACE}$/,/^$/d" "${iface_file}" 2>/dev/null || true
    sed -i "/^iface ${DETECTED_IFACE} inet dhcp/d" "${iface_file}" 2>/dev/null || true
    sed -i "/^iface ${DETECTED_IFACE} inet manual/d" "${iface_file}" 2>/dev/null || true

    cat >> "${iface_file}" << EOF

# --- BEGIN PI-HOLE SETUP ---
auto ${DETECTED_IFACE}
iface ${DETECTED_IFACE} inet static
    address ${STATIC_IP}/${STATIC_CIDR}
    gateway ${STATIC_GATEWAY}
# --- END PI-HOLE SETUP ---
EOF

    # Apply network config. On SSH, this might drop the connection.
    if systemctl restart networking.service 2>/dev/null; then
        log_ok "ifupdown configured."
    else
        log_warn "networking.service restart returned non-zero."
        log_info "If SSH dropped, reconnect to ${STATIC_IP} and re-run the script."
        sleep 3
    fi
}

configure_static_ip_netplan() {
    local netplan_file
    netplan_file=$(ls /etc/netplan/*.yaml 2>/dev/null | head -1 || true)
    if [[ -z "${netplan_file}" ]]; then
        netplan_file="/etc/netplan/01-netcfg.yaml"
    fi

    cat > "${netplan_file}" << EOF
# Static IP configured by pihole-unbound-setup.sh
network:
  version: 2
  renderer: networkd
  ethernets:
    ${DETECTED_IFACE}:
      dhcp4: false
      addresses:
        - ${STATIC_IP}/${STATIC_CIDR}
      routes:
        - to: default
          via: ${STATIC_GATEWAY}
      nameservers:
        addresses: [127.0.0.1]
EOF

    netplan apply 2>&1 || die "netplan apply failed."
    log_ok "Netplan configured."
}

configure_static_ip_systemd_networkd() {
    local net_file="/etc/systemd/network/10-${DETECTED_IFACE}.network"

    cat > "${net_file}" << EOF
# Static IP configured by pihole-unbound-setup.sh
[Match]
Name=${DETECTED_IFACE}

[Network]
Address=${STATIC_IP}/${STATIC_CIDR}
Gateway=${STATIC_GATEWAY}
DNS=127.0.0.1
EOF

    systemctl restart systemd-networkd || die "systemd-networkd restart failed"
    log_ok "systemd-networkd configured."
}

configure_static_ip_nmcli() {
    local conn_name
    conn_name=$(nmcli -t -f NAME,DEVICE con show --active 2>/dev/null | grep ":${DETECTED_IFACE}$" | cut -d: -f1 | head -1 || true)
    if [[ -z "${conn_name}" ]]; then
        conn_name="Wired connection 1"
    fi

    nmcli con mod "${conn_name}" ipv4.addresses "${STATIC_IP}/${STATIC_CIDR}"
    nmcli con mod "${conn_name}" ipv4.gateway "${STATIC_GATEWAY}"
    nmcli con mod "${conn_name}" ipv4.dns "127.0.0.1"
    nmcli con mod "${conn_name}" ipv4.method manual
    nmcli con down "${conn_name}" && nmcli con up "${conn_name}" || die "nmcli failed."
    log_ok "NetworkManager configured."
}

test_network_static() {
    log_step "Step 2c: Verifying static IP"

    local current_ip
    current_ip=$(ip -4 addr show "${DETECTED_IFACE}" 2>/dev/null | awk '/inet / {print $2; exit}' || true)

    if echo "${current_ip}" | grep -q "^${STATIC_IP}"; then
        log_ok "IP correctly set to ${current_ip}"
    else
        log_warn "Expected ${STATIC_IP}/${STATIC_CIDR}, got: ${current_ip}"
        confirm_or_exit "IP mismatch - continue?"
    fi
    log_ok "Network verification passed"
}

# ============================================================
# 3. SYSTEM PREPARATION
# ============================================================

prepare_system() {
    log_step "Step 3: System preparation"

    # Disable systemd-resolved FIRST
    disable_systemd_resolved

    # Fix /etc/resolv.conf - replace dangling symlink with real file
    fix_resolv_conf

    # Disable unbound-resolvconf
    disable_unbound_resolvconf
}

disable_systemd_resolved() {
    log_info "Checking systemd-resolved..."

    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        log_info "Disabling systemd-resolved stub listener..."

        if [[ -f /etc/systemd/resolved.conf ]]; then
            backup_file "/etc/systemd/resolved.conf"
            if grep -q "^DNSStubListener=" /etc/systemd/resolved.conf; then
                sed -i 's/^DNSStubListener=.*/DNSStubListener=no/' /etc/systemd/resolved.conf
            elif grep -q "^#DNSStubListener=" /etc/systemd/resolved.conf; then
                sed -i 's/^#DNSStubListener=.*/DNSStubListener=no/' /etc/systemd/resolved.conf
            else
                echo "DNSStubListener=no" >> /etc/systemd/resolved.conf
            fi
        fi

        systemctl restart systemd-resolved 2>/dev/null || true
        sleep 2
    fi

    # Force-disable if still on port 53
    if ss -tulpn 2>/dev/null | grep -q "127.0.0.53:53"; then
        log_warn "systemd-resolved still on :53. Force-disabling..."
        systemctl disable --now systemd-resolved 2>/dev/null || true
        sleep 2
    fi

    # Check port 53
    local p53
    p53=$(ss -tulpn 2>/dev/null | grep ":53 " || true)
    if [[ -n "${p53}" ]]; then
        log_warn "Port 53 still in use: ${p53}"
        confirm_or_exit "Port 53 occupied - continue? (Pi-hole needs it)"
    else
        log_ok "Port 53 is free"
    fi
}

fix_resolv_conf() {
    # systemd-resolved leaves a dangling symlink when disabled
    if [[ -L /etc/resolv.conf ]]; then
        local target
        target=$(readlink /etc/resolv.conf 2>/dev/null || true)
        log_info "Removing dangling resolv.conf symlink -> ${target}"
        rm -f /etc/resolv.conf
    fi

    # Ensure resolv.conf has a working nameserver
    if ! grep -q "nameserver" /etc/resolv.conf 2>/dev/null; then
        echo "nameserver 1.1.1.1" > /etc/resolv.conf
        chmod 644 /etc/resolv.conf
        log_ok "Stub DNS set: 1.1.1.1"
    fi
}

disable_unbound_resolvconf() {
    if systemctl is-active --quiet unbound-resolvconf.service 2>/dev/null; then
        systemctl disable --now unbound-resolvconf.service 2>/dev/null || true
        log_ok "unbound-resolvconf.service disabled"
    fi

    if systemctl is-active --quiet resolvconf.service 2>/dev/null; then
        systemctl disable --now resolvconf.service 2>/dev/null || true
        log_ok "resolvconf.service disabled"
    fi

    if [[ -f /etc/unbound/unbound.conf.d/resolvconf_resolvers.conf ]]; then
        rm -f /etc/unbound/unbound.conf.d/resolvconf_resolvers.conf
        log_ok "Removed resolvconf_resolvers.conf"
    fi

    if [[ -f /etc/resolvconf.conf ]]; then
        backup_file "/etc/resolvconf.conf"
        sed -i 's/^unbound_conf=.*/# unbound_conf=disabled-by-pihole-setup/' /etc/resolvconf.conf 2>/dev/null || true
    fi
}

# ============================================================
# 4. INSTALL & CONFIGURE UNBOUND
# ============================================================

install_unbound() {
    log_step "Step 4: Install Unbound"

    install_packages unbound dns-root-data

    configure_unbound
}

configure_unbound() {
    log_info "Configuring Unbound for DoT forwarding..."

    local conf_dir="/etc/unbound/unbound.conf.d"
    mkdir -p "${conf_dir}"
    rm -f "${conf_dir}/resolvconf_resolvers.conf"

    cat > "${conf_dir}/pi-hole.conf" << 'UBEOF'
server:
    interface: 127.0.0.1
    port: 5335
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes
    tls-cert-bundle: /etc/ssl/certs/ca-certificates.crt

    # Performance
    prefetch: yes
    prefetch-key: yes
    num-threads: 2
    msg-cache-size: 128m
    rrset-cache-size: 256m
    cache-min-ttl: 3600
    cache-max-ttl: 86400
    so-rcvbuf: 1m

    # Privacy
    hide-identity: yes
    hide-version: yes
    harden-glue: yes
    harden-dnssec-stripped: yes
    do-not-query-localhost: no

forward-zone:
    name: "."
    forward-tls-upstream: yes
    forward-addr: 9.9.9.9@853#dns.quad9.net
    forward-addr: 149.112.112.112@853#dns.quad9.net
    forward-addr: 1.1.1.1@853#cloudflare-dns.com
    forward-addr: 1.0.0.1@853#cloudflare-dns.com
UBEOF

    chown -R root:root "${conf_dir}"
    chmod 644 "${conf_dir}/pi-hole.conf"

    systemctl enable unbound 2>/dev/null || true
    systemctl restart unbound 2>&1 || {
        log_error "Unbound failed to start. Checking logs..."
        journalctl -u unbound --no-pager -n 40 || true
        if aa-status 2>/dev/null | grep -q "unbound.*enforce"; then
            log_warn "AppArmor may be blocking Unbound. Check: sudo aa-status | grep unbound"
        fi
        die "Unbound failed to start."
    }

    sleep 2
    if ! systemctl is-active --quiet unbound; then
        log_error "Unbound not running after restart."
        journalctl -u unbound --no-pager -n 30 || true
        die "Unbound not running."
    fi
    log_ok "Unbound is running"
}

# ============================================================
# 5. TEST UNBOUND
# ============================================================

test_unbound() {
    log_step "Step 5: Test Unbound DoT resolution"

    # 5.1 Basic resolution
    log_info "5.1 Basic resolution test..."
    local result
    result=$(dig +short "@127.0.0.1" -p "${UNBOUND_PORT}" google.com 2>&1 || true)
    if [[ -z "${result}" ]]; then
        result=$(dig +tcp +short "@127.0.0.1" -p "${UNBOUND_PORT}" google.com 2>&1 || true)
    fi
    if [[ -z "${result}" ]]; then
        die "Unbound resolution test failed."
    fi
    log_ok "Unbound resolves google.com -> ${result}"

    # 5.2 DoT traffic verification
    log_info "5.2 Verifying DoT traffic (TLS on port 853)..."
    log_info "Generating uncached queries..."

    for i in 1 2 3 4 5; do
        dig +short "@127.0.0.1" -p "${UNBOUND_PORT}" \
            "uncached-${i}-$(date +%s%N).example.com" >/dev/null 2>&1 || true
        sleep 0.5
    done

    local dot_capture="/tmp/dot-test-$(date +%s).pcap"
    timeout 12 tcpdump -i "${DETECTED_IFACE}" -nn 'tcp dst port 853' -c 3 \
        -w "${dot_capture}" 2>/dev/null &
    local tcpdump_pid=$!

    sleep 2
    for i in 1 2 3; do
        dig +short "@127.0.0.1" -p "${UNBOUND_PORT}" \
            "capture-${i}-$(date +%s%N).org" >/dev/null 2>&1 || true
        sleep 1
    done

    wait "${tcpdump_pid}" 2>/dev/null || true

    local dot_found=0
    if [[ -f "${dot_capture}" ]]; then
        dot_found=$(tcpdump -nn -r "${dot_capture}" 2>/dev/null | wc -l || true)
    fi

    if [[ "${dot_found}" -ge 1 ]]; then
        log_ok "DoT confirmed: ${dot_found} packet(s) to port 853"
    else
        log_warn "No DoT packets captured. Trying direct check..."
        timeout 6 tcpdump -i "${DETECTED_IFACE}" -nn 'tcp dst port 853' -c 1 -v 2>&1 &
        local tpid=$!
        sleep 1
        dig +short "@127.0.0.1" -p "${UNBOUND_PORT}" \
            "forced-miss-$(date +%s%N).com" >/dev/null 2>&1 || true
        wait "${tpid}" 2>/dev/null || true
    fi

    rm -f "${dot_capture}"
    echo ""
    log_info "Expected: outbound TLS to 9.9.9.9:853, 1.1.1.1:853"
    confirm_or_exit "Does the above show TLS on port 853? (If unsure, answer Y)"
    log_ok "Unbound DoT verification complete"
}

# ============================================================
# 6. INSTALL PI-HOLE
# ============================================================

install_pihole() {
    log_step "Step 6: Install Pi-hole"

    detect_pihole_version
    if [[ -n "${PIHOLE_VERSION}" ]]; then
        log_ok "Pi-hole v${PIHOLE_VERSION} already installed"
        return
    fi

    # Pre-create setupVars.conf for unattended install
    mkdir -p /etc/pihole
    cat > /etc/pihole/setupVars.conf << 'SETUPVAR'
PIHOLE_INTERFACE=eth0
IPV4_ADDRESS=PLACEHOLDER
IPV6_ADDRESS=
PIHOLE_DNS_1=1.1.1.1
PIHOLE_DNS_2=1.0.0.1
QUERY_LOGGING=true
INSTALL_WEB_SERVER=true
INSTALL_WEB_INTERFACE=true
LIGHTTPD_ENABLED=true
BLOCKING_ENABLED=true
DNSSEC=false
CONDITIONAL_FORWARDING=false
ADMIN_EMAIL=
WEBTHEME=default
CACHE_SIZE=10000
SETUPVAR

    # Fix interface name and IP address in setupVars
    sed -i "s/PIHOLE_INTERFACE=eth0/PIHOLE_INTERFACE=${DETECTED_IFACE}/" /etc/pihole/setupVars.conf
    sed -i "s/IPV4_ADDRESS=PLACEHOLDER/IPV4_ADDRESS=${STATIC_IP}\/${STATIC_CIDR}/" /etc/pihole/setupVars.conf

    log_info "Pi-hole installer ready (unattended mode)."
    echo ""
    confirm_or_exit "Proceed with Pi-hole installation?"

    log_info "Downloading and running Pi-hole installer..."
    # Retry loop for network glitches
    local max_attempts=3
    local attempt=0
    while [[ $attempt -lt $max_attempts ]]; do
        attempt=$((attempt + 1))
        if curl -sSL https://install.pi-hole.net | bash /dev/stdin --unattended; then
            break
        fi
        detect_pihole_version
        if [[ -n "${PIHOLE_VERSION}" ]]; then
            break
        fi
        if [[ $attempt -lt $max_attempts ]]; then
            log_warn "Attempt $attempt/$max_attempts failed. Retrying in 5s..."
            sleep 5
        fi
    done

    detect_pihole_version
    if [[ -z "${PIHOLE_VERSION}" ]]; then
        log_error "Pi-hole installation failed after $max_attempts attempts."
        log_info "Common issues:"
        log_info "  - Port 53 occupied:  ss -tulpn | grep :53"
        log_info "  - Missing deps:      apt install -f"
        log_info "  - Network: check /etc/resolv.conf"
        die "Installation failed."
    fi
    log_ok "Pi-hole v${PIHOLE_VERSION} installed"

    # Configure upstream DNS to Unbound
    configure_pihole_upstream
}

configure_pihole_upstream() {
    log_info "Setting Pi-hole upstream DNS -> ${PIHOLE_UPSTREAM}..."

    if [[ "${PIHOLE_VERSION}" == "6" ]] && check_command pihole-FTL; then
        if pihole-FTL --config dns.upstreams "${PIHOLE_UPSTREAM}" 2>&1; then
            log_ok "Upstream DNS configured via pihole-FTL"
            systemctl restart pihole-FTL 2>/dev/null || true
            sleep 2
            return
        fi
        log_warn "pihole-FTL config failed, trying fallback..."
    fi

    # v5 method (also works on some v6)
    sleep 2
    if pihole setdns "${PIHOLE_UPSTREAM}" 2>&1; then
        log_ok "Upstream DNS configured"
    else
        systemctl restart pihole-FTL 2>/dev/null || pihole restartdns 2>/dev/null || true
        sleep 2
        pihole setdns "${PIHOLE_UPSTREAM}" 2>&1 || \
            log_warn "Set manually: Settings > DNS > Custom 127.0.0.1#5335"
    fi

    systemctl restart pihole-FTL 2>/dev/null || pihole restartdns 2>/dev/null || true
    sleep 2

    # Update server's own DNS to use Pi-hole (127.0.0.1)
    if grep -q "^nameserver" /etc/resolv.conf 2>/dev/null; then
        echo "nameserver 127.0.0.1" > /etc/resolv.conf
        log_ok "Server DNS set to 127.0.0.1 (Pi-hole)"
    fi
}

# ============================================================
# 7. CONFIGURE PI-HOLE PASSWORD
# ============================================================

configure_pihole() {
    log_step "Step 7: Configure Pi-hole password"

    echo ""
    echo -e "${YELLOW}Choose a password for Pi-hole web interface (http://${STATIC_IP}/admin/)${NC}"

    local pass1=""
    local pass2=""

    echo -en "Password: "
    if read -s pass1 </dev/tty 2>/dev/null; then :; else read -s pass1; fi
    echo ""

    if [[ -z "${pass1}" ]]; then
        pass1=$(random_string 20)
        echo -e "${YELLOW}[Empty input] Generated: ${pass1}${NC}"
        echo -e "${YELLOW}Save this. Change later: pihole setpassword${NC}"
        confirm_or_exit "Continue with generated password?"
    else
        echo -en "Confirm:   "
        if read -s pass2 </dev/tty 2>/dev/null; then :; else read -s pass2; fi
        echo ""
        if [[ "${pass1}" != "${pass2}" ]]; then
            log_warn "Passwords don't match. Using generated."
            pass1=$(random_string 20)
            echo -e "${YELLOW}Generated: ${pass1}${NC}"
            confirm_or_exit "Continue?"
        fi
    fi

    local admin_pass="${pass1}"

    # Pi-hole v6: pihole setpassword accepts CLI argument
    if pihole setpassword "${admin_pass}" 2>/dev/null; then
        log_ok "Password set via pihole setpassword"
    elif [[ "${PIHOLE_VERSION}" == "6" ]] && check_command pihole-FTL; then
        pihole-FTL --config webserver.api_password "${admin_pass}" 2>&1 && \
            log_ok "Password set via pihole-FTL" || \
            log_warn "FTL password set failed"
        systemctl restart pihole-FTL 2>/dev/null || true
    else
        log_warn "Could not set password automatically."
        log_info "Run manually: pihole setpassword"
        confirm_or_exit "Continue?"
    fi

    # Clear from memory
    admin_pass=""
    pass1=""
    pass2=""

    # Ensure Pi-hole is running
    sleep 2
    if [[ "${PIHOLE_VERSION}" == "6" ]] && systemctl is-active --quiet pihole-FTL 2>/dev/null; then
        log_ok "Pi-hole FTL running"
    elif systemctl is-active --quiet pihole 2>/dev/null; then
        log_ok "Pi-hole (v5) running"
    else
        log_warn "Pi-hole service status unknown."
    fi
}

# ============================================================
# 8. ADD BLOCKLIST AND UPDATE GRAVITY
# ============================================================

add_blocklist() {
    log_step "Step 8: Add OISD blocklist and update gravity"

    local oisd="${OISD_BIG_URL}"
    # Strip trailing slash for consistency
    oisd="${oisd%/}"

    if [[ -f /etc/pihole/gravity.db ]]; then
        log_info "Adding OISD Big to gravity.db..."
        sqlite3 /etc/pihole/gravity.db \
            "INSERT OR IGNORE INTO adlist (address, enabled, comment) \
             VALUES ('${oisd}', 1, 'OISD Big - ads, tracking, malware');" || \
            log_warn "gravity.db insert failed."
    fi

    # v5 fallback
    if [[ -f /etc/pihole/adlists.list ]]; then
        if ! grep -qF "${oisd}" /etc/pihole/adlists.list 2>/dev/null; then
            echo "${oisd}" >> /etc/pihole/adlists.list
            log_ok "Added to adlists.list"
        fi
    fi

    # Update gravity
    log_info "Downloading blocklists (may take a minute)..."
    if pihole -g 2>&1; then
        log_ok "Gravity updated"
    elif pihole updateGravity 2>&1; then
        log_ok "Gravity updated (updateGravity)"
    else
        log_warn "Gravity update had issues."
        confirm_or_exit "Continue?"
    fi
}

# ============================================================
# 9. TEST PI-HOLE
# ============================================================

test_pihole() {
    log_step "Step 9: Test Pi-hole functionality"

    local pihole_ip="${STATIC_IP}"

    # 9.1 Status
    log_info "9.1 Pi-hole status..."
    pihole status 2>&1 | head -3 || true

    # 9.2 DNS resolution
    log_info "9.2 DNS resolution via Pi-hole..."
    local result
    result=$(dig +short "@${pihole_ip}" google.com 2>&1 || true)
    if [[ -z "${result}" ]]; then
        result=$(dig +short "@127.0.0.1" google.com 2>&1 || true)
    fi
    if [[ -n "${result}" ]]; then
        log_ok "Pi-hole resolves google.com -> ${result}"
    else
        log_warn "Pi-hole resolution test failed."
        confirm_or_exit "Continue?"
    fi

    # 9.3 Ad blocking
    log_info "9.3 Ad blocking test..."
    local bt
    bt=$(dig +short "@${pihole_ip}" doubleclick.net 2>&1 || true)
    if echo "${bt}" | grep -qE '^(0\.0\.0\.0|127\.0\.0\.|::)$'; then
        log_ok "doubleclick.net -> ${bt} (BLOCKED)"
    else
        log_warn "doubleclick.net returned: ${bt:-empty}"
        log_info "(blocklist may still be downloading)"
    fi

    # 9.4 Web interface
    log_info "9.4 Web interface check..."
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" "http://${pihole_ip}/admin/" 2>/dev/null || echo "000")
    if [[ "${http_code}" =~ ^[23] ]]; then
        log_ok "Web UI at http://${pihole_ip}/admin/ (HTTP ${http_code})"
    else
        log_warn "Web UI returned HTTP ${http_code}"
    fi

    log_ok "Pi-hole tests complete"
}

# ============================================================
# 10. DNS LEAK PROTECTION (FIREWALL)
# ============================================================

setup_firewall() {
    log_step "Step 10: DNS leak protection"

    if ! check_command nft; then
        log_warn "nftables not available. Skipping firewall."
        return
    fi

    confirm_or_exit "Block cleartext DNS (port 53) leaving the server?"

    systemctl enable nftables 2>/dev/null || true

    # Ensure table and chains exist
    nft add table inet filter 2>/dev/null || true
    nft add chain inet filter input  '{ type filter hook input priority 0; policy accept; }' 2>/dev/null || true
    nft add chain inet filter forward '{ type filter hook forward priority 0; policy accept; }' 2>/dev/null || true
    nft add chain inet filter output '{ type filter hook output priority 0; policy accept; }' 2>/dev/null || true

    # Add drop rules for cleartext DNS (only if not already present)
    local has_udp53
    local has_tcp53
    has_udp53=$(nft -a list chain inet filter output 2>/dev/null | grep "dport 53" | grep "udp" || true)
    has_tcp53=$(nft -a list chain inet filter output 2>/dev/null | grep "dport 53" | grep "tcp" || true)
    if [[ -z "${has_udp53}" ]]; then
        nft add rule inet filter output udp dport 53 ip daddr != 127.0.0.0/8 drop
        log_ok "nftables UDP 53 drop rule added"
    fi
    if [[ -z "${has_tcp53}" ]]; then
        nft add rule inet filter output tcp dport 53 ip daddr != 127.0.0.0/8 drop
        log_ok "nftables TCP 53 drop rule added"
    fi

    # Persist
    nft list ruleset > /etc/nftables.conf 2>/dev/null || true
    if [[ -s /etc/nftables.conf ]]; then
        log_ok "Rules saved to /etc/nftables.conf"
    fi

    log_ok "Firewall configured"
}

test_no_dns_leaks() {
    log_step "Step 10b: Verify no DNS leaks"

    log_info "Monitoring outgoing UDP port 53 for 12 seconds..."

    local leak_capture="/tmp/leak-test-$(date +%s).pcap"
    timeout 14 tcpdump -i "${DETECTED_IFACE}" -nn \
        "udp dst port 53 and not src net 127.0.0.0/8" \
        -w "${leak_capture}" 2>/dev/null &
    local tcpdump_pid=$!

    sleep 2
    # Generate traffic
    for dom in google.com youtube.com facebook.com wikipedia.org reddit.com; do
        dig +short "@${STATIC_IP}" "${dom}" >/dev/null 2>&1 || true
        sleep 0.5
    done
    for i in 1 2 3; do
        dig +short "@${STATIC_IP}" "leak-$(date +%s%N)-${i}.com" >/dev/null 2>&1 || true
        sleep 0.5
    done

    sleep 3
    wait "${tcpdump_pid}" 2>/dev/null || true

    local leak_count=0
    if [[ -f "${leak_capture}" ]]; then
        leak_count=$(tcpdump -nn -r "${leak_capture}" 2>/dev/null | wc -l || true)
    fi

    if [[ "${leak_count}" -eq 0 ]]; then
        log_ok "NO DNS LEAKS - zero outgoing UDP 53 packets"
    else
        log_warn "${leak_count} outgoing UDP 53 packet(s) detected!"
        tcpdump -nn -r "${leak_capture}" 2>/dev/null || true
        log_warn "DNS may be leaking in cleartext."
        confirm_or_exit "Leak detected - continue anyway?"
    fi

    rm -f "${leak_capture}"
    log_ok "DNS leak test complete"
}

# ============================================================
# 11. MAINTENANCE
# ============================================================

setup_maintenance() {
    log_step "Step 11: Maintenance setup"

    local update_script="/usr/local/bin/update-dns-stack.sh"
    cat > "${update_script}" << 'UPSCRIPT'
#!/bin/bash
set -euo pipefail

LOG="/var/log/dns-stack-update.log"

echo "===== DNS Stack Update: $(date) =====" >> "${LOG}"

echo "Updating Pi-hole..." >> "${LOG}"
pihole -up --non-interactive >> "${LOG}" 2>&1 || echo "pihole -up skipped (non-fatal)" >> "${LOG}"

echo "Updating blocklists..." >> "${LOG}"
pihole -g >> "${LOG}" 2>&1 || echo "pihole -g had warnings" >> "${LOG}"

echo "Restarting Unbound..." >> "${LOG}"
systemctl restart unbound >> "${LOG}" 2>&1

echo "Update complete: $(date)" >> "${LOG}"
echo "" >> "${LOG}"

tail -3 "${LOG}"
UPSCRIPT

    chmod +x "${update_script}"
    log_ok "Update script: ${update_script}"

    local cron_line="0 4 * * 1 ${update_script}"
    if ! crontab -l 2>/dev/null | grep -qF "${update_script}"; then
        (crontab -l 2>/dev/null; echo "${cron_line}") | crontab -
        log_ok "Weekly cron: Monday 04:00"
    else
        log_ok "Cron already present"
    fi

    log_info "Crontab:"
    crontab -l 2>/dev/null || echo "(empty)"
}

# ============================================================
# 12. FINAL VERIFICATION
# ============================================================

final_verification() {
    log_step "Step 12: Final verification"

    echo ""
    echo "==============================================="
    echo "  Pi-hole + Unbound DoT - Final Summary"
    echo "==============================================="
    echo ""

    local GREEN="${GREEN}" RED="${RED}" YELLOW="${YELLOW}" NC="${NC}"

    echo -n "Pi-hole      : "
    if systemctl is-active --quiet pihole-FTL 2>/dev/null; then
        echo -e "${GREEN}Running (v6)${NC}"
    elif systemctl is-active --quiet pihole 2>/dev/null; then
        echo -e "${GREEN}Running (v5)${NC}"
    else
        echo -e "${RED}Not running${NC}"
    fi

    echo -n "Unbound      : "
    if systemctl is-active --quiet unbound 2>/dev/null; then
        echo -e "${GREEN}Running${NC}"
    else
        echo -e "${RED}Not running${NC}"
    fi

    echo -n "Port :53     : "
    if ss -tulpn 2>/dev/null | grep -q ':53 '; then
        echo -e "${GREEN}Listening${NC}"
    else
        echo -e "${RED}Not listening${NC}"
    fi

    echo -n "Port :5335   : "
    if ss -tulpn 2>/dev/null | grep -q ':5335 '; then
        echo -e "${GREEN}Listening${NC}"
    else
        echo -e "${RED}Not listening${NC}"
    fi

    echo -n "DNS resolve  : "
    if dig +short @"${STATIC_IP}" google.com >/dev/null 2>&1; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAIL${NC}"
    fi

    echo -n "Ad blocking  : "
    local bt
    bt=$(dig +short @"${STATIC_IP}" doubleclick.net 2>&1 || true)
    if echo "${bt}" | grep -qE '^(0\.0\.0\.0|127\.0\.0\.|::)$'; then
        echo -e "${GREEN}Active${NC}"
    else
        echo -e "${YELLOW}Pending${NC}"
    fi

    echo -n "DoT upstream : "
    if ss -tpn 2>/dev/null | grep -qE \
        '(9\.9\.9\.9)[:.](853|dns)|(1\.1\.1\.1)[:.](853|dns)|(149\.112\.112\.112)[:.](853|dns)|(1\.0\.0\.1)[:.](853|dns)'; then
        echo -e "${GREEN}Connected${NC}"
    else
        echo -e "${YELLOW}Idle (on-demand)${NC}"
    fi

    echo ""
    echo "  Web Interface: http://${STATIC_IP}/admin/"
    echo ""

    confirm_or_exit "Configure router NOW with DNS=${STATIC_IP} (single DNS, no secondary)?"
    log_ok "Router configuration confirmed"
}

# ============================================================
# ROLLBACK INFO
# ============================================================

show_rollback_info() {
    cat << 'ROLLBACK'

===============================================
  Rollback Instructions
===============================================

  1. Restore network config:
     ls -la /etc/network/interfaces.backup.*
     ls -la /etc/netplan/*.yaml.backup.*

  2. Remove Pi-hole:
     pihole uninstall

  3. Remove Unbound:
     apt remove --purge unbound -y

  4. Remove nftables DNS rules:
     nft -a list chain inet filter output
     # Find handle numbers for dport 53 rules, then:
     nft delete rule inet filter output handle <HANDLE>

  5. Restore systemd-resolved:
     sed -i 's/DNSStubListener=no/DNSStubListener=yes/' /etc/systemd/resolved.conf
     systemctl restart systemd-resolved

  6. Remove cron job:
     crontab -e  (remove update-dns-stack.sh)

  7. Remove update script:
     rm /usr/local/bin/update-dns-stack.sh
ROLLBACK
}

# ============================================================
# MAIN
# ============================================================

main() {
    echo ""
    echo "==============================================="
    echo "  Pi-hole + Unbound DoT  v${SCRIPT_VERSION}"
    echo "  Debian Setup"
    echo "==============================================="
    echo ""

    if [[ "${1:-}" == "--rollback-info" ]]; then
        show_rollback_info
        exit 0
    fi

    # Sequential execution with test gates
    preflight_checks
    detect_network
    configure_static_ip
    test_network_static
    prepare_system
    install_unbound
    test_unbound
    install_pihole
    configure_pihole
    add_blocklist
    test_pihole
    setup_firewall
    test_no_dns_leaks
    setup_maintenance
    final_verification
    show_rollback_info

    # Final DNS self-check
    if dig +short google.com @127.0.0.1 >/dev/null 2>&1; then
        log_ok "Server DNS resolution via localhost: OK"
    else
        log_warn "Server DNS via localhost failed. Check /etc/resolv.conf"
        log_info "Expected: nameserver 127.0.0.1"
    fi

    log_ok "All steps completed successfully."
    echo ""
    echo "  Next:"
    echo "  1. Configure router DHCP with single DNS -> ${STATIC_IP}"
    echo "  2. Renew DHCP leases on all devices"
    echo "  3. Browse to http://${STATIC_IP}/admin/"
    echo "  4. Monitor for a few days - cache will warm up"
    echo ""
}

main "$@"
