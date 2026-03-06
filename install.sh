#!/usr/bin/env bash
set -euo pipefail

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

info()  { echo -e "\033[1;34m[*]\033[0m $*"; }
ok()    { echo -e "\033[1;32m[+]\033[0m $*"; }
warn()  { echo -e "\033[1;33m[!]\033[0m $*"; }
die()   { echo -e "\033[1;31m[!]\033[0m $*" >&2; exit 1; }

require_root() {
    [[ $EUID -eq 0 ]] || die "Please run as root: sudo bash install.sh"
}

# ---------------------------------------------------------------------------
# Gather config
# ---------------------------------------------------------------------------

gather_config() {
    echo ""
    echo "  Certificate Transparency Discovery Demo — Installer"
    echo "  ====================================================="
    echo ""

    read -rp "  Domain (e.g. www.example.com): " DOMAIN
    [[ -n "$DOMAIN" ]] || die "Domain cannot be empty."

    read -rp "  Email for Let's Encrypt:        " EMAIL
    [[ -n "$EMAIL" ]] || die "Email cannot be empty."

    # Auto-detect default interface (first non-loopback with an IPv6 global address)
    DEFAULT_IFACE=$(ip -6 addr show scope global | awk '/^[0-9]+:/ {gsub(":",""); print $2}' | head -1)
    read -rp "  Network interface [${DEFAULT_IFACE:-eth0}]:  " IFACE
    IFACE="${IFACE:-${DEFAULT_IFACE:-eth0}}"

    echo ""
    info "Domain:    $DOMAIN"
    info "Email:     $EMAIL"
    info "Interface: $IFACE"
    echo ""
    read -rp "  Proceed? [y/N] " CONFIRM
    [[ "${CONFIRM,,}" == "y" ]] || die "Aborted."
}

# ---------------------------------------------------------------------------
# Detect OS
# ---------------------------------------------------------------------------

detect_os() {
    . /etc/os-release 2>/dev/null || true
    OS_ID="${ID:-unknown}"
    OS_VER="${VERSION_ID:-unknown}"
    info "Detected OS: $OS_ID $OS_VER"

    case "$OS_ID" in
        ubuntu|debian) ;;
        *) die "Unsupported OS '$OS_ID'. This installer targets Ubuntu/Debian." ;;
    esac
}

# ---------------------------------------------------------------------------
# Install packages
# ---------------------------------------------------------------------------

resolve_zeek_bin() {
    # Zeek may land in /usr/bin, /usr/local/bin, or /opt/zeek/bin depending on
    # how it was installed. Find it now (while PATH is intact) and store for use
    # in the generated run.sh, which runs under sudo where PATH may be stripped.
    ZEEK_BIN=$(command -v zeek 2>/dev/null \
        || ls /opt/zeek/bin/zeek /usr/local/bin/zeek 2>/dev/null | head -1 \
        || echo "")
    [[ -n "$ZEEK_BIN" ]] || die "Cannot find zeek binary after installation."
    ok "zeek binary: $ZEEK_BIN"
}

install_zeek() {
    if command -v zeek &>/dev/null; then
        ok "zeek already installed ($(zeek --version 2>&1 | head -1))"
        return
    fi

    info "Adding Zeek apt repository…"
    # Map Ubuntu version to OpenBuildService path
    case "$OS_VER" in
        24.04) ZEEK_REPO="xUbuntu_24.04" ;;
        22.04) ZEEK_REPO="xUbuntu_22.04" ;;
        20.04) ZEEK_REPO="xUbuntu_20.04" ;;
        12)    ZEEK_REPO="Debian_12"     ;;
        11)    ZEEK_REPO="Debian_11"     ;;
        *)     die "No Zeek repo mapping for $OS_ID $OS_VER. Install zeek manually then re-run." ;;
    esac

    ZEEK_BASE="https://download.opensuse.org/repositories/security:/zeek/${ZEEK_REPO}"
    curl -fsSL "${ZEEK_BASE}/Release.key" | gpg --dearmor -o /etc/apt/trusted.gpg.d/zeek.gpg
    echo "deb ${ZEEK_BASE}/ /" > /etc/apt/sources.list.d/zeek.list
    apt-get update -qq
    apt-get install -y zeek
    ok "zeek installed"
}

install_packages() {
    info "Updating apt…"
    apt-get update -qq

    info "Installing nginx, certbot, python3-venv, asciinema…"
    apt-get install -y nginx certbot python3-venv asciinema
    ok "Packages installed"

    install_zeek
    resolve_zeek_bin
}

# ---------------------------------------------------------------------------
# Python venv
# ---------------------------------------------------------------------------

setup_venv() {
    VENV_DIR="$DEMO_DIR/venv"
    if [[ ! -d "$VENV_DIR" ]]; then
        info "Creating Python venv…"
        python3 -m venv "$VENV_DIR"
    fi
    info "Installing Python dependencies…"
    "$VENV_DIR/bin/pip" install --quiet --upgrade pip
    "$VENV_DIR/bin/pip" install --quiet rich
    ok "Python venv ready at $VENV_DIR"
}

# ---------------------------------------------------------------------------
# nginx config
# ---------------------------------------------------------------------------

setup_nginx() {
    NGINX_CONF="/etc/nginx/sites-available/ct-demo"
    info "Writing nginx config for $DOMAIN (HTTP only — HTTPS added after cert issuance)…"

    # Install HTTP-only config so nginx starts cleanly before the cert exists.
    # monitor.py will install the full HTTP+HTTPS config after certbot succeeds.
    cat > "$NGINX_CONF" <<NGINXEOF
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    root /var/www/html;
}
NGINXEOF

    ln -sf "$NGINX_CONF" /etc/nginx/sites-enabled/ct-demo
    rm -f /etc/nginx/sites-enabled/default

    nginx -t || die "nginx config test failed — check $NGINX_CONF"
    systemctl enable nginx
    systemctl restart nginx
    ok "nginx started (HTTP only)"
}

# ---------------------------------------------------------------------------
# demo.conf
# ---------------------------------------------------------------------------

write_demo_conf() {
    CONF="$DEMO_DIR/demo.conf"
    info "Writing $CONF…"
    cat > "$CONF" <<EOF
[demo]
domain        = $DOMAIN
email         = $EMAIL
log_dir       = $DEMO_DIR
nginx_template = $DEMO_DIR/nginx.conf
EOF
    ok "demo.conf written"
}

# ---------------------------------------------------------------------------
# run.sh wrapper
# ---------------------------------------------------------------------------

write_run_script() {
    RUN="$DEMO_DIR/run.sh"
    cat > "$RUN" <<EOF
#!/usr/bin/env bash
# Start Zeek and the monitor together.
# Run as root (Zeek requires it).
set -euo pipefail
DEMO_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
cd "\$DEMO_DIR"
echo "Starting Zeek on interface $IFACE…"
$ZEEK_BIN -i $IFACE -C &
ZEEK_PID=\$!
sleep 2
echo "Starting monitor…"
"\$DEMO_DIR/venv/bin/python3" "\$DEMO_DIR/monitor.py"
kill \$ZEEK_PID 2>/dev/null || true
EOF
    chmod +x "$RUN"
    ok "run.sh written"
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

print_summary() {
    echo ""
    ok "Installation complete."
    echo ""
    echo "  To run the demo:"
    echo ""
    echo "    sudo bash $DEMO_DIR/run.sh"
    echo ""
    echo "  Or step by step:"
    echo ""
    echo "    sudo zeek -i $IFACE -C &"
    echo "    $DEMO_DIR/venv/bin/python3 $DEMO_DIR/monitor.py"
    echo ""
    echo "  To record with asciinema:"
    echo ""
    echo "    asciinema rec ct-demo.cast --command 'sudo bash $DEMO_DIR/run.sh'"
    echo ""
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

require_root
detect_os
gather_config
install_packages
setup_venv
setup_nginx
write_demo_conf
write_run_script
print_summary
