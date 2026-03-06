#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# Validate required environment variables
# ---------------------------------------------------------------------------

: "${DOMAIN:?Environment variable DOMAIN must be set (e.g. www.example.com)}"
: "${EMAIL:?Environment variable EMAIL must be set (e.g. you@example.com)}"
: "${IFACE:=eth0}"

# ---------------------------------------------------------------------------
# Write demo.conf
# ---------------------------------------------------------------------------

cat > /demo/demo.conf <<EOF
[demo]
domain         = ${DOMAIN}
email          = ${EMAIL}
log_dir        = /demo/logs
nginx_template = /demo/nginx.conf
EOF

mkdir -p /demo/logs

# ---------------------------------------------------------------------------
# Configure nginx (HTTP-only — HTTPS added after cert issuance)
# ---------------------------------------------------------------------------

cat > /etc/nginx/sites-available/ct-demo <<NGINXEOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};
    root /var/www/html;
}
NGINXEOF

ln -sf /etc/nginx/sites-available/ct-demo /etc/nginx/sites-enabled/ct-demo
rm -f /etc/nginx/sites-enabled/default

# ---------------------------------------------------------------------------
# Start nginx
# ---------------------------------------------------------------------------

nginx -t
nginx

# ---------------------------------------------------------------------------
# Start Zeek in the background (cd so logs land in /demo/logs/)
# ---------------------------------------------------------------------------

cd /demo/logs
zeek -i "${IFACE}" -C &
ZEEK_PID=$!

# Wait up to 5s for Zeek to confirm it started (packet_filter.log appears)
for i in $(seq 1 10); do
    sleep 0.5
    if ! kill -0 "${ZEEK_PID}" 2>/dev/null; then
        echo "ERROR: Zeek exited immediately — is IFACE=${IFACE} correct?"
        echo "       Run: ip -4 addr show scope global"
        exit 1
    fi
    if [ -f packet_filter.log ]; then
        break
    fi
done

if ! kill -0 "${ZEEK_PID}" 2>/dev/null; then
    echo "ERROR: Zeek is not running — is IFACE=${IFACE} correct?"
    exit 1
fi

cd /demo

# ---------------------------------------------------------------------------
# Run the monitor as the main process (Ctrl+C propagates correctly)
# ---------------------------------------------------------------------------

exec /demo/venv/bin/python3 /demo/monitor.py
