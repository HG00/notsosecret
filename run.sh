#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# Load .env to get DOMAIN
# ---------------------------------------------------------------------------

ENV_FILE="${SCRIPT_DIR}/.env"
if [[ ! -f "${ENV_FILE}" ]]; then
    echo "Error: .env not found. Copy .env.example and fill in your values."
    exit 1
fi

# shellcheck source=/dev/null
source "${ENV_FILE}"

if [[ -z "${DOMAIN:-}" ]]; then
    echo "Error: DOMAIN not set in .env"
    exit 1
fi

# ---------------------------------------------------------------------------
# Fetch public IPs
# ---------------------------------------------------------------------------

IPV4=""
IPV6=""

IPV4=$(curl -4 -s --max-time 3 https://icanhazip.com 2>/dev/null || true)
IPV6=$(curl -6 -s --max-time 3 https://icanhazip.com 2>/dev/null || true)

# ---------------------------------------------------------------------------
# Print setup instructions
# ---------------------------------------------------------------------------

if [[ -n "${IPV4}" || -n "${IPV6}" ]]; then
    echo ""
    echo "  Set the following DNS records before requesting a certificate:"
    echo ""
    [[ -n "${IPV4}" ]] && echo "    A     ${DOMAIN}  →  ${IPV4}"
    [[ -n "${IPV6}" ]] && echo "    AAAA  ${DOMAIN}  →  ${IPV6}"
    echo ""
    echo "  Ensure your firewall / cloud security group allows inbound TCP:"
    echo "    22 (SSH)   80 (HTTP)   443 (HTTPS)"
    echo ""
    read -rp "  Press Enter when DNS is configured (or to skip)… "
    echo ""
fi

# ---------------------------------------------------------------------------
# Start the demo
# ---------------------------------------------------------------------------

cd "${SCRIPT_DIR}"

echo "  Building and starting container…"
docker compose up -d --build

echo "  Attaching (Ctrl+C to stop)…"
echo ""
CID=$(docker compose ps -q demo)
exec docker attach --sig-proxy=true "${CID}"
