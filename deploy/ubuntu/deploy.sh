#!/usr/bin/env bash
#
# Deploys the mikrotik-wg-provision server on Ubuntu (22.04/24.04, also fine
# on Debian 12). Run as root from anywhere inside the repo:
#
#   sudo deploy/ubuntu/deploy.sh \
#       --public-url https://provision.example.com \
#       --endpoint-host provision.example.com
#
# What it does:
#   1. Installs Node.js >= 20 (NodeSource) and wireguard-tools if missing
#   2. Builds the provisioning server (npm ci + npm run build)
#   3. Generates the server WireGuard keypair and brings the management
#      tunnel up via wg-quick@<iface> (enabled at boot)
#   4. Generates config.json with random tokens (kept if it already exists)
#   5. Installs a systemd service (mtprov) that starts after the tunnel;
#      the server re-applies all peers on startup so reboots self-heal
#   6. Opens ufw ports if ufw is active
#   7. Health-checks the server and prints the bootstrap one-liner
#
#   sudo deploy/ubuntu/deploy.sh --uninstall
# removes the systemd service and tunnel (config, keys and inventory stay).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

PUBLIC_URL=""
ENDPOINT_HOST=""
HTTP_PORT=8442
WG_PORT=51820
MGMT_CIDR="10.99.0.0/16"
SERVER_TUNNEL_IP="10.99.0.1"
WG_IFACE="wg0"
UNINSTALL=0

usage() {
    sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --public-url)       PUBLIC_URL="$2"; shift 2 ;;
        --endpoint-host)    ENDPOINT_HOST="$2"; shift 2 ;;
        --http-port)        HTTP_PORT="$2"; shift 2 ;;
        --wg-port)          WG_PORT="$2"; shift 2 ;;
        --mgmt-cidr)        MGMT_CIDR="$2"; shift 2 ;;
        --server-tunnel-ip) SERVER_TUNNEL_IP="$2"; shift 2 ;;
        --wg-interface)     WG_IFACE="$2"; shift 2 ;;
        --uninstall)        UNINSTALL=1; shift ;;
        -h|--help)          usage ;;
        *) echo "unknown option: $1" >&2; usage ;;
    esac
done

[[ $EUID -eq 0 ]] || { echo "run as root (sudo)" >&2; exit 1; }

step() { printf '\n\033[36m==> %s\033[0m\n' "$*"; }

SERVICE_FILE="/etc/systemd/system/mtprov.service"
WG_CONF="/etc/wireguard/${WG_IFACE}.conf"
WG_KEY="/etc/wireguard/${WG_IFACE}.key"

# ---------------------------------------------------------------- uninstall
if [[ $UNINSTALL -eq 1 ]]; then
    step "Stopping and removing mtprov service"
    systemctl disable --now mtprov 2>/dev/null || true
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload

    step "Bringing down tunnel ${WG_IFACE}"
    systemctl disable --now "wg-quick@${WG_IFACE}" 2>/dev/null || true

    echo
    echo "Uninstalled. Left in place: $WG_CONF, $WG_KEY, config.json, data/routers.json"
    exit 0
fi

[[ -n "$PUBLIC_URL" && -n "$ENDPOINT_HOST" ]] || { echo "--public-url and --endpoint-host are required" >&2; usage; }

# ------------------------------------------------------------ prerequisites
step "Installing prerequisites"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq wireguard-tools curl ca-certificates openssl >/dev/null

node_ok() { command -v node >/dev/null && [[ "$(node -p 'process.versions.node.split(".")[0]')" -ge 20 ]]; }
if ! node_ok; then
    step "Installing Node.js 22 (NodeSource)"
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash - >/dev/null
    apt-get install -y -qq nodejs >/dev/null
fi
node_ok || { echo "Node.js >= 20 is required but could not be installed" >&2; exit 1; }
echo "node: $(command -v node) ($(node --version))"
echo "wg:   $(command -v wg)"

# ------------------------------------------------------------------- build
step "Building the provisioning server"
cd "$REPO_ROOT"
npm ci
npm run build

# --------------------------------------------------------- WireGuard tunnel
MGMT_PREFIX="${MGMT_CIDR#*/}"

if [[ -f "$WG_CONF" ]]; then
    step "Tunnel config $WG_CONF already exists — keeping it"
    PRIVATE_KEY="$(sed -n 's/^PrivateKey *= *//p' "$WG_CONF" | head -n1)"
    [[ -n "$PRIVATE_KEY" ]] || { echo "could not read PrivateKey from $WG_CONF" >&2; exit 1; }
else
    step "Creating WireGuard management tunnel ${WG_IFACE}"
    mkdir -p /etc/wireguard
    (umask 077 && wg genkey > "$WG_KEY")
    PRIVATE_KEY="$(cat "$WG_KEY")"
    (umask 077 && cat > "$WG_CONF" <<EOF
[Interface]
PrivateKey = ${PRIVATE_KEY}
Address = ${SERVER_TUNNEL_IP}/${MGMT_PREFIX}
ListenPort = ${WG_PORT}
EOF
    )
fi
SERVER_PUBLIC_KEY="$(wg pubkey <<< "$PRIVATE_KEY")"
echo "server public key: $SERVER_PUBLIC_KEY"

systemctl enable --now "wg-quick@${WG_IFACE}" >/dev/null 2>&1 || systemctl restart "wg-quick@${WG_IFACE}"

# ------------------------------------------------------------- config.json
CONFIG_PATH="$REPO_ROOT/config.json"
if [[ -f "$CONFIG_PATH" ]]; then
    step "config.json already exists — keeping it (delete it to regenerate)"
else
    step "Generating config.json"
    # No pipelines here: 'urandom | tr | head' dies of SIGPIPE under pipefail.
    new_token() { openssl rand -hex 20; }
    PROV_TOKEN="$(new_token)"
    ADMIN_TOKEN="$(new_token)"
    (umask 077 && cat > "$CONFIG_PATH" <<EOF
{
  "server": { "host": "0.0.0.0", "port": ${HTTP_PORT}, "publicUrl": "${PUBLIC_URL}" },
  "auth": { "provisioningToken": "${PROV_TOKEN}", "adminToken": "${ADMIN_TOKEN}" },
  "wireguard": {
    "interface": "${WG_IFACE}",
    "serverPublicKey": "${SERVER_PUBLIC_KEY}",
    "endpointHost": "${ENDPOINT_HOST}",
    "endpointPort": ${WG_PORT},
    "mgmtCidr": "${MGMT_CIDR}",
    "serverTunnelIp": "${SERVER_TUNNEL_IP}",
    "persistentKeepalive": 25,
    "applyMode": "wg"
  },
  "router": { "wgInterfaceName": "wg-mgmt", "username": "wg-mgmt", "strictTls": false },
  "storePath": "data/routers.json"
}
EOF
    )
fi

# ---------------------------------------------------------- systemd service
step "Installing systemd service (mtprov)"
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=MikroTik WireGuard auto-provisioning server
After=network-online.target wg-quick@${WG_IFACE}.service
Wants=network-online.target
Requires=wg-quick@${WG_IFACE}.service

[Service]
Type=simple
WorkingDirectory=${REPO_ROOT}
ExecStart=$(command -v node) ${REPO_ROOT}/dist/cli.js serve
Restart=always
RestartSec=5
# needs root to run 'wg set' on ${WG_IFACE}
User=root
NoNewPrivileges=yes
ProtectSystem=full
ReadWritePaths=${REPO_ROOT}

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now mtprov
sleep 2

# ---------------------------------------------------------------- firewall
if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
    step "Opening ufw ports"
    ufw allow "${WG_PORT}/udp" comment "mtprov WireGuard" >/dev/null
    ufw allow "${HTTP_PORT}/tcp" comment "mtprov HTTP" >/dev/null
else
    echo "(ufw not active — make sure UDP ${WG_PORT} and TCP ${HTTP_PORT} are reachable)"
fi

# ------------------------------------------------------------ verification
step "Verifying"
if curl -fsS "http://127.0.0.1:${HTTP_PORT}/healthz" >/dev/null; then
    echo "provisioning server: OK (http://127.0.0.1:${HTTP_PORT})"
else
    echo "WARNING: server did not answer /healthz — check: journalctl -u mtprov -e" >&2
fi
wg show "$WG_IFACE" || true

# ----------------------------------------------------------------- summary
step "Bootstrap one-liner for field techs"
node "$REPO_ROOT/dist/cli.js" bootstrap

cat <<EOF

Deployment complete.
  - Tunnel        : wg-quick@${WG_IFACE}  (${WG_CONF})
  - Server        : systemctl status mtprov   (logs: journalctl -u mtprov -f)
  - Config        : ${CONFIG_PATH}
  - Inventory     : ${REPO_ROOT}/data/routers.json
  - Manage fleet  : node dist/cli.js list | show <serial> | verify <serial> | revoke <serial>

IMPORTANT: put a TLS reverse proxy (nginx/caddy) in front of port ${HTTP_PORT}
so ${PUBLIC_URL} serves HTTPS — the provisioning response contains router
credentials. Example (caddy): ${PUBLIC_URL#https://} { reverse_proxy 127.0.0.1:${HTTP_PORT} }
EOF
