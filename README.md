# mikrotik-wg-provision

Zero-touch WireGuard auto-provisioning for MikroTik routers (RouterOS v7).

A factory-fresh router runs one bootstrap command, phones home, and comes up
with a WireGuard management tunnel to your WireGuard server — with a management
user account, a tunnel IP, and SSH/API/REST reachable over the tunnel so you
can talk to it and view its info from then on.

## How it works

```
 MikroTik (fresh)                Provisioning server              WireGuard server
 ────────────────                ───────────────────              ────────────────
 1. tech runs one-liner
 2. bootstrap.rsc creates
    wg-mgmt interface
    (keypair generated
    on the router)
 3. POST /api/register  ───────► allocates tunnel IP
    pubkey + serial              stores router record
                                 registers peer  ───────────────► wg set wg0 peer ...
                       ◄───────  responds with tailored .rsc
 4. imports the .rsc:
    peer + tunnel IP +
    mgmt user + services
    + firewall rule
 5. POST /api/confirm  ───────►  marks router "confirmed"
 6. tunnel is up ◄══════════════════ WireGuard ═════════════════► manage via
                                                                  SSH / API / REST
```

The private key never leaves the router: RouterOS generates the keypair when
the WireGuard interface is created, and only the public key is sent to the
provisioning server.

Everything created on the router carries a `managed: wg-provision` comment, so
re-provisioning is idempotent and never touches config added by hand.

## Requirements

- **Routers**: RouterOS v7 (WireGuard support), internet access at bootstrap time.
- **Server host**: Node.js ≥ 20, a WireGuard interface (e.g. `wg0`) this tool can
  manage with the `wg` command, and a TLS reverse proxy (nginx/caddy) in front of
  the provisioning HTTP server.

## Quick start

```bash
npm install
npm run build

cp config.example.json config.json
# edit config.json — see below

node dist/cli.js serve
```

Set up the WireGuard server interface once (outside this tool), e.g.:

```bash
wg genkey | tee /etc/wireguard/wg0.key | wg pubkey   # -> serverPublicKey for config.json
# wg0.conf: Address = 10.99.0.1/16, ListenPort = 51820, PrivateKey = ...
wg-quick up wg0
```

Then print the one-liner for field techs:

```bash
node dist/cli.js bootstrap
```

which outputs something like:

```
/tool fetch url="https://provision.example.com/bootstrap.rsc?token=..." dst-path=bootstrap.rsc; :delay 2s; /import bootstrap.rsc
```

Paste that into a terminal on a factory-fresh router (Winbox/serial/MAC-telnet)
and the rest is automatic. About 10 seconds later the router is registered,
tunnelled and manageable:

```bash
node dist/cli.js list
node dist/cli.js show <serial|tunnel-ip|id>    # includes generated credentials
node dist/cli.js verify <serial>               # checks handshake + REST over the tunnel
node dist/cli.js revoke <serial>               # removes the peer, blocks re-registration
```

## Web UI

The server also serves a dashboard at `http://<server>:8442/` (same port as
the API). Sign in with `auth.adminToken` from `config.json`. It shows the
fleet with live tunnel status (WireGuard handshake age, auto-refreshing every
15 s), per-router details including management credentials with copy buttons,
Verify (REST check over the tunnel) and Revoke actions, and the bootstrap
one-liner ready to copy for field techs.

The dashboard talks to the admin API below; anything it does you can also
script. If you expose it beyond localhost, put it behind the same HTTPS
reverse proxy as the provisioning endpoints.

## Configuration (`config.json`)

| Key | Meaning |
| --- | --- |
| `server.publicUrl` | URL routers use to reach this server from the field (must be reachable pre-tunnel) |
| `server.host` / `server.port` | Bind address of the provisioning HTTP server (default `0.0.0.0:8442`) |
| `auth.provisioningToken` | Shared secret embedded in the bootstrap script; authorises registration |
| `auth.adminToken` | Bearer token for `GET /api/routers` |
| `wireguard.interface` | WireGuard interface on this host that terminates management tunnels |
| `wireguard.serverPublicKey` | Public key of that interface (routers peer with it) |
| `wireguard.endpointHost` / `endpointPort` | WireGuard endpoint routers connect to |
| `wireguard.mgmtCidr` | Subnet management tunnel IPs are allocated from (e.g. `10.99.0.0/16`) |
| `wireguard.serverTunnelIp` | This server's own IP inside `mgmtCidr` (never allocated) |
| `wireguard.applyMode` | `wg` (apply live) or `dry-run` (log commands only — dev/testing) |
| `router.wgInterfaceName` | Name of the WireGuard interface created on each MikroTik |
| `router.username` | Management user created on each MikroTik (per-router random password) |
| `router.strictTls` | When true, RouterOS verifies the TLS cert of `publicUrl` during bootstrap |
| `storePath` | JSON inventory location (default `data/routers.json`) |

## HTTP API

| Endpoint | Auth | Purpose |
| --- | --- | --- |
| `GET /bootstrap.rsc?token=…` | provisioning token | The generic bootstrap script |
| `POST /api/register` | provisioning token (body) | Router phone-home; responds with a tailored `.rsc` |
| `POST /api/confirm` | provisioning token (body) | Router confirms the config was applied |
| `GET /` | none (UI does client-side auth) | Web dashboard |
| `GET /api/routers` | `Bearer` admin token | Inventory with handshake ages (passwords excluded) |
| `GET /api/routers/:ref` | `Bearer` admin token | Full details incl. credentials (ref = id, serial or tunnel IP) |
| `POST /api/routers/:ref/verify` | `Bearer` admin token | Handshake + REST reachability check; marks `verified` |
| `POST /api/routers/:ref/revoke` | `Bearer` admin token | Remove peer, block re-registration |
| `GET /api/bootstrap-info` | `Bearer` admin token | The tech-facing bootstrap one-liner |
| `GET /healthz` | none | Liveness |

Router lifecycle: `registered → confirmed → verified` (via `verify`), or `revoked`.
A router that re-registers (reset/reflashed) keeps its tunnel IP and credentials;
its new public key replaces the old peer. Revoked serials cannot re-register.

## What gets configured on the router

- `wg-mgmt` WireGuard interface + peer to your server (keepalive 25s)
- Management IP from `mgmtCidr` on the tunnel interface
- Management user (group `full`, strong random per-router password)
- `ssh`, `api` and `www` services enabled — `www` serves the RouterOS REST API,
  which this tool uses over the tunnel (`http://<tunnelIp>/rest/…`)
- One firewall filter rule accepting input from `mgmtCidr`, inserted at the top
  of the input chain

## Security notes

- **Run the provisioning server behind HTTPS.** The register response contains
  the router's management password. RouterOS `fetch` does not verify
  certificates by default; set `router.strictTls: true` once your routers trust
  your CA (`/certificate import`).
- The provisioning token gates registration. Rotate it if a bootstrap script
  leaks; already-provisioned routers are unaffected.
- Management services are reachable from `mgmtCidr` — anything on the
  management VPN can reach every router's SSH/API. Keep the WireGuard server
  host locked down.
- Credentials live in `data/routers.json` on the server host — restrict file
  permissions and back it up encrypted.

## Deploying on Ubuntu

`deploy/ubuntu/deploy.sh` sets up an Ubuntu host (22.04/24.04, Debian 12 also
works) in one shot:

```bash
sudo deploy/ubuntu/deploy.sh \
    --public-url https://provision.example.com \
    --endpoint-host provision.example.com
```

It installs Node.js ≥ 20 (NodeSource) and `wireguard-tools` if missing, builds
the project, generates the server WireGuard keypair, brings the management
tunnel up via `wg-quick@wg0` (enabled at boot), writes `config.json` with
random tokens (an existing one is kept), installs a `mtprov` systemd service
that starts after the tunnel with auto-restart, opens ufw ports if ufw is
active, health-checks the server, and prints the bootstrap one-liner.

Optional flags: `--http-port` (8442), `--wg-port` (51820), `--mgmt-cidr`
(`10.99.0.0/16`), `--server-tunnel-ip` (`10.99.0.1`), `--wg-interface`
(`wg0`). Day-to-day:

```bash
systemctl status mtprov          # server status
journalctl -u mtprov -f          # live logs
node dist/cli.js list            # fleet
sudo deploy/ubuntu/deploy.sh --uninstall   # remove service + tunnel, keep config/inventory
```

On startup (and via `node dist/cli.js sync`) the server re-applies every
non-revoked peer to the interface, so the fleet reconnects after reboots.
Terminate TLS in front of the HTTP port (nginx/caddy) so `--public-url`
serves HTTPS.

## Deploying on Windows

`deploy/windows/deploy.ps1` sets up everything on a Windows host (Windows
10/11 or Server 2019+) in one shot. From an elevated PowerShell prompt in the
repo:

```powershell
powershell -ExecutionPolicy Bypass -File deploy\windows\deploy.ps1 `
    -PublicUrl "https://provision.example.com" `
    -EndpointHost "provision.example.com"
```

It installs Node.js LTS and WireGuard (via winget) if missing, builds the
project, generates the server WireGuard keypair, installs the management
tunnel as a Windows service, writes `config.json` with random tokens (an
existing one is kept), opens firewall ports, registers the provisioning
server as a boot-time Scheduled Task (SYSTEM, auto-restart, logs to
`logs\server.log`), health-checks it, and prints the bootstrap one-liner.

Optional parameters: `-HttpPort` (8442), `-WgPort` (51820), `-MgmtCidr`
(`10.99.0.0/16`), `-ServerTunnelIp` (`10.99.0.1`), `-TunnelName`
(`wg-mgmt-server`). Remove everything (keeping config and inventory) with:

```powershell
powershell -ExecutionPolicy Bypass -File deploy\windows\deploy.ps1 -Uninstall
```

On startup (and via `node dist/cli.js sync`) the server re-applies every
non-revoked peer to the interface, so the fleet reconnects after reboots.

As on Linux, terminate TLS in front of the HTTP port (IIS ARR, nginx, caddy,
or a cloud load balancer) so `PublicUrl` serves HTTPS.

## Development

```bash
npm test            # vitest — ipam, store, templates, HTTP API
npm run typecheck
npm run dev         # tsx, no build step
```

`wireguard.applyMode: "dry-run"` lets you run the whole flow (including a real
router registering!) without touching a live WireGuard interface.
