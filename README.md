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

## Users & roles

The dashboard supports named accounts with two roles:

- **tech** — view the fleet, verify routers, see live stats, view/download backups
- **admin** — everything, plus revoke, bulk commands, tokens, users, restore staging

Manage users entirely from the **Users** tab — add users (with a chosen or
generated password), reset any user's password (ends their sessions), and
remove them. Each person can change their own password from the **My account**
button in the header. `mtprov user add/list/rm` still exists for bootstrapping
the first admin, but the CLI is never required after that. The legacy
`adminToken` also works as a break-glass admin login (username `admin`, token
as the password) and for API scripting. Sessions last `auth.sessionHours`
(default 12) with sliding expiry. Every mutating action is written to an
append-only audit log (`auditPath`, viewable in the Audit tab).

> First login on a fresh install: sign in with username `admin` and your
> `adminToken` as the password, then create your personal account in the
> Users tab. (Creating a user from the CLI while the server is already
> running needs a `systemctl restart mtprov` to be picked up; creating it
> from the dashboard does not.)

## Alerts

Set any of `alerts.webhookUrl`, `alerts.telegramBotToken` +
`alerts.telegramChatId` and the monitor sends a notification when a router
goes offline, comes back (`notifyOnline`), or registers (`notifyOnRegister`).
`suppressMinutes` (default 15) caps a flapping link to one offline + one
online alert per window. The webhook receives
`{text, event, router:{serialNumber,label,tunnelIp}}` — point it at Slack,
Discord, n8n, or your own endpoint.

### Telegram routing (Settings tab)

Beyond the static config above, the **Settings** tab (admin) configures
Telegram interactively: paste a bot token (from @BotFather), click **Verify &
fetch chats** — the server calls `getMe` + `getUpdates` and lists every chat
the bot can reach (add the bot to your group/channel and message it once so it
appears). Then tick, per chat, which notification categories it receives — New
device, Offline, Online, Login, Link — and **Test** sends a message to that
chat. Routing is stored in `settingsPath` (`data/settings.json`) and the
alerter fans each event out to the subscribed chats. This is layered on top of
(not instead of) the config.json webhook/Telegram settings.

## One-time bootstrap tokens

The shared `provisioningToken` lives in every bootstrap script, so a leaked
script can onboard rogue routers indefinitely. One-time tokens close that:
generate one per install from the Tokens tab or `mtprov token "note"`, and it
registers exactly one router before burning. Set
`auth.allowMasterProvisioningToken: false` to refuse the shared token
entirely and require one-time tokens for every onboard.

## Pre-staging

Enter a serial and customer label *before* the router ships
(`mtprov prestage <serial> "label"` or the Fleet tab). When that router phones
home it's automatically matched by serial and keeps the label, so the fleet is
never a wall of anonymous serials.

## Live device stats

The Live button on each router opens a real-time snapshot pulled over the
tunnel via REST: uptime, CPU, memory, interface traffic, and — for LTE/5G
devices like the Chateau — signal metrics (RSRP/RSRQ/SINR, operator, band).
Handy for diagnosing "internet is slow" without a truck roll.

## Bulk commands

Admins can run a RouterOS command across the whole fleet (or a selection)
over SSH from the Bulk actions tab, 5 routers at a time, with per-router
success/output captured. Presets included for identity, resources, DNS,
firmware update check, and reboot.

## Backup diff & restore

The details view diffs any two stored config versions (colourised) and, for
admins, stages a restore: the chosen backup is uploaded to the router as
`wg-restore.rsc` for you to review and `/import` manually — never auto-applied,
because replaying a full export onto a live device needs human eyes. A **Back
up now** button in the same view triggers an immediate `/export` over SSH
(stored only if the config changed) — handy for a snapshot right before you
make a change.

## Status board & device monitoring

The dashboard opens on a **Status board**: a live banner (green "all nominal"
/ amber / red), a list of active issues you can acknowledge or clear, and a
rolling event feed. A badge on the tab shows the open-issue count.

Beyond the WireGuard-handshake up/down tracking, the server actively polls
each monitored device over the tunnel (`deviceMonitor.intervalSeconds`,
default 120 s) and raises:

- **Login events** — someone logging into the router (Winbox / SSH / WebFig /
  API) produces a notification (via your alert channels) and is logged to that
  device's event history and the global feed.
- **Link-down issues** — when a watched port's link drops, an issue opens and
  an alert fires; it auto-clears when the link returns.

Detection is baselined on the first poll (so existing history and current link
state don't fire spurious alerts) and state is stored per device, so it
survives restarts and never double-fires. Provisioned routers get a RouterOS
`account`-topic logging rule so login events are always captured.

### Device types

Each router is classed as **customer** (CPE — watch the uplink + logins, pull
access stats like LTE/5G signal) or **infrastructure** (towers/PoPs/core —
watch every port + logins, pull port traffic). Set it per device in the
details view; it drives the default monitoring profile (infrastructure always
watches link state, since those links are load-bearing) and which live stats
the dashboard emphasises. New routers default to customer with monitoring on.

Per-device monitoring is fully configurable in the details view (admin):
device type, master on/off, alert-on-login, alert-on-link-down, and which
ports to watch (blank = auto: ethernet/SFP/LTE ports up at first poll).

## Live data (streaming)

The dashboard streams live data over Server-Sent Events, so it updates without
you refreshing:

- **Fleet heartbeat** (`GET /api/stream`) — WireGuard handshake age and
  online/offline for every router, pushed every ~3 s to all open dashboards
  from a single shared ticker. The fleet table's up/down dots and handshake
  column tick in near-real-time and the header shows "live".
- **Per-device stats** (`GET /api/routers/:ref/stream`) — while the Live view
  is open, that router's CPU, memory, per-interface **throughput in bits/sec**
  (computed from byte-counter deltas), and LTE/5G signal stream every ~2 s.

Both authenticate via `?token=` (EventSource can't send headers) and reconnect
automatically. If you put the server behind a reverse proxy, make sure it does
not buffer `text/event-stream` — caddy flushes it automatically; for nginx set
`proxy_buffering off` on these routes.

## Fleet monitoring

The server checks every router's WireGuard handshake in the background
(`monitor.intervalSeconds`, default 60 s; offline after
`monitor.offlineAfterSeconds`, default 180 s). Online routers get their
last-seen time updated continuously, and every online↔offline transition is
recorded (bounded history), so flapping links are visible in the dashboard's
details view without anyone clicking Verify.

## Labels & notes

Each router can carry a free-text label (customer, site, address) and notes,
editable in the dashboard details view or via `mtprov label <ref> <text>`.
The dashboard search box filters on label, serial, identity, IP and notes.

## Hardening / base config

Every provisioning script applies opinionated defaults, configurable under
`hardening` in config.json:

- `disableServices` (default `["telnet", "ftp"]`) — services the tool
  depends on (ssh/www/api) are never disabled, even if listed
- `dns` — when set, configures `/ip/dns` servers
- `ntpServers` — when set, enables the NTP client with these servers
- `identityPrefix` — routers still named "MikroTik" get renamed to
  `<prefix>-<serial>`; custom identities are left alone

## Config backups

After provisioning, each router runs a scheduler (`backup.intervalHours`,
default 24 h, plus once at startup) that `/export`s its configuration and
pushes it to `POST /api/backup` — router-initiated, so it works behind NAT
and needs no polling. The server keeps a new version only when the config
actually changed (up to `backup.keep` versions per router, default 30, under
`backup.dir`). Versions are listed and downloadable in the dashboard details
view. Set `backup.enabled: false` to skip the scheduler on newly provisioned
routers.

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
Auth is a **Bearer session token** (from `POST /api/login`) or the legacy
**admin token**. "tech" endpoints accept either role; "admin" endpoints
require the admin role.

| `GET /` | none (UI does client-side auth) | Web dashboard |
| `POST /api/login` | none | Exchange username/password for a session token |
| `POST /api/logout` / `GET /api/me` | tech | End session / current identity |
| `POST /api/account/password` | tech | Change your own password |
| `POST /api/users/:username/password` | admin | Reset a user's password |
| `GET /api/routers` | tech | Inventory with handshake ages + online flag |
| `GET /api/routers/:ref` | tech | Full details incl. credentials (ref = id, serial or tunnel IP) |
| `POST /api/routers/:ref/verify` | tech | Handshake + REST reachability check; marks `verified` |
| `GET /api/routers/:ref/live` | tech | Live stats over the tunnel (system, interfaces, LTE) |
| `PATCH /api/routers/:ref` | tech | Set `label` / `notes` |
| `GET /api/routers/:ref/backups` / `…/:name` | tech | List / download backup versions |
| `POST /api/routers/:ref/backup-now` | tech | Trigger an immediate `/export` backup over SSH |
| `GET /api/routers/:ref/backups-diff?a&b` | tech | Diff two backup versions |
| `POST /api/routers/:ref/revoke` | admin | Remove peer, block re-registration |
| `POST /api/routers/:ref/restore` | admin | Upload a backup to the router as `wg-restore.rsc` |
| `POST /api/prestage` | admin | Create a staged record by serial |
| `POST /api/bulk` | admin | Run a command on many routers over SSH |
| `GET/POST/DELETE /api/tokens` | admin | Manage one-time bootstrap tokens |
| `GET/POST/DELETE /api/users` | admin | Manage dashboard users |
| `GET /api/audit` | admin | Recent audit entries |
| `GET/POST /api/settings/telegram*` | admin | Telegram token, verify/fetch chats, routing, test |
| `GET /api/routers/:ref/interfaces` | tech | Router ports for the faceplate diagram |
| `GET /api/stream` | token in query | SSE: live fleet handshake/online heartbeat |
| `GET /api/routers/:ref/stream` | token in query | SSE: live per-device CPU/mem/traffic/LTE |
| `GET /api/issues` | tech | Active issues + counts (status board) |
| `POST /api/issues/:id/ack` / `…/resolve` | tech | Acknowledge / clear an issue |
| `GET /api/events` / `/api/routers/:ref/events` | tech | Global / per-device event feed |
| `PATCH /api/routers/:ref/monitoring` | admin | Set device type + monitoring rules |
| `GET /api/bootstrap-info` | tech | The tech-facing bootstrap one-liner |
| `POST /api/backup?token&serial` | provisioning token (query) | Router-pushed config backup |
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
