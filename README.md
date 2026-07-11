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

## NOC wallboard

`http://<server>:8442/noc` is a stripped-down, full-screen live wallboard for
a big screen on the wall — **status and faults only**, nothing to click:

- A pulsing banner: green **ALL SYSTEMS OPERATIONAL**, or red/amber with the
  live count when something is wrong.
- **Active faults** as cards, critical first then newest — a new fault flashes
  in and floats to the top. Each shows the device, the message, how long it's
  been open, and who (if anyone) acknowledged it.
- A **live event feed** streaming logins, link flaps, on/offline and traffic
  alerts as they happen.
- Fleet online / offline / total counts and a connection indicator.

It updates over Server-Sent Events (no manual refresh) and auto-reconnects. The
**◉ NOC** button in the dashboard header opens it in a new tab, carrying your
token. For an unattended screen, open `…/noc?token=<admin-or-session-token>`
directly — the token is saved to the browser and stripped from the address bar.

## Users & roles

The dashboard supports named accounts with three roles:

- **tech** — view the fleet, verify routers, see live stats, view/download backups
- **admin** — everything, plus revoke, bulk commands, tokens, users, restore staging
- **customer** — a read-only **customer portal** (see below), scoped to a single
  customer group; no access to the ops dashboard or any staff API

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

Delivery is reliable by design: every destination (webhook, each Telegram
chat) is retried once after 3 s on failure, and failures are logged naming the
destination that failed, not just "fetch failed".

### Escalation & acknowledging from Telegram

A critical issue nobody acknowledges within `alerts.escalateAfterMinutes`
(default 10, 0 = off) is re-announced as a 🚨 **ESCALATION** — to the webhook
and to every Telegram chat subscribed to the *Offline* category — and keeps
re-paging every `escalateEveryMinutes` (default 15) up to `maxEscalations`
(default 3) until someone acks it or it resolves.

Escalation messages on Telegram carry an inline **✅ Ack** button: pressing it
acknowledges the issue right from the chat (recorded in the audit log as
`tg:<username>`), edits the message to "ACKED by …", and stops the re-paging.
The button works via a long-poll the server runs against the Bot API; the
poller also keeps the Settings chat-discovery working (chats it consumes are
merged into "Verify & fetch chats").

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
registers exactly one router before burning. A token can carry a **customer**
and **label**: set them when generating the token, and the device is
automatically assigned to that customer (and labelled) the moment it bootstraps
with that token — so a whole install is one-and-done from the script. Set
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

## Device page

The **Open** button on each router (and clicking a map node) navigates to a
full in-app page for that device — a real routed view, not a modal, so the
browser Back button and a refresh both work and the URL (`#device/<id>`) is
shareable. A **← Back** button returns to the fleet. The old details and
profile modals are merged into it: the header bar carries the device controls,
and the body is a two-column layout with live telemetry on the left and
everything you manage on the right.

- **Controls** (header) — **Verify** reachability, **Live stats** stream,
  **Back up now**, **Reboot** (admin; confirms first, then issues
  `/system/reboot` over the tunnel and logs a device event), and
  **Revoke / Remove**.
- **Overview** (top tiles) — state, health, uptime, CPU, memory, board,
  ROS + firmware version (with an "upgrade available" flag when the
  RouterBOARD reports a newer firmware). Admins get **Check updates** and, once
  an update is flagged, a one-click **Upgrade → x.y** button right in the
  header (see Firmware below).
- **Ports** (top diagram) — a live router faceplate showing every physical
  port with its link status; click a port to set link / inverted-link /
  traffic-threshold monitoring (admin).
- **Traffic graph** — per-interface throughput over 1h / 6h / 24h / 7d / 30d,
  drawn from a background sampler that records each online device's counters
  every few minutes. The **previous period** is overlaid faintly behind the
  current one, and tiles show total downloaded / uploaded with the percentage
  change vs. the preceding window. Pick any interface; it defaults to the
  busiest (usually the uplink). The management tunnel is excluded.
- **Upstream ping** — every monitored router pings anchor IPs (8.8.8.8 and
  1.1.1.1 by default; add your own, e.g. the POP gateway) once a minute *from
  the router itself*, and the page graphs that latency per target over
  1h / 6h / 24h / 7d. Partial loss shows as amber dots on the line, 100% loss
  as red ✕ marks on the baseline. Sustained full loss (two consecutive ticks)
  opens a warning issue + alert with a recovery notice when it clears, and an
  optional per-device **latency threshold** (ms) flags sustained slow paths
  the same way. Targets, on/off and the threshold live in the Monitoring
  section; interval/retention under `upstreamPing` in `config.json`. Routers
  that are themselves offline are skipped — liveness already reports those.
- **Health** — temperature / voltage / fan sensors where the board exposes them.
- **Ping test & monitored hosts / DHCP leases / IP addresses** — the router's
  live tables (see below for internal-host ping monitoring).
- **Manage** (right column) — label, customer, SLA target and notes;
  SSH / credential quick-copy; a collapsible **Monitoring** section (device
  type + active-monitoring / login-alert toggles, with port monitoring driven
  by the port diagram at the top);
  and the config-backup list with diff / restore. Saving details or monitoring
  refreshes the panel in place without leaving the page.
- **Console** (admin, full width at the bottom) — the *actual* RouterOS CLI:
  the server opens a persistent SSH PTY to the router and streams it to an
  in-page terminal (a self-hosted xterm.js — no CDN). Tab completion, `?`
  help, colours, menus, safe mode — everything behaves exactly like ssh'ing
  in, because it is the router's own shell. Keystrokes ride ordered POSTs;
  output streams over SSE and survives brief reconnects (the scrollback
  replays). Sessions close when you leave the page and are reaped after 15
  minutes idle; opening and closing a console is audit-logged (individual
  keystrokes are not).

Traffic history is stored in `data/metrics.jsonl` and pruned to
`metrics.retentionDays` (default 14). Sampling cadence and retention are set
under `metrics` in `config.json`.

## Bulk commands

Admins can run a RouterOS command across the whole fleet (or a selection)
over SSH from the Bulk actions tab, 5 routers at a time, with per-router
success/output captured. Presets included for identity, resources, DNS,
firmware update check, and reboot.

## Backup diff & restore

The device page diffs any two stored config versions (colourised) and, for
admins, stages a restore: the chosen backup is uploaded to the router as
`wg-restore.rsc` for you to review and `/import` manually — never auto-applied,
because replaying a full export onto a live device needs human eyes. A **Back
up now** button in the same view triggers an immediate `/export` over SSH
(stored only if the config changed) — handy for a snapshot right before you
make a change.

## RouterOS upgrades

**Settings → Firmware** (admin) is a fleet view of who's running what. Tick
devices and **Check selected for updates** (runs `check-for-updates` and
records the result per device), or **Upgrade selected** to roll them out. A
single device can also be checked/upgraded straight from its device page.

Rollouts run as a **staged job — one device at a time**: check → `update
install` (the router downloads packages and reboots itself) → wait until it's
back over the tunnel → confirm the reported version actually changed → move on.
So a bad build takes out one CPE, not the whole fleet, and you watch it live:
each device shows queued / checking / installing / rebooting / done, with a
**Cancel rest** that stops the queue after the current device finishes. Tick
*also upgrade RouterBOARD firmware* to run `/system routerboard upgrade` +
a second reboot after the RouterOS bump.

Each device gets a **temporary maintenance window** for the duration so its
reboot doesn't page anyone, the version bump is written back to the inventory,
and start/finish land in the device event log (and the audit log). A device
that doesn't come back within the timeout is marked failed and left for you to
look at — the rollout continues past it. Only one rollout runs at a time; job
history is kept under `upgradesPath`. Timeouts/poll cadence aren't hand-tuned
in config (sensible defaults: ~12 min online-wait, 10 s poll).

## Config compliance

**Settings → Compliance** (and a panel on each device page) checks whether a
device still matches the **provisioning hardening baseline** — the same policy
(`config.hardening`) the bootstrap script applied. Drift is normal in the
field: someone re-enables telnet, a factory reset wipes DNS, an identity never
got set. Each rule is only enforced if the baseline specifies it:

- **Insecure services disabled** — `hardening.disableServices` (telnet/ftp/…)
  must stay disabled.
- **DNS servers** — the device must carry `hardening.dns`.
- **NTP time sync** — client enabled with `hardening.ntpServers`.
- **Device identity set** — non-factory, matching `hardening.identityPrefix`.
- **Management firewall rule** — the managed tunnel-access rule is present.

The fleet view lists every device compliant / non-compliant / not-checked
(non-compliant first) with the failing rules named; **Check all online
devices** sweeps them. On a device page the same check runs live, and admins
get a one-click **Fix** that re-applies the fixable rules over SSH (services,
DNS, NTP, and naming a still-factory identity) and re-checks. It deliberately
won't rename a *deliberately-set* identity or re-add the firewall rule
unattended — those are surfaced for a human. Every fix is audit-logged.

`GET /api/routers/:ref/compliance` runs a live check (tech), `GET
/api/compliance` is the cached fleet roll-up (tech), `POST
/api/routers/:ref/compliance/fix` remediates (admin).

## Customer portal

Customers get their own **read-only login** at `http://<server>:8442/portal` —
distinct from the shared-link public status page. Create a **customer** account
in the Users tab and tie it to one customer group; that account sees *only* that
customer's devices and nothing else. The portal shows, per device:

- live status (online / degraded / down) and how long it's been up,
- **30-day uptime vs the committed SLA** (green when meeting it, red when below),
- connected equipment the router ping-monitors (by name, never the LAN IP),
- a **traffic graph** with a previous-period comparison, per interface / range.

It refreshes every 30 s and carries a planned-maintenance banner. Crucially it
is enforced server-side: the role hierarchy (admin > tech > customer) keeps a
customer token off every staff endpoint (the fleet, credentials, config,
upgrades, console…), and the portal's own endpoints resolve the device set from
the *session's* customer group — a customer can't read another customer's
device even by guessing its id (it 404s, so ids can't be probed). Customer
accounts that try the main dashboard are redirected to the portal.

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

Each router is classed as **customer** (CPE — logins, pull access stats like
LTE/5G signal) or **infrastructure** (towers/PoPs/core — logins + port
traffic). Set it per device in the details view; it drives the default
monitoring profile (infrastructure enables link-down alerting by default,
since those links are load-bearing) and which live stats the dashboard
emphasises. Link-down still only fires for the specific ports you select. New
routers default to customer with monitoring on.

Per-device monitoring is fully configurable in the details view (admin):
device type, master on/off, alert-on-login, and per-port rules. Click a port
in the faceplate map to open its rule dialog:

- **Monitor link status** — alert when the link drops (and clears when it
  recovers).
- **Inverted** — the port is *meant* to stay unplugged (a spare WAN, a
  disabled uplink), so the alarm is the port coming **UP**, and DOWN is normal.
- **Traffic above / below** — alert when the port's combined rx+tx throughput
  crosses a threshold (e.g. above 800 Mbps = saturated uplink; below 1 Mbps on
  a link that should be busy = something's wrong). Thresholds are
  edge-triggered with hysteresis, so a sustained condition alerts once and
  clears once, not every tick.

Ports with no rule are not monitored at all — you opt each one in. A port can
combine checks (e.g. link status *and* a high-traffic threshold).

## Customers & network map

Create customers with their details (contact, phone, email, address, notes) in
**Settings → Customers**. Assign a device to a customer in its details view
(a dropdown of existing customers, or type a new one). Deleting a customer
unassigns its devices and clears its map.

Devices for a customer appear together on the **Map** tab as a network
topology; the customer's contact details show above the map:

- Devices are draggable nodes (positions are saved per customer); a green LED
  shows online state. **Add device** pulls any fleet device into the customer
  and onto the map.
- Admins draw **links** between two devices, naming the interface on each end
  (e.g. `sfp1` ↔ `ether1`), and remove a link by clicking its label.
- Each link shows **live throughput** streamed from the group's devices
  (`GET /api/groups/:name/stream`), so you can watch traffic move across the
  customer's network in real time. Links carrying traffic highlight.
- **⟲ Discover links** builds the map for you: it reads each device's
  MikroTik neighbor table (`/ip/neighbor` — MNDP/LLDP) and creates a link for
  every pair of managed devices that see each other, with the correct port on
  each end (each side's own port name wins over the remote's advertisement).
  Existing manual links are kept and counted as confirmed; neighbors that
  aren't managed devices (upstream carrier gear, random APs) are reported but
  not drawn. Devices still on the factory "MikroTik" identity are skipped as
  ambiguous — set identities first (provisioning's `identityPrefix` does this).

## Customer status pages

Give a customer a **read-only public status page**: Settings → Customers →
**Status page** generates an unguessable link
(`https://…/status/st-…`) you can send them. It shows — labels only, no
serials, IPs or credentials —

- an overall banner (operational / partially degraded / service disruption),
- each of their devices with live up/degraded/down state, its **SLA
  commitment and whether it's currently met** (e.g. `SLA 99.9% ✓`), and any
  **ping-monitored internal equipment nested under its router** (the NVR, an
  AP…) with its own state,
- a read-only **network map** — the same topology you maintain on the Map tab
  (node states, links, port names; internal ids never leave the server),
- current incidents in customer-friendly words ("Device offline", "Link
  issue"), a planned-maintenance notice when a window is active,
- and their last-30-days uptime % (maintenance excluded).

The page refreshes itself every 30 s. **The link is permanent** — reopening
the dialog always shows the same URL, so what you've given the customer keeps
working. **Rotate link** explicitly mints a new URL (killing the old one, for
leaks); **Disable** shuts the page off entirely.

Layouts and links are stored per group in `topologyPath`
(`data/topology.json`). Removing a router also drops it from any map.

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

## Fleet monitoring & liveness

Online/offline is driven by an **active liveness probe**: a fast TCP connect
to each device over the tunnel every `liveness.intervalSeconds` (default 10 s).
This is far quicker than WireGuard handshake age, which only re-handshakes
every ~2 minutes on a healthy link and so can't tell you anything useful
sub-minute. Each device moves through three states:

- **up** — responded to a recent probe.
- **warning / degraded** — no reply for `liveness.warnAfterSeconds` (default
  20 s). Shown as an amber pulsing dot; a "degraded" event is logged, but no
  issue or hard alert yet (rides out a brief blip).
- **offline** — no reply for `liveness.offlineAfterSeconds` (default 60 s).
  Opens the critical **offline** issue, fires the alert, and records the
  transition.

Recovery clears the issue and (if it had gone fully offline) sends the
back-online alert. The probe hits `liveness.port` (default 80 / the REST
service, always enabled) with a `liveness.timeoutMs` connect timeout; a
connection *refused* still counts as alive (the host answered). Set
`liveness.enabled: false` to fall back to the legacy handshake-age monitor
(`monitor.offlineAfterSeconds`, default 180 s).

The fleet table, the details view, the live heartbeat and the NOC wallboard
all reflect this three-state health. On the NOC, degraded devices show as amber
cards alongside the faults, and a **new critical fault plays an alert sound**
(click the 🔊 button once to satisfy the browser's audio-gesture rule).

## SLA / uptime reports

The **Reports** tab turns the liveness data into a customer-facing uptime
report. Pick a range (7d / 30d / 90d presets or custom dates) and Generate:

- **Fleet uptime %**, total unplanned downtime and outage count up top.
- **By customer** and **by device** tables, each with uptime %, downtime,
  outage count, longest outage and planned-maintenance time.
- **Export CSV** for a spreadsheet, or **Print / PDF** for a clean customer
  hand-out (the browser print dialog).

Each router can carry an **SLA target** (set it in the device details — none /
99% / 99.5% / 99.9% / 99.95% / 99.99%). The report shows each device's target
and a **✓ met / ✗ breached** status against its actual uptime, and the summary
counts how many devices are breaching their commitment.

Uptime is computed from a durable **outage log** (`outagesPath`,
`data/outages.json`) that the liveness monitor writes to — it opens an outage
when a device goes offline and closes it on recovery, so downtime survives
restarts and the bounded event feed. **Planned maintenance is excluded**: any
downtime inside a maintenance window (that covered "offline") is removed from
both the downtime and the denominator, so a scheduled reboot neither helps nor
hurts the number. A device is only measured from its registration date
forward.

## Maintenance windows

Planned work shouldn't page anyone. Under **Settings → Maintenance** you can
schedule a window scoped to the **whole fleet**, a **single device**, or a
**customer**, for a start/end time, and choose which alert categories to mute
(offline/degraded, port link & traffic, internal hosts, logins — or all of
them). While a window is active:

- No issues, alerts or events are raised for the covered devices/categories —
  monitoring still tracks real state, it just stays quiet.
- The **NOC wallboard** shows a "🔧 MAINTENANCE — … — alerts suppressed" bar
  and a MAINT pill, and hides the covered faults so the board stays calm.
- The fleet table marks the device with a 🔧 badge until the window ends.
- The downtime is excluded from SLA reporting (planned, not an outage).

Windows auto-expire; there's a Delete button and quick 1h/3h/8h presets.
Stored in `maintenancePath` (`data/maintenance.json`).

## Monitoring internal LAN devices

You can ping-monitor devices *behind* a router — a DHCP client, camera, AP or
anything on its LAN — even though they aren't routable from the provisioning
server. The router does the pinging on our behalf.

On a device's **Profile**, each DHCP lease has a **＋ Monitor** button; click it
to start watching that client. There's also a **Ping test & static monitor**
tool: type any LAN address, hit **Ping test** for a one-off result (replies,
loss %, average RTT), or **＋ Monitor** to watch a fixed IP that isn't in the
DHCP table (a statically-addressed camera, PLC, switch…).

Monitored hosts appear in a "Monitored internal hosts" table with live state and
round-trip time, and move through the same **up → warning → offline** states
(`hosts.warnAfterSeconds` / `offlineAfterSeconds`, pinged every
`hosts.intervalSeconds`). Going offline opens a `host-down` issue — so it shows
on the status board **and the NOC wallboard** — and fires an alert; recovery
clears it. A host is never blamed while its own router is offline. Monitored
hosts live in `hostsPath` (`data/hosts.json`) and are removed with the device.

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
| `GET /noc` | none (page authenticates the stream) | Live NOC wallboard |
| `GET /api/noc/stream` | tech (via `?token=`) | SSE: faults + live events + fleet counts |
| `POST /api/login` | none | Exchange username/password for a session token |
| `POST /api/logout` / `GET /api/me` | tech | End session / current identity |
| `POST /api/account/password` | tech | Change your own password |
| `POST /api/users/:username/password` | admin | Reset a user's password |
| `GET /api/routers` | tech | Inventory with handshake ages + online flag |
| `GET /api/routers/:ref` | tech | Full details incl. credentials (ref = id, serial or tunnel IP) |
| `POST /api/routers/:ref/verify` | tech | Handshake + REST reachability check; marks `verified` |
| `POST /api/routers/:ref/reboot` | admin | Reboot the device over the tunnel (`/system/reboot`); logs a device event |
| `POST /api/routers/:ref/exec` | admin | Run one RouterOS command over SSH and return its output |
| `POST /api/routers/:ref/upgrade-check` | admin | Check for a RouterOS update; records the result on the device |
| `POST /api/upgrades` | admin | Start a staged RouterOS rollout over `{refs, alsoFirmware}` |
| `GET /api/upgrades` / `GET /api/upgrades/:id` | tech | Rollout jobs + live per-device progress |
| `POST /api/upgrades/:id/cancel` | admin | Stop a running rollout after the current device |
| `GET /api/routers/:ref/live` | tech | Live stats over the tunnel (system, interfaces, LTE) |
| `GET /api/routers/:ref/profile` | tech | Live profile: DHCP leases, IP addresses, health, firmware |
| `GET /api/routers/:ref/traffic?hours=` | tech | Traffic history + previous-period comparison from stored metrics |
| `GET /api/routers/:ref/pings?hours=` | tech | Upstream ping latency/loss series per target (8.8.8.8, 1.1.1.1, custom) |
| `GET /api/reports/sla?from&to` | tech | Uptime/SLA per device, customer and fleet (maintenance-excluded) |
| `POST /api/groups/:name/discover` | admin | Auto-discover map links from MikroTik neighbor tables |
| `POST/DELETE /api/customers/:name/status-token` | admin | Enable/rotate / disable a customer's public status page |
| `GET /status/:token` + `/api/status/:token` | public (token) | Read-only customer status page + its JSON |
| `GET /portal` + `/api/portal/overview` | customer | Authenticated per-customer portal (own devices, SLA, uptime) |
| `GET /api/portal/devices/:id/traffic` | customer | Traffic history for one of the account's own devices |
| `GET/POST /api/maintenance` | tech / admin | List / schedule maintenance windows |
| `DELETE /api/maintenance/:id` | admin | Cancel a maintenance window |
| `POST /api/routers/:ref/ping` | tech | One-off ping test from the router to a LAN address |
| `GET/POST /api/routers/:ref/hosts` | tech | List / add monitored internal ping targets |
| `PATCH/DELETE /api/hosts/:id` | tech | Toggle/rename / remove a monitored host |
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
| `GET /api/customers` | tech | Customers with device counts + details |
| `POST /api/customers` / `DELETE /api/customers/:name` | admin | Create/update / delete a customer |
| `GET /api/groups/:name` | tech | A customer's devices + topology |
| `PUT /api/groups/:name/topology` | admin | Save the group's map layout + links |
| `GET /api/groups/:name/stream` | token in query | SSE: live per-interface traffic for the map |
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
