import type { Config } from "./config.js";
import type { RouterRecord } from "./types.js";
import { parseCidr } from "./ipam.js";

/**
 * RouterOS script generation.
 *
 * Everything we create on the router carries a "managed:" comment so it can
 * be found (and replaced idempotently) on re-provisioning without touching
 * config a customer or tech added by hand.
 *
 * Requires RouterOS v7 (WireGuard support).
 */

function rosQuote(value: string): string {
  // RouterOS string literals: escape backslash and double quote. Values we
  // interpolate (keys, generated passwords, hostnames) never contain control
  // characters, but escape defensively anyway.
  return value.replace(/\\/g, "\\\\").replace(/"/g, "\\\"").replace(/\$/g, "\\$");
}

/**
 * The generic bootstrap script. The same script is used for every router:
 * it creates the WireGuard interface (RouterOS generates the keypair),
 * reports the public key + serial number to the provisioning server, and
 * imports the tailored provisioning script the server responds with.
 */
export function renderBootstrap(cfg: Config, tokenOverride?: string): string {
  const url = cfg.server.publicUrl.replace(/\/$/, "");
  const wg = rosQuote(cfg.router.wgInterfaceName);
  const token = rosQuote(tokenOverride ?? cfg.auth.provisioningToken);
  const cert = cfg.router.strictTls ? " check-certificate=yes-without-crl" : "";
  return `# mikrotik-wg-provision bootstrap
# Paste into a terminal on a factory-fresh RouterOS v7 device, or run:
#   /tool fetch url="${url}/bootstrap.rsc?token=..." dst-path=bootstrap.rsc
#   /import bootstrap.rsc
:log info "wg-provision: bootstrap starting"

# 1. Create the management WireGuard interface (RouterOS generates the keypair)
:if ([:len [/interface/wireguard/find name="${wg}"]] = 0) do={
    /interface/wireguard/add name="${wg}" comment="managed: wg-provision"
}
:local pubkey [/interface/wireguard/get [find name="${wg}"] public-key]

# 2. Collect device identity
:local serial "unknown"
:do { :set serial [/system/routerboard/get serial-number] } on-error={}
:local board [/system/resource/get board-name]
:local rosver [/system/resource/get version]
:local ident [/system/identity/get name]

# 3. Register with the provisioning server; the response is a tailored
#    RouterOS script which we import.
:local body ("{\\"token\\":\\"${token}\\",\\"publicKey\\":\\"" . \$pubkey . "\\",\\"serialNumber\\":\\"" . \$serial . "\\",\\"boardName\\":\\"" . \$board . "\\",\\"rosVersion\\":\\"" . \$rosver . "\\",\\"identity\\":\\"" . \$ident . "\\"}")
:do {
    /tool fetch url="${url}/api/register" http-method=post http-header-field="Content-Type: application/json" http-data=\$body dst-path="wg-provision.rsc"${cert}
    :delay 2s
    /import file-name=wg-provision.rsc
    /file/remove [find name="wg-provision.rsc"]
    :log info "wg-provision: bootstrap complete"
} on-error={
    :log error "wg-provision: registration failed"
    # Ask the server WHY, and print it on the terminal.
    :do {
        /tool fetch url=("${url}/api/register-reason?token=${token}&serial=" . \$serial) dst-path="wg-reason.rsc"${cert}
        :delay 1s
        /import file-name=wg-reason.rsc
        /file/remove [find name="wg-reason.rsc"]
    } on-error={
        :put "wg-provision: registration FAILED and the reason could not be retrieved - check connectivity to ${url}"
    }
}
`;
}

/** A tiny RSC the router imports to print, on the CLI, why provisioning failed. */
export function renderReason(reason: string): string {
  const m = rosQuote(reason);
  return `:log error "wg-provision: ${m}"\n:put "\\n=== WG-PROVISION FAILED ===\\n${m}\\n"\n`;
}

/**
 * The per-router provisioning script returned by /api/register. Applies the
 * tunnel, management IP, management user, services and a firewall rule that
 * lets the provisioning server reach the router over the tunnel.
 */
export function renderProvision(cfg: Config, router: RouterRecord, tokenOverride?: string): string {
  const url = cfg.server.publicUrl.replace(/\/$/, "");
  const wg = rosQuote(cfg.router.wgInterfaceName);
  const provToken = tokenOverride ?? cfg.auth.provisioningToken;
  const mgmt = parseCidr(cfg.wireguard.mgmtCidr);
  const cert = cfg.router.strictTls ? " check-certificate=yes-without-crl" : "";
  const keepalive =
    cfg.wireguard.persistentKeepalive > 0
      ? ` persistent-keepalive=${cfg.wireguard.persistentKeepalive}s`
      : "";
  return `# mikrotik-wg-provision: configuration for serial ${router.serialNumber}
:log info "wg-provision: applying provisioned configuration"

# 1. Peer with the WireGuard management server (replace any managed peer)
/interface/wireguard/peers/remove [find interface="${wg}" comment="managed: wg-provision"]
/interface/wireguard/peers/add interface="${wg}" \\
    public-key="${rosQuote(cfg.wireguard.serverPublicKey)}" \\
    endpoint-address="${rosQuote(cfg.wireguard.endpointHost)}" \\
    endpoint-port=${cfg.wireguard.endpointPort} \\
    allowed-address=${cfg.wireguard.mgmtCidr}${keepalive} \\
    comment="managed: wg-provision"

# 2. Management tunnel address
/ip/address/remove [find interface="${wg}" comment="managed: wg-provision"]
/ip/address/add address=${router.tunnelIp}/${mgmt.prefix} interface="${wg}" comment="managed: wg-provision"

# 3. Management user
:if ([:len [/user/find name="${rosQuote(router.username)}"]] = 0) do={
    /user/add name="${rosQuote(router.username)}" password="${rosQuote(router.password)}" group=full comment="managed: wg-provision"
} else={
    /user/set [find name="${rosQuote(router.username)}"] password="${rosQuote(router.password)}" group=full
}

# 4. Make sure we can talk to the router over the tunnel (SSH, API, REST)
/ip/service/enable [find name="ssh"]
/ip/service/enable [find name="api"]
/ip/service/enable [find name="www"]

# 5. Firewall: accept management traffic arriving over the tunnel.
#    Inserted at the top of the input chain so default drop rules don't block it.
:if ([:len [/ip/firewall/filter/find comment="managed: wg-provision allow mgmt"]] = 0) do={
    :do {
        /ip/firewall/filter/add chain=input src-address=${cfg.wireguard.mgmtCidr} action=accept comment="managed: wg-provision allow mgmt" place-before=([:pick [/ip/firewall/filter/find] 0])
    } on-error={
        /ip/firewall/filter/add chain=input src-address=${cfg.wireguard.mgmtCidr} action=accept comment="managed: wg-provision allow mgmt"
    }
}

${renderHardening(cfg, router)}${renderBackupSchedule(cfg, router, provToken)}# 8. Tell the provisioning server the configuration was applied
:do {
    /tool fetch url="${url}/api/confirm" http-method=post http-header-field="Content-Type: application/json" http-data="{\\"token\\":\\"${rosQuote(provToken)}\\",\\"serialNumber\\":\\"${rosQuote(router.serialNumber)}\\"}" output=none${cert}
} on-error={
    :log warning "wg-provision: could not confirm with server (tunnel may still be fine)"
}

:log info "wg-provision: done - management IP ${router.tunnelIp}"
`;
}

/** Services the tool depends on; never allowed to be disabled by hardening. */
const REQUIRED_SERVICES = new Set(["ssh", "www", "api"]);

function renderHardening(cfg: Config, router: RouterRecord): string {
  const h = cfg.hardening;
  const parts: string[] = [];

  const disable = h.disableServices.filter((s) => !REQUIRED_SERVICES.has(s));
  for (const svc of disable) {
    parts.push(`/ip/service/disable [find name="${rosQuote(svc)}"]`);
  }
  if (h.dns.length > 0) {
    parts.push(`/ip/dns/set servers=${h.dns.map(rosQuote).join(",")}`);
  }
  if (h.ntpServers.length > 0) {
    parts.push(
      `:do {`,
      `    /system/ntp/client/servers/remove [find]`,
      ...h.ntpServers.map((s) => `    /system/ntp/client/servers/add address="${rosQuote(s)}"`),
      `    /system/ntp/client/set enabled=yes`,
      `} on-error={ :log warning "wg-provision: could not configure NTP" }`,
    );
  }
  if (h.identityPrefix) {
    const name = rosQuote(`${h.identityPrefix}-${router.serialNumber}`);
    parts.push(
      `:if ([/system/identity/get name] = "MikroTik") do={ /system/identity/set name="${name}" }`,
    );
  }
  // Ensure account (login) events are captured in the memory log so the
  // server's device monitor can read them over the tunnel.
  parts.push(
    `:if ([:len [/system/logging/find topics~"account"]] = 0) do={ /system/logging/add topics=account action=memory }`,
  );
  if (parts.length === 0) return "";
  return `# 6. Hardening / base configuration\n${parts.join("\n")}\n\n`;
}

function renderBackupSchedule(cfg: Config, router: RouterRecord, provToken: string): string {
  if (!cfg.backup.enabled) return "";
  const url = cfg.server.publicUrl.replace(/\/$/, "");
  const h = cfg.backup.intervalHours;
  const interval = h % 24 === 0 ? `${h / 24}d` : `${h}h`;
  const cert = cfg.router.strictTls ? " check-certificate=yes-without-crl" : "";
  // The script body is a RouterOS string literal inside the .rsc, so quotes
  // inside it are escaped for RouterOS (\\\" in TS source -> \" in the file).
  const uploadUrl = `${url}/api/backup?token=${encodeURIComponent(provToken)}&serial=${encodeURIComponent(router.serialNumber)}`;
  const script =
    `/export file=wg-provision-backup; :delay 5s; ` +
    `/tool fetch upload=yes http-method=post url=\\"${rosQuote(uploadUrl)}\\" src-path=wg-provision-backup.rsc output=none${cert}; ` +
    `/file/remove [find name=\\"wg-provision-backup.rsc\\"]`;
  return `# 7. Scheduled config backup (router pushes /export to the server)
/system/script/remove [find name="wg-provision-backup"]
/system/script/add name="wg-provision-backup" comment="managed: wg-provision" source="${script}"
/system/scheduler/remove [find name="wg-provision-backup"]
/system/scheduler/add name="wg-provision-backup" interval=${interval} start-time=startup on-event="wg-provision-backup" comment="managed: wg-provision"
:do { /system/script/run wg-provision-backup } on-error={ :log warning "wg-provision: first backup failed" }

`;
}

/** One-liner a tech runs on a fresh router to kick everything off. */
export function renderOneLiner(cfg: Config, tokenOverride?: string): string {
  const url = cfg.server.publicUrl.replace(/\/$/, "");
  const cert = cfg.router.strictTls ? " check-certificate=yes-without-crl" : "";
  const token = tokenOverride ?? cfg.auth.provisioningToken;
  return `/tool fetch url="${url}/bootstrap.rsc?token=${encodeURIComponent(token)}" dst-path=bootstrap.rsc${cert}; :delay 2s; /import bootstrap.rsc`;
}
