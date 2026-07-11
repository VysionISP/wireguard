import type { ComplianceResult, ComplianceRule } from "./types.js";
import type { ComplianceState } from "./routeros.js";

/**
 * Config compliance: does a device still match the hardening baseline we
 * provisioned it with? Drift happens — someone re-enables telnet in the field,
 * a factory reset wipes DNS, an identity never got set. We re-read the live
 * config over the tunnel and diff it against `config.hardening`, the same
 * policy the bootstrap script applied. Each rule is checked only if the
 * baseline actually specifies it (empty baseline = nothing to enforce).
 */

export interface ComplianceBaseline {
  /** Services that must stay disabled (e.g. telnet, ftp). */
  disableServices: string[];
  /** Required DNS servers (device must have at least these). */
  dns: string[];
  /** Required NTP servers (client enabled + at least these). */
  ntpServers: string[];
  /** When set, identity must be non-factory (and start with the prefix). */
  identityPrefix: string;
  /** Comment of the managed management-access firewall rule. */
  mgmtFirewallComment?: string;
}

const MGMT_FW_COMMENT = "managed: wg-provision allow mgmt";

function has(list: string[], want: string): boolean {
  return list.map((s) => s.toLowerCase()).includes(want.toLowerCase());
}

export function evaluateCompliance(state: ComplianceState, baseline: ComplianceBaseline, at: string): ComplianceResult {
  const rules: ComplianceRule[] = [];

  // Disabled services.
  if (baseline.disableServices.length) {
    const byName = new Map(state.services.map((s) => [s.name.toLowerCase(), s]));
    const stillOn = baseline.disableServices.filter((name) => {
      const svc = byName.get(name.toLowerCase());
      return svc && !svc.disabled; // present and enabled = violation
    });
    rules.push({
      key: "services",
      label: "Insecure services disabled",
      ok: stillOn.length === 0,
      detail: stillOn.length ? `enabled: ${stillOn.join(", ")}` : `${baseline.disableServices.join(", ")} disabled`,
      fixable: true,
    });
  }

  // DNS servers.
  if (baseline.dns.length) {
    const missing = baseline.dns.filter((d) => !has(state.dnsServers, d));
    rules.push({
      key: "dns",
      label: "DNS servers",
      ok: missing.length === 0,
      detail: missing.length ? `missing: ${missing.join(", ")} (have: ${state.dnsServers.join(", ") || "none"})` : state.dnsServers.join(", "),
      fixable: true,
    });
  }

  // NTP.
  if (baseline.ntpServers.length) {
    const missing = baseline.ntpServers.filter((n) => !has(state.ntpServers, n));
    const ok = state.ntpEnabled && missing.length === 0;
    rules.push({
      key: "ntp",
      label: "NTP time sync",
      ok,
      detail: !state.ntpEnabled ? "NTP client disabled" : missing.length ? `missing: ${missing.join(", ")}` : `enabled: ${state.ntpServers.join(", ")}`,
      fixable: true,
    });
  }

  // Identity (non-factory; matches prefix when configured).
  if (baseline.identityPrefix) {
    const id = state.identity;
    const ok = id !== "MikroTik" && id !== "" && id.startsWith(baseline.identityPrefix);
    rules.push({
      key: "identity",
      label: "Device identity set",
      ok,
      detail: ok ? id : id === "MikroTik" ? "still factory-default (MikroTik)" : `"${id}" — expected ${baseline.identityPrefix}-…`,
      // We can name it, but only if it's still the factory default — renaming a
      // hand-set identity would clobber a deliberate choice, so don't auto-fix that.
      fixable: id === "MikroTik",
    });
  }

  // Management-access firewall rule present.
  const comment = baseline.mgmtFirewallComment ?? MGMT_FW_COMMENT;
  rules.push({
    key: "mgmt-firewall",
    label: "Management firewall rule",
    ok: state.firewallComments.some((c) => c === comment),
    detail: state.firewallComments.some((c) => c === comment) ? "present" : "missing — tunnel access not firewalled as provisioned",
    fixable: false, // re-adding needs the mgmt CIDR; surfaced for a human to re-provision
  });

  const failCount = rules.filter((r) => !r.ok).length;
  return { at, ok: failCount === 0, failCount, rules };
}

/**
 * RouterOS commands that bring the fixable rules back into line. Only emits
 * commands for rules that actually failed and are auto-fixable.
 */
export function remediationCommands(result: ComplianceResult, baseline: ComplianceBaseline, serial: string): string[] {
  const cmds: string[] = [];
  const failed = new Set(result.rules.filter((r) => !r.ok && r.fixable).map((r) => r.key));

  if (failed.has("services")) for (const svc of baseline.disableServices) cmds.push(`/ip/service/disable [find name="${svc}"]`);
  if (failed.has("dns") && baseline.dns.length) cmds.push(`/ip/dns/set servers=${baseline.dns.join(",")}`);
  if (failed.has("ntp") && baseline.ntpServers.length) {
    cmds.push("/system/ntp/client/servers/remove [find]");
    for (const s of baseline.ntpServers) cmds.push(`/system/ntp/client/servers/add address="${s}"`);
    cmds.push("/system/ntp/client/set enabled=yes");
  }
  if (failed.has("identity") && baseline.identityPrefix) cmds.push(`/system/identity/set name="${baseline.identityPrefix}-${serial}"`);
  return cmds;
}
