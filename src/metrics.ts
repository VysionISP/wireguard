import fs from "node:fs";
import path from "node:path";
import type { RouterStore } from "./store.js";
import type { WireguardManager } from "./wireguard.js";
import { fetchLiveStats, type FetchLiveFn } from "./routeros.js";

/**
 * Lightweight per-device time-series: CPU, memory and cumulative interface
 * byte counters, sampled every few minutes over the tunnel. Stored as JSONL
 * (one compact row per sample) with an in-memory index for fast queries, and
 * pruned to a retention window. This is what powers the traffic graph and the
 * "compared to the previous period" numbers on a device's profile page.
 */

export interface MetricSample {
  at: number; // epoch ms
  cpu: number; // percent
  memUsed: number; // bytes
  memTotal: number; // bytes
  /** Cumulative rx/tx byte counters per interface at sample time. */
  ifaces: Record<string, { rx: number; tx: number }>;
}

interface Row {
  s: string; // serial
  t: number; // at
  c: number; // cpu
  mu: number; // memUsed
  mt: number; // memTotal
  i: Record<string, [number, number]>; // iface -> [rx, tx]
}

const COMPACT_EVERY = 500;

export class MetricsStore {
  private byId = new Map<string, MetricSample[]>();
  private appendsSinceCompact = 0;

  constructor(
    private readonly filePath: string,
    private readonly retentionMs = 14 * 24 * 3600_000,
  ) {
    if (fs.existsSync(filePath)) this.load();
  }

  private load(): void {
    const cutoff = Date.now() - this.retentionMs;
    for (const line of fs.readFileSync(this.filePath, "utf8").split("\n")) {
      if (!line.trim()) continue;
      let row: Row;
      try {
        row = JSON.parse(line);
      } catch {
        continue;
      }
      if (!row || typeof row.t !== "number" || row.t < cutoff) continue;
      const ifaces: MetricSample["ifaces"] = {};
      for (const [name, pair] of Object.entries(row.i || {})) ifaces[name] = { rx: pair[0], tx: pair[1] };
      this.push(row.s, { at: row.t, cpu: row.c, memUsed: row.mu, memTotal: row.mt, ifaces });
    }
  }

  private push(serial: string, s: MetricSample): void {
    const arr = this.byId.get(serial);
    if (arr) arr.push(s);
    else this.byId.set(serial, [s]);
  }

  private static toRow(serial: string, s: MetricSample): Row {
    const i: Record<string, [number, number]> = {};
    for (const [name, v] of Object.entries(s.ifaces)) i[name] = [v.rx, v.tx];
    return { s: serial, t: s.at, c: s.cpu, mu: s.memUsed, mt: s.memTotal, i };
  }

  record(serial: string, s: MetricSample): void {
    this.push(serial, s);
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    fs.appendFileSync(this.filePath, JSON.stringify(MetricsStore.toRow(serial, s)) + "\n");
    if (++this.appendsSinceCompact >= COMPACT_EVERY) this.compact();
  }

  /** Drop expired samples from memory and rewrite the file from scratch. */
  compact(): void {
    const cutoff = Date.now() - this.retentionMs;
    const lines: string[] = [];
    for (const [serial, arr] of this.byId) {
      const kept = arr.filter((s) => s.at >= cutoff);
      this.byId.set(serial, kept);
      for (const s of kept) lines.push(JSON.stringify(MetricsStore.toRow(serial, s)));
    }
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    const tmp = `${this.filePath}.tmp`;
    fs.writeFileSync(tmp, lines.length ? lines.join("\n") + "\n" : "");
    fs.renameSync(tmp, this.filePath);
    this.appendsSinceCompact = 0;
  }

  /** Samples for a device, oldest-first, optionally only those at/after sinceMs. */
  samples(serial: string, sinceMs?: number): MetricSample[] {
    const sorted = [...(this.byId.get(serial) ?? [])].sort((a, b) => a.at - b.at);
    return sinceMs == null ? sorted : sorted.filter((s) => s.at >= sinceMs);
  }
}

export interface TrafficPoint {
  at: number;
  rx: number; // bits/sec
  tx: number; // bits/sec
}

export interface TrafficResult {
  interfaces: string[];
  /** Per-interface throughput over time (bits/sec). */
  series: Record<string, TrafficPoint[]>;
  /** Per-interface bytes transferred across the whole window. */
  totals: Record<string, { rx: number; tx: number }>;
}

/**
 * Turns cumulative-counter samples into per-interface throughput points and
 * window totals. A gap larger than 4x the sample interval (device was offline)
 * breaks the line rather than smearing a huge average across it, and a counter
 * that goes backwards (reboot) contributes zero for that step.
 */
export function computeTraffic(
  samples: MetricSample[],
  sampleSeconds: number,
  exclude: Set<string> = new Set(),
): TrafficResult {
  const maxGapMs = sampleSeconds * 4 * 1000;
  const series: Record<string, TrafficPoint[]> = {};
  const totals: Record<string, { rx: number; tx: number }> = {};
  for (let k = 1; k < samples.length; k++) {
    const prev = samples[k - 1];
    const curr = samples[k];
    const dtMs = curr.at - prev.at;
    if (dtMs <= 0 || dtMs > maxGapMs) continue;
    const dt = dtMs / 1000;
    for (const [name, cv] of Object.entries(curr.ifaces)) {
      if (exclude.has(name)) continue;
      const pv = prev.ifaces[name];
      if (!pv) continue;
      const drx = cv.rx >= pv.rx ? cv.rx - pv.rx : 0;
      const dtx = cv.tx >= pv.tx ? cv.tx - pv.tx : 0;
      (series[name] ??= []).push({ at: curr.at, rx: (drx * 8) / dt, tx: (dtx * 8) / dt });
      const tot = (totals[name] ??= { rx: 0, tx: 0 });
      tot.rx += drx;
      tot.tx += dtx;
    }
  }
  return { interfaces: Object.keys(series).sort(), series, totals };
}

// ---- background sampler --------------------------------------------------

export interface MetricsSamplerDeps {
  store: RouterStore;
  wg: WireguardManager;
  metrics: MetricsStore;
  offlineAfterSeconds: number;
  fetchLive?: FetchLiveFn;
}

/** One sampling pass: record a metric sample for every online router. */
export async function metricsTick(deps: MetricsSamplerDeps): Promise<{ sampled: number }> {
  const fetchLive = deps.fetchLive ?? fetchLiveStats;
  const hs = await deps.wg.latestHandshakes().catch(() => ({}) as Record<string, number | null>);
  const targets = deps.store.list().filter((r) => {
    if (r.state === "revoked" || r.state === "staged") return false;
    const age = hs[r.publicKey] ?? null;
    return age !== null && age < deps.offlineAfterSeconds;
  });

  let sampled = 0;
  const CONCURRENCY = 5;
  for (let i = 0; i < targets.length; i += CONCURRENCY) {
    await Promise.all(
      targets.slice(i, i + CONCURRENCY).map(async (r) => {
        try {
          const live = await fetchLive(r.tunnelIp, r.username, r.password, 6000);
          const ifaces: MetricSample["ifaces"] = {};
          for (const it of live.interfaces) ifaces[it.name] = { rx: it.rxByte, tx: it.txByte };
          deps.metrics.record(r.serialNumber, {
            at: Date.now(),
            cpu: live.resource.cpuLoad,
            memUsed: live.resource.totalMemory - live.resource.freeMemory,
            memTotal: live.resource.totalMemory,
            ifaces,
          });
          sampled++;
        } catch {
          // unreachable this pass — skip, we'll catch it next time
        }
      }),
    );
  }
  return { sampled };
}

/** Runs metricsTick on an interval; returns a stop function. */
export function startMetricsSampler(deps: MetricsSamplerDeps, intervalSeconds: number): () => void {
  let busy = false;
  const run = async (): Promise<void> => {
    if (busy) return;
    busy = true;
    try {
      await metricsTick(deps);
    } catch (err) {
      console.error(`metrics: ${(err as Error).message}`);
    } finally {
      busy = false;
    }
  };
  const timer = setInterval(() => void run(), intervalSeconds * 1000);
  timer.unref?.();
  void run();
  return () => clearInterval(timer);
}
