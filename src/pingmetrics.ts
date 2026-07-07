import fs from "node:fs";
import path from "node:path";

/**
 * Per-device upstream-ping time-series: for each router, the RTT and packet
 * loss to each of its ping targets (8.8.8.8 / 1.1.1.1 / custom), sampled on
 * an interval by the ping monitor. Same JSONL + in-memory-index shape as
 * MetricsStore; powers the latency graph on the device page.
 */

export interface PingSample {
  at: number; // epoch ms
  /** target -> result. rtt is average ms, null when every echo was lost. */
  targets: Record<string, { rtt: number | null; loss: number }>;
}

interface Row {
  s: string; // serial
  t: number; // at
  /** target -> [rtt|null, lossPct] */
  p: Record<string, [number | null, number]>;
}

const COMPACT_EVERY = 500;

export class PingMetricsStore {
  private byId = new Map<string, PingSample[]>();
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
      this.push(row.s, PingMetricsStore.fromRow(row));
    }
  }

  private static fromRow(row: Row): PingSample {
    const targets: PingSample["targets"] = {};
    for (const [addr, pair] of Object.entries(row.p || {})) targets[addr] = { rtt: pair[0], loss: pair[1] };
    return { at: row.t, targets };
  }

  private static toRow(serial: string, s: PingSample): Row {
    const p: Row["p"] = {};
    for (const [addr, v] of Object.entries(s.targets)) p[addr] = [v.rtt === null ? null : Math.round(v.rtt * 10) / 10, Math.round(v.loss)];
    return { s: serial, t: s.at, p };
  }

  private push(serial: string, s: PingSample): void {
    const arr = this.byId.get(serial);
    if (arr) arr.push(s);
    else this.byId.set(serial, [s]);
  }

  record(serial: string, s: PingSample): void {
    this.push(serial, s);
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    fs.appendFileSync(this.filePath, JSON.stringify(PingMetricsStore.toRow(serial, s)) + "\n");
    if (++this.appendsSinceCompact >= COMPACT_EVERY) this.compact();
  }

  /** Samples for one device inside the window, oldest first. */
  samples(serial: string, hours: number, now = Date.now()): PingSample[] {
    const from = now - hours * 3600_000;
    return (this.byId.get(serial) ?? []).filter((s) => s.at >= from && s.at <= now);
  }

  /** Drop everything past retention and rewrite the file compactly. */
  compact(now = Date.now()): void {
    this.appendsSinceCompact = 0;
    const cutoff = now - this.retentionMs;
    const lines: string[] = [];
    for (const [serial, arr] of this.byId) {
      const kept = arr.filter((s) => s.at >= cutoff);
      if (kept.length) this.byId.set(serial, kept);
      else this.byId.delete(serial);
      for (const s of kept) lines.push(JSON.stringify(PingMetricsStore.toRow(serial, s)));
    }
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    const tmp = `${this.filePath}.tmp`;
    fs.writeFileSync(tmp, lines.join("\n") + (lines.length ? "\n" : ""));
    fs.renameSync(tmp, this.filePath);
  }
}
