import { describe, expect, it } from "vitest";
import path from "node:path";
import fs from "node:fs";
import { MetricsStore, computeTraffic, type MetricSample } from "../src/metrics.js";
import { tempDir } from "./helpers.js";

function sample(at: number, rx: number, tx: number, iface = "ether1"): MetricSample {
  return { at, cpu: 5, memUsed: 100, memTotal: 200, ifaces: { [iface]: { rx, tx } } };
}

describe("MetricsStore", () => {
  it("persists samples and reloads them from disk", () => {
    const file = path.join(tempDir(), "metrics.jsonl");
    const now = Date.now();
    const a = new MetricsStore(file);
    a.record("HEX1", sample(now - 2000, 100, 50));
    a.record("HEX1", sample(now - 1000, 300, 150));
    a.record("HEX2", sample(now - 1500, 10, 5));

    const b = new MetricsStore(file);
    expect(b.samples("HEX1")).toHaveLength(2);
    expect(b.samples("HEX2")).toHaveLength(1);
    expect(b.samples("HEX1")[1].ifaces.ether1.rx).toBe(300);
  });

  it("prunes samples older than the retention window on load", () => {
    const file = path.join(tempDir(), "metrics.jsonl");
    const store = new MetricsStore(file, 3600_000); // 1h retention
    const now = Date.now();
    store.record("HEX1", sample(now - 2 * 3600_000, 1, 1)); // 2h old — should be dropped
    store.record("HEX1", sample(now - 60_000, 2, 2)); // fresh

    const reloaded = new MetricsStore(file, 3600_000);
    expect(reloaded.samples("HEX1")).toHaveLength(1);
    expect(reloaded.samples("HEX1")[0].ifaces.ether1.rx).toBe(2);
  });

  it("compaction rewrites the file dropping expired rows", () => {
    const file = path.join(tempDir(), "metrics.jsonl");
    const store = new MetricsStore(file, 3600_000);
    const now = Date.now();
    store.record("HEX1", sample(now - 30_000, 5, 5));
    store.compact();
    const lines = fs.readFileSync(file, "utf8").trim().split("\n").filter(Boolean);
    expect(lines).toHaveLength(1);
  });
});

describe("computeTraffic", () => {
  it("computes bits/sec from cumulative counters", () => {
    // +125000 bytes over 10s = 1,250,000 bytes/s * 8 = 100,000 bps? no: 125000*8/10 = 100000
    const samples = [sample(0, 0, 0), sample(10_000, 125_000, 62_500)];
    const t = computeTraffic(samples, 300);
    expect(t.series.ether1).toHaveLength(1);
    expect(t.series.ether1[0].rx).toBeCloseTo(100_000, 0);
    expect(t.series.ether1[0].tx).toBeCloseTo(50_000, 0);
    expect(t.totals.ether1).toEqual({ rx: 125_000, tx: 62_500 });
  });

  it("treats a counter reset as zero for that step, not a negative spike", () => {
    const samples = [sample(0, 1_000_000, 0), sample(10_000, 5_000, 0)]; // reboot
    const t = computeTraffic(samples, 300);
    expect(t.series.ether1[0].rx).toBe(0);
    expect(t.totals.ether1.rx).toBe(0);
  });

  it("breaks the series across an offline gap larger than 4x the sample interval", () => {
    // sampleSeconds=10 -> maxGap 40s. A 5-minute gap should be skipped.
    const samples = [sample(0, 0, 0), sample(300_000, 999_999, 0)];
    const t = computeTraffic(samples, 10);
    expect(t.series.ether1 ?? []).toHaveLength(0);
  });

  it("excludes named interfaces (e.g. the management tunnel)", () => {
    const s: MetricSample[] = [
      { at: 0, cpu: 0, memUsed: 0, memTotal: 0, ifaces: { ether1: { rx: 0, tx: 0 }, "wg-mgmt": { rx: 0, tx: 0 } } },
      { at: 10_000, cpu: 0, memUsed: 0, memTotal: 0, ifaces: { ether1: { rx: 100, tx: 0 }, "wg-mgmt": { rx: 9999, tx: 0 } } },
    ];
    const t = computeTraffic(s, 300, new Set(["wg-mgmt"]));
    expect(t.interfaces).toEqual(["ether1"]);
    expect(t.totals["wg-mgmt"]).toBeUndefined();
  });
});
