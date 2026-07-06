import { describe, expect, it } from "vitest";
import { computeSla, mergeDuration } from "../src/sla.js";

const H = 3600_000;
const base = 1_700_000_000_000; // fixed epoch for determinism

describe("mergeDuration", () => {
  it("merges overlapping spans and sums coverage", () => {
    expect(mergeDuration([{ start: 0, end: 10 }, { start: 5, end: 15 }])).toBe(15);
    expect(mergeDuration([{ start: 0, end: 10 }, { start: 20, end: 25 }])).toBe(15);
    expect(mergeDuration([])).toBe(0);
  });
});

describe("computeSla", () => {
  it("100% with no outages", () => {
    const r = computeSla({ createdAt: base, from: base, to: base + 100 * H, outages: [], maintenance: [] });
    expect(r.uptimePct).toBe(100);
    expect(r.downMs).toBe(0);
  });

  it("counts unplanned downtime against a 100h window", () => {
    // 1h outage over 100h = 99% uptime
    const r = computeSla({
      createdAt: base, from: base, to: base + 100 * H,
      outages: [{ start: base + 10 * H, end: base + 11 * H }],
      maintenance: [],
    });
    expect(r.uptimePct).toBeCloseTo(99, 5);
    expect(r.outages).toBe(1);
    expect(r.longestMs).toBe(H);
  });

  it("excludes downtime that falls inside a maintenance window", () => {
    // 2h outage, but 1h of it is inside a maintenance window -> only 1h counts,
    // and that maintenance hour is also removed from the denominator.
    const r = computeSla({
      createdAt: base, from: base, to: base + 100 * H,
      outages: [{ start: base + 10 * H, end: base + 12 * H }],
      maintenance: [{ start: base + 10 * H, end: base + 11 * H }],
    });
    expect(r.downMs).toBe(H); // 1h unplanned
    expect(r.excludedMs).toBe(H); // 1h planned removed from denominator
    expect(r.uptimePct).toBeCloseTo((1 - H / (99 * H)) * 100, 5);
  });

  it("floors the period at the device's creation time", () => {
    // Device created 50h into the window; only the later 50h counts.
    const r = computeSla({
      createdAt: base + 50 * H, from: base, to: base + 100 * H,
      outages: [{ start: base + 60 * H, end: base + 61 * H }],
      maintenance: [],
    });
    expect(r.start).toBe(base + 50 * H);
    expect(r.periodMs).toBe(50 * H);
    expect(r.uptimePct).toBeCloseTo((1 - H / (50 * H)) * 100, 5);
  });
});
