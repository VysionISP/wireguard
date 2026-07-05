import { describe, expect, it } from "vitest";
import { interfaceRates, type Sample } from "../src/stream.js";

const iface = (name: string, rxByte: number, txByte: number) => ({
  name, type: "ether", running: true, rxByte, txByte,
});

describe("interfaceRates", () => {
  it("returns zero rates on the first sample", () => {
    const curr: Sample = { at: 1000, interfaces: [iface("ether1", 100, 200)] };
    const r = interfaceRates(null, curr);
    expect(r[0]).toMatchObject({ name: "ether1", rxBps: 0, txBps: 0 });
  });

  it("computes bits/sec from byte deltas over elapsed time", () => {
    const prev: Sample = { at: 0, interfaces: [iface("ether1", 0, 0)] };
    const curr: Sample = { at: 2000, interfaces: [iface("ether1", 250_000, 125_000)] };
    const r = interfaceRates(prev, curr);
    // 250000 bytes in 2s = 125000 B/s = 1,000,000 bits/s
    expect(r[0].rxBps).toBe(1_000_000);
    expect(r[0].txBps).toBe(500_000);
  });

  it("clamps counter resets (reboot) to zero instead of negative", () => {
    const prev: Sample = { at: 0, interfaces: [iface("ether1", 1_000_000, 1_000_000)] };
    const curr: Sample = { at: 1000, interfaces: [iface("ether1", 50, 50)] };
    const r = interfaceRates(prev, curr);
    expect(r[0].rxBps).toBe(0);
    expect(r[0].txBps).toBe(0);
  });

  it("handles new interfaces appearing between samples", () => {
    const prev: Sample = { at: 0, interfaces: [iface("ether1", 0, 0)] };
    const curr: Sample = { at: 1000, interfaces: [iface("ether1", 1000, 0), iface("ether2", 500, 0)] };
    const r = interfaceRates(prev, curr);
    expect(r.find((i) => i.name === "ether2")!.rxBps).toBe(0); // no prior sample
    expect(r.find((i) => i.name === "ether1")!.rxBps).toBe(8000);
  });
});
