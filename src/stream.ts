import type { LiveInterface } from "./routeros.js";

export interface RatedInterface extends LiveInterface {
  /** Bits per second since the previous sample (0 on the first sample). */
  rxBps: number;
  txBps: number;
}

export interface Sample {
  at: number; // epoch ms
  interfaces: LiveInterface[];
}

/**
 * Computes per-interface throughput (bits/sec) from two cumulative
 * byte-counter samples. Returns zeroes on the first sample or when a
 * counter resets (e.g. router reboot) so we never show a negative or absurd
 * spike.
 */
export function interfaceRates(prev: Sample | null, curr: Sample): RatedInterface[] {
  const prevBy = prev ? new Map(prev.interfaces.map((i) => [i.name, i])) : null;
  const dt = prev ? Math.max(0.001, (curr.at - prev.at) / 1000) : 0;
  return curr.interfaces.map((i) => {
    let rxBps = 0;
    let txBps = 0;
    const p = prevBy?.get(i.name);
    if (p && dt > 0) {
      rxBps = i.rxByte >= p.rxByte ? ((i.rxByte - p.rxByte) * 8) / dt : 0;
      txBps = i.txByte >= p.txByte ? ((i.txByte - p.txByte) * 8) / dt : 0;
    }
    return { ...i, rxBps, txBps };
  });
}
