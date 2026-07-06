/** Interval math for SLA/uptime, kept pure so it's easy to test. */

export interface Span {
  start: number;
  end: number;
}

/** Merge overlapping/adjacent spans and return the total covered milliseconds. */
export function mergeDuration(spans: Span[]): number {
  const sorted = spans.filter((s) => s.end > s.start).sort((a, b) => a.start - b.start);
  let total = 0;
  let curStart = 0;
  let curEnd = 0;
  let have = false;
  for (const s of sorted) {
    if (!have) {
      curStart = s.start;
      curEnd = s.end;
      have = true;
    } else if (s.start <= curEnd) {
      curEnd = Math.max(curEnd, s.end);
    } else {
      total += curEnd - curStart;
      curStart = s.start;
      curEnd = s.end;
    }
  }
  if (have) total += curEnd - curStart;
  return total;
}

export interface SlaInput {
  /** Device existed from here — the period floor (registration time). */
  createdAt: number;
  from: number;
  to: number;
  /** Outage spans (open outages should pass end = to). */
  outages: Span[];
  /** Maintenance spans that exclude downtime (offline-covering windows). */
  maintenance: Span[];
}

export interface SlaResult {
  /** Effective period start (max of from and createdAt). */
  start: number;
  periodMs: number;
  /** Planned-maintenance time excluded from the denominator. */
  excludedMs: number;
  /** Unplanned downtime (outage minus maintenance overlap). */
  downMs: number;
  /** periodMs - excludedMs. */
  effectiveMs: number;
  uptimePct: number;
  outages: number;
  longestMs: number;
}

/**
 * Uptime for one device: unplanned downtime over the period, with planned
 * maintenance removed from both the downtime and the denominator so a window
 * neither helps nor hurts the number.
 */
export function computeSla(i: SlaInput): SlaResult {
  const start = Math.max(i.from, i.createdAt);
  const period: Span = { start, end: i.to };
  const periodMs = Math.max(0, i.to - start);

  const maintClipped = i.maintenance
    .map((m) => ({ start: Math.max(m.start, start), end: Math.min(m.end, i.to) }))
    .filter((m) => m.end > m.start);
  const excludedMs = mergeDuration(maintClipped);

  let downMs = 0;
  let longestMs = 0;
  let count = 0;
  for (const o of i.outages) {
    const clipped: Span = { start: Math.max(o.start, start), end: Math.min(o.end, i.to) };
    if (clipped.end <= clipped.start) continue;
    // Subtract the maintenance covered by this outage. Clip each window to the
    // outage and MERGE before summing, so two overlapping windows (e.g. a
    // fleet-wide + a device-specific one) aren't double-counted.
    const maintInOutage = maintClipped
      .map((m) => ({ start: Math.max(m.start, clipped.start), end: Math.min(m.end, clipped.end) }))
      .filter((m) => m.end > m.start);
    let dur = clipped.end - clipped.start - mergeDuration(maintInOutage);
    dur = Math.max(0, dur);
    if (dur === 0) continue;
    downMs += dur;
    longestMs = Math.max(longestMs, dur);
    count++;
  }

  const effectiveMs = Math.max(0, periodMs - excludedMs);
  const uptimePct = effectiveMs > 0 ? Math.max(0, (1 - downMs / effectiveMs) * 100) : 100;
  return { start, periodMs, excludedMs, downMs, effectiveMs, uptimePct, outages: count, longestMs };
}
