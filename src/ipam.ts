/** Minimal IPv4 address allocation within a management CIDR. */

export function ipToInt(ip: string): number {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) {
    throw new Error(`Invalid IPv4 address: ${ip}`);
  }
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

export function intToIp(n: number): string {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
}

export interface Cidr {
  base: number;
  prefix: number;
  first: number;
  last: number;
}

export function parseCidr(cidr: string): Cidr {
  const [ip, prefixStr] = cidr.split("/");
  const prefix = Number(prefixStr);
  if (!ip || Number.isNaN(prefix) || prefix < 0 || prefix > 32) {
    throw new Error(`Invalid CIDR: ${cidr}`);
  }
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const base = (ipToInt(ip) & mask) >>> 0;
  const size = 2 ** (32 - prefix);
  // Skip network and broadcast addresses for prefixes that have them.
  const first = prefix >= 31 ? base : base + 1;
  const last = prefix >= 31 ? base + size - 1 : base + size - 2;
  return { base, prefix, first, last };
}

export function cidrContains(cidr: string, ip: string): boolean {
  const c = parseCidr(cidr);
  const n = ipToInt(ip);
  return n >= c.first && n <= c.last;
}

/**
 * Returns the lowest free host address in `cidr` that is not in `used`
 * and not in `reserved`. Throws when the pool is exhausted.
 */
export function allocateIp(cidr: string, used: Iterable<string>, reserved: Iterable<string> = []): string {
  const c = parseCidr(cidr);
  const taken = new Set<number>();
  for (const ip of used) taken.add(ipToInt(ip));
  for (const ip of reserved) taken.add(ipToInt(ip));
  for (let n = c.first; n <= c.last; n++) {
    if (!taken.has(n)) return intToIp(n);
  }
  throw new Error(`IP pool exhausted for ${cidr}`);
}
