import { describe, expect, it } from "vitest";
import { allocateIp, cidrContains, intToIp, ipToInt, parseCidr } from "../src/ipam.js";

describe("ipam", () => {
  it("round-trips ip <-> int", () => {
    for (const ip of ["0.0.0.0", "10.99.0.1", "192.168.1.254", "255.255.255.255"]) {
      expect(intToIp(ipToInt(ip))).toBe(ip);
    }
  });

  it("rejects malformed addresses", () => {
    expect(() => ipToInt("10.0.0")).toThrow();
    expect(() => ipToInt("10.0.0.256")).toThrow();
    expect(() => parseCidr("10.0.0.0/33")).toThrow();
  });

  it("skips network and broadcast addresses", () => {
    const c = parseCidr("10.99.0.0/24");
    expect(intToIp(c.first)).toBe("10.99.0.1");
    expect(intToIp(c.last)).toBe("10.99.0.254");
  });

  it("allocates the lowest free address, honouring used and reserved", () => {
    expect(allocateIp("10.99.0.0/24", [], ["10.99.0.1"])).toBe("10.99.0.2");
    expect(allocateIp("10.99.0.0/24", ["10.99.0.2", "10.99.0.3"], ["10.99.0.1"])).toBe("10.99.0.4");
  });

  it("throws when the pool is exhausted", () => {
    const used = ["10.0.0.1", "10.0.0.2"];
    expect(() => allocateIp("10.0.0.0/30", used)).toThrow(/exhausted/);
  });

  it("cidrContains", () => {
    expect(cidrContains("10.99.0.0/16", "10.99.42.7")).toBe(true);
    expect(cidrContains("10.99.0.0/16", "10.100.0.1")).toBe(false);
  });
});
