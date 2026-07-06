import { describe, expect, it } from "vitest";
import { rosTimeToMs } from "../src/routeros.js";

describe("rosTimeToMs", () => {
  it("parses compound RouterOS durations to milliseconds", () => {
    expect(rosTimeToMs("15ms473us")).toBeCloseTo(15.473, 3);
    expect(rosTimeToMs("473us")).toBeCloseTo(0.473, 3);
    expect(rosTimeToMs("1s200ms")).toBeCloseTo(1200, 3);
    expect(rosTimeToMs("2ms")).toBe(2);
    expect(rosTimeToMs("800ns")).toBeCloseTo(0.0008, 4);
  });

  it("handles a bare number (assumed ms) and empty input", () => {
    expect(rosTimeToMs("15")).toBe(15);
    expect(rosTimeToMs("")).toBeNull();
    expect(rosTimeToMs(undefined)).toBeNull();
  });

  it("does not concatenate digits across units (the 15473 bug)", () => {
    // Regression: "15ms473us" must be ~15.5ms, never 15473ms.
    expect(rosTimeToMs("15ms473us")).toBeLessThan(20);
  });
});
