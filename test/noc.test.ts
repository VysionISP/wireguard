import { beforeEach, describe, expect, it } from "vitest";
import request from "supertest";
import { buildApp } from "../src/server.js";
import { RouterStore } from "../src/store.js";
import { DryRunManager } from "../src/wireguard.js";
import { testConfig } from "./helpers.js";
import type { Config } from "../src/config.js";

let cfg: Config;
let app: ReturnType<typeof buildApp>;

beforeEach(() => {
  cfg = testConfig();
  app = buildApp({ config: cfg, store: new RouterStore(cfg.storePath), wg: new DryRunManager("wg0", true) });
});

describe("NOC wallboard", () => {
  it("serves the wallboard page", async () => {
    const res = await request(app).get("/noc");
    expect(res.status).toBe(200);
    expect(res.text).toContain("KORVIX");
    expect(res.text).toContain("/api/noc/stream");
  });

  it("the NOC stream refuses an unauthenticated client", async () => {
    const res = await request(app).get("/api/noc/stream");
    expect(res.status).toBe(401);
  });
});
