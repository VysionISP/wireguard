import { describe, expect, it } from "vitest";
import { BackupStore } from "../src/backups.js";
import { tempDir } from "./helpers.js";

describe("BackupStore", () => {
  it("stores a new version only when content changed", async () => {
    const store = new BackupStore(tempDir(), 30);
    const first = store.saveIfChanged("HEX1", Buffer.from("# config v1"));
    expect(first.stored).toBe(true);

    const dup = store.saveIfChanged("HEX1", Buffer.from("# config v1"));
    expect(dup.stored).toBe(false);
    expect(store.list("HEX1")).toHaveLength(1);

    await new Promise((r) => setTimeout(r, 5)); // distinct timestamp filename
    const changed = store.saveIfChanged("HEX1", Buffer.from("# config v2"));
    expect(changed.stored).toBe(true);
    expect(store.list("HEX1")).toHaveLength(2);
    // newest first
    expect(store.read("HEX1", store.list("HEX1")[0].name)!.toString()).toBe("# config v2");
  });

  it("prunes old versions beyond the keep limit", async () => {
    const store = new BackupStore(tempDir(), 2);
    for (let i = 0; i < 4; i++) {
      store.saveIfChanged("HEX2", Buffer.from(`# config v${i}`));
      await new Promise((r) => setTimeout(r, 5));
    }
    const kept = store.list("HEX2");
    expect(kept).toHaveLength(2);
    expect(store.read("HEX2", kept[0].name)!.toString()).toBe("# config v3");
  });

  it("refuses path traversal in serials and names", () => {
    const store = new BackupStore(tempDir(), 5);
    expect(() => store.saveIfChanged("../evil", Buffer.from("x"))).toThrow(/unsafe/);
    expect(store.read("HEX3", "../../etc/passwd")).toBeNull();
  });
});
