import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export interface NodePos {
  x: number;
  y: number;
}

export interface Link {
  id: string;
  /** Router ids at each end, and the interface on each. */
  a: string;
  aIface: string;
  b: string;
  bIface: string;
}

export interface GroupTopology {
  /** Router id -> canvas position. */
  nodes: Record<string, NodePos>;
  links: Link[];
}

function empty(): GroupTopology {
  return { nodes: {}, links: [] };
}

/**
 * Per-customer-group network map layout: device positions and the links
 * between them (with the interface on each end). Persisted as one JSON file
 * keyed by group name.
 */
export class TopologyStore {
  private groups: Record<string, GroupTopology> = {};

  constructor(private readonly filePath: string) {
    if (fs.existsSync(filePath)) {
      try {
        this.groups = JSON.parse(fs.readFileSync(filePath, "utf8"));
      } catch {
        this.groups = {};
      }
    }
  }

  private persist(): void {
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    const tmp = `${this.filePath}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(this.groups, null, 2));
    fs.renameSync(tmp, this.filePath);
  }

  get(group: string): GroupTopology {
    return this.groups[group] ?? empty();
  }

  /**
   * Replaces a group's layout. `validIds` restricts nodes/links to routers
   * actually in the group so stale references get pruned. Link ids are
   * assigned if missing.
   */
  set(group: string, topology: GroupTopology, validIds: Set<string>): GroupTopology {
    const nodes: Record<string, NodePos> = {};
    for (const [id, pos] of Object.entries(topology.nodes ?? {})) {
      if (validIds.has(id)) nodes[id] = { x: Math.round(pos.x), y: Math.round(pos.y) };
    }
    const links: Link[] = (topology.links ?? [])
      .filter((l) => validIds.has(l.a) && validIds.has(l.b) && l.a !== l.b)
      .map((l) => ({
        id: l.id || "lnk-" + crypto.randomBytes(6).toString("hex"),
        a: l.a,
        aIface: String(l.aIface ?? "").slice(0, 64),
        b: l.b,
        bIface: String(l.bIface ?? "").slice(0, 64),
      }));
    this.groups[group] = { nodes, links };
    this.persist();
    return this.groups[group];
  }

  /** Drop a router from every group's layout (used on remove/revoke cleanup). */
  removeRouter(id: string): void {
    let changed = false;
    for (const g of Object.values(this.groups)) {
      if (g.nodes[id]) {
        delete g.nodes[id];
        changed = true;
      }
      const before = g.links.length;
      g.links = g.links.filter((l) => l.a !== id && l.b !== id);
      if (g.links.length !== before) changed = true;
    }
    if (changed) this.persist();
  }
}
