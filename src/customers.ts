import fs from "node:fs";
import path from "node:path";

export interface Customer {
  /** Name is the identity — devices reference it via customerGroup. */
  name: string;
  contact: string;
  phone: string;
  email: string;
  address: string;
  notes: string;
  createdAt: string;
  updatedAt: string;
}

export type CustomerFields = Partial<Omit<Customer, "name" | "createdAt" | "updatedAt">>;

/** Customer records (contact details) keyed by name; the map + device grouping key on the same name. */
export class CustomerStore {
  private customers = new Map<string, Customer>();

  constructor(private readonly filePath: string) {
    if (fs.existsSync(filePath)) {
      try {
        const arr = JSON.parse(fs.readFileSync(filePath, "utf8")) as Customer[];
        this.customers = new Map(arr.map((c) => [c.name, c]));
      } catch {
        this.customers = new Map();
      }
    }
  }

  private persist(): void {
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    const tmp = `${this.filePath}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify([...this.customers.values()], null, 2));
    fs.renameSync(tmp, this.filePath);
  }

  list(): Customer[] {
    return [...this.customers.values()].sort((a, b) => a.name.localeCompare(b.name));
  }

  get(name: string): Customer | undefined {
    return this.customers.get(name);
  }

  has(name: string): boolean {
    return this.customers.has(name);
  }

  /** Create or update a customer's details. Name is the key. */
  upsert(name: string, fields: CustomerFields): Customer {
    const now = new Date().toISOString();
    const existing = this.customers.get(name);
    const c: Customer = {
      name,
      contact: fields.contact ?? existing?.contact ?? "",
      phone: fields.phone ?? existing?.phone ?? "",
      email: fields.email ?? existing?.email ?? "",
      address: fields.address ?? existing?.address ?? "",
      notes: fields.notes ?? existing?.notes ?? "",
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
    };
    this.customers.set(name, c);
    this.persist();
    return c;
  }

  delete(name: string): boolean {
    if (!this.customers.delete(name)) return false;
    this.persist();
    return true;
  }
}
