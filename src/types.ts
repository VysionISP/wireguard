export type RouterState = "registered" | "confirmed" | "verified" | "revoked";

export interface RouterRecord {
  /** Stable internal id (uuid). */
  id: string;
  /** RouterBOARD serial number — the zero-touch identity of the device. */
  serialNumber: string;
  /** Current WireGuard public key of the router. */
  publicKey: string;
  boardName: string;
  rosVersion: string;
  identity: string;
  /** Management IP allocated inside the WireGuard tunnel subnet. */
  tunnelIp: string;
  /** Management credentials created on the router during provisioning. */
  username: string;
  password: string;
  state: RouterState;
  createdAt: string;
  updatedAt: string;
  lastSeenAt: string | null;
  /** Operator-set friendly name (customer, site…). Absent on old records. */
  label?: string;
  /** Operator notes. Absent on old records. */
  notes?: string;
  /** Last online/offline verdict from the monitor; undefined until first tick. */
  lastOnline?: boolean;
  /** Recent online/offline transitions (bounded), newest last. */
  transitions?: Array<{ at: string; online: boolean }>;
  /** When the router last pushed a config backup that we stored or matched. */
  lastBackupAt?: string | null;
}

export interface RegisterRequest {
  token: string;
  publicKey: string;
  serialNumber: string;
  boardName?: string;
  rosVersion?: string;
  identity?: string;
}
