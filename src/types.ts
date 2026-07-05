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
}

export interface RegisterRequest {
  token: string;
  publicKey: string;
  serialNumber: string;
  boardName?: string;
  rosVersion?: string;
  identity?: string;
}
