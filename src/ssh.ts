import { Client } from "ssh2";

export interface SshResult {
  ok: boolean;
  output: string;
}

export type SshRunFn = (
  host: string,
  username: string,
  password: string,
  command: string,
  timeoutMs?: number,
) => Promise<SshResult>;

export type SftpPutFn = (
  host: string,
  username: string,
  password: string,
  content: Buffer,
  remotePath: string,
  timeoutMs?: number,
) => Promise<void>;

function connect(host: string, username: string, password: string, timeoutMs: number): Promise<Client> {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    const timer = setTimeout(() => {
      conn.end();
      reject(new Error("ssh connect timeout"));
    }, timeoutMs);
    conn
      .on("ready", () => {
        clearTimeout(timer);
        resolve(conn);
      })
      .on("error", (err) => {
        clearTimeout(timer);
        reject(err);
      })
      .connect({ host, username, password, readyTimeout: timeoutMs });
  });
}

/** Runs one command on a RouterOS device over SSH, capturing all output. */
export const sshRun: SshRunFn = async (host, username, password, command, timeoutMs = 20000) => {
  const conn = await connect(host, username, password, timeoutMs);
  try {
    return await new Promise<SshResult>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("ssh command timeout")), timeoutMs);
      conn.exec(command, (err, stream) => {
        if (err) {
          clearTimeout(timer);
          return reject(err);
        }
        let output = "";
        stream
          .on("data", (d: Buffer) => (output += d.toString()))
          .stderr.on("data", (d: Buffer) => (output += d.toString()));
        stream.on("close", (code: number | null) => {
          clearTimeout(timer);
          resolve({ ok: code === 0 || code === null, output: output.trim() });
        });
      });
    });
  } finally {
    conn.end();
  }
};

/** Uploads a file to the router (used to stage config restores). */
export const sftpPut: SftpPutFn = async (host, username, password, content, remotePath, timeoutMs = 20000) => {
  const conn = await connect(host, username, password, timeoutMs);
  try {
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("sftp timeout")), timeoutMs);
      conn.sftp((err, sftp) => {
        if (err) {
          clearTimeout(timer);
          return reject(err);
        }
        sftp.writeFile(remotePath, content, (werr) => {
          clearTimeout(timer);
          werr ? reject(werr) : resolve();
        });
      });
    });
  } finally {
    conn.end();
  }
};
