/**
 * SignerStorage — persistence contract for the bao-signer server.
 *
 * The reference implementation (`MemorySignerStorage`) is suitable for
 * development and single-process deployments. Production deployments should
 * implement this interface over a real database (see `schema.sql` for a
 * PostgreSQL reference schema).
 *
 * Security notes:
 * - `updateCredentialCounter` is the WebAuthn replay-attack prevention
 *   mechanism. It MUST be durable and MUST NOT fail silently.
 * - `insertAccount`/`insertCredential` should tolerate conflicts idempotently
 *   (ON CONFLICT DO NOTHING semantics) — the routes perform explicit
 *   existence checks first.
 */

export interface StoredPasskeyCredential {
  credential_id: string;
  pubkey: string;
  /** Base64url-encoded COSE public key. */
  public_key: string;
  counter: number;
  /** JSON-encoded transports array. */
  transports?: string;
  /** 1 = PRF-derived identity (server never saw the nsec), 0 = server-generated. */
  is_prf: number;
}

export interface StoredAccount {
  pubkey: string;
  username: string;
}

export interface AccountInsert {
  pubkey: string;
  /** SHA-256 of the nsec hex (server-generated accounts) or "prf:<pubkey>" marker. */
  nsec_hash: string;
  username: string;
  now: number;
}

export interface AuthMethodInsert {
  method: string;
  authId: string;
  pubkey: string;
  now: number;
}

export interface CredentialInsert {
  credential_id: string;
  pubkey: string;
  public_key: string;
  counter: number;
  transports: string;
  name: string;
  now: number;
  is_prf: number;
}

export interface SessionMeta {
  userAgent: string;
  ipAddress: string;
  expiresAt: number;
}

export interface SignerStorage {
  getCredentialById(credentialId: string): Promise<StoredPasskeyCredential | undefined>;
  insertAccount(row: AccountInsert): Promise<void>;
  insertAuthMethod(row: AuthMethodInsert): Promise<void>;
  insertCredential(row: CredentialInsert): Promise<void>;
  updateCredentialCounter(credentialId: string, counter: number, now: number): Promise<void>;
  touchAuthMethod(method: string, authId: string, now: number): Promise<void>;
  updateAccountLastLogin(pubkey: string, now: number): Promise<void>;
  getAccount(pubkey: string): Promise<StoredAccount | undefined>;
  getAuthMethodsForPubkey(pubkey: string): Promise<Array<{ method: string }>>;
  storeSession(token: string, pubkey: string, meta: SessionMeta): Promise<void>;
  /** Run the given operations atomically. */
  withTransaction<T>(fn: () => Promise<T>): Promise<T>;
}

/**
 * In-memory reference implementation. NOT for multi-process production use:
 * data is lost on restart and not shared between replicas.
 */
export class MemorySignerStorage implements SignerStorage {
  private credentials = new Map<string, StoredPasskeyCredential>();
  private accounts = new Map<string, StoredAccount & { nsec_hash: string; last_login_at: number }>();
  private authMethods = new Map<string, { method: string; authId: string; pubkey: string; last_used_at: number }>();
  private sessions = new Map<string, { pubkey: string; meta: SessionMeta }>();

  async getCredentialById(credentialId: string) {
    return this.credentials.get(credentialId);
  }

  async insertAccount(row: AccountInsert): Promise<void> {
    if (this.accounts.has(row.pubkey)) return; // ON CONFLICT DO NOTHING
    this.accounts.set(row.pubkey, {
      pubkey: row.pubkey,
      username: row.username,
      nsec_hash: row.nsec_hash,
      last_login_at: row.now,
    });
  }

  async insertAuthMethod(row: AuthMethodInsert): Promise<void> {
    const key = `${row.method}:${row.authId}`;
    if (this.authMethods.has(key)) return;
    this.authMethods.set(key, { method: row.method, authId: row.authId, pubkey: row.pubkey, last_used_at: row.now });
  }

  async insertCredential(row: CredentialInsert): Promise<void> {
    if (this.credentials.has(row.credential_id)) return;
    this.credentials.set(row.credential_id, {
      credential_id: row.credential_id,
      pubkey: row.pubkey,
      public_key: row.public_key,
      counter: row.counter,
      transports: row.transports,
      is_prf: row.is_prf,
    });
  }

  async updateCredentialCounter(credentialId: string, counter: number, _now: number): Promise<void> {
    const cred = this.credentials.get(credentialId);
    if (!cred) throw new Error(`updateCredentialCounter: unknown credential ${credentialId}`);
    cred.counter = counter;
  }

  async touchAuthMethod(method: string, authId: string, now: number): Promise<void> {
    const row = this.authMethods.get(`${method}:${authId}`);
    if (row) row.last_used_at = now;
  }

  async updateAccountLastLogin(pubkey: string, now: number): Promise<void> {
    const account = this.accounts.get(pubkey);
    if (account) account.last_login_at = now;
  }

  async getAccount(pubkey: string) {
    const account = this.accounts.get(pubkey);
    return account ? { pubkey: account.pubkey, username: account.username } : undefined;
  }

  async getAuthMethodsForPubkey(pubkey: string) {
    return [...this.authMethods.values()]
      .filter((m) => m.pubkey === pubkey)
      .map((m) => ({ method: m.method }));
  }

  async storeSession(token: string, pubkey: string, meta: SessionMeta): Promise<void> {
    this.sessions.set(token, { pubkey, meta });
  }

  /** Resolve a session token (used by the default authenticate hook). */
  async getSession(token: string): Promise<{ pubkey: string; meta: SessionMeta } | undefined> {
    const row = this.sessions.get(token);
    if (!row) return undefined;
    if (row.meta.expiresAt < Math.floor(Date.now() / 1000)) {
      this.sessions.delete(token);
      return undefined;
    }
    return row;
  }

  async withTransaction<T>(fn: () => Promise<T>): Promise<T> {
    // Single-process memory store: operations are already effectively atomic.
    return fn();
  }
}
