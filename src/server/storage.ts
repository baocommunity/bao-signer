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
 * - OTP codes are stored HASHED (sha256). Never store plaintext codes.
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
  /** SHA-256 of the nsec hex (server-generated accounts) or a marker hash. */
  nsec_hash: string;
  username: string;
  now: number;
  npub?: string;
  nostr_only_mode?: number;
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

/* ── LNURL-auth ─────────────────────────────────────────────── */

export interface LnurlChallengeRow {
  k1: string;
  created_at: number;
  expires_at: number;
  authenticated: boolean;
  linking_key?: string;
  resolved_pubkey?: string;
  is_new_account?: number;
  session_token_hash?: string;
}

/* ── Email OTP ──────────────────────────────────────────────── */

export interface EmailAccountRow {
  email_hash: string;
  pubkey: string;
  username: string;
  encrypted_nsec?: string;
  nsec_salt?: string;
  nsec_iv?: string;
}

/* ── Telegram OIDC ──────────────────────────────────────────── */

export interface OidcChallengeRow {
  state: string;
  code_verifier: string;
  created_at: number;
  expires_at: number;
  authenticated: boolean;
  auth_id?: string;
  resolved_pubkey?: string;
  is_new_account?: number;
}

/* ── The storage contract ───────────────────────────────────── */

export interface SignerStorage {
  /* accounts + passkeys */
  getCredentialById(credentialId: string): Promise<StoredPasskeyCredential | undefined>;
  insertAccount(row: AccountInsert): Promise<void>;
  upsertAccount(row: AccountInsert): Promise<void>;
  insertAuthMethod(row: AuthMethodInsert): Promise<void>;
  /**
   * Insert an auth method only if the (method, authId) pair is absent.
   * Returns true when this call performed the insert (i.e. this caller
   * "won" the claim). Find-or-create flows use this as their idempotency
   * gate so concurrent first logins cannot mint two identities for the
   * same auth id.
   */
  insertAuthMethodIfAbsent(row: AuthMethodInsert): Promise<boolean>;
  insertCredential(row: CredentialInsert): Promise<void>;
  updateCredentialCounter(credentialId: string, counter: number, now: number): Promise<void>;
  touchAuthMethod(method: string, authId: string, now: number): Promise<void>;
  updateAccountLastLogin(pubkey: string, now: number): Promise<void>;
  getAccount(pubkey: string): Promise<StoredAccount | undefined>;
  getAuthMethodsForPubkey(pubkey: string): Promise<Array<{ method: string }>>;
  findAuthMethod(method: string, authId: string): Promise<{ pubkey: string } | undefined>;
  storeSession(token: string, pubkey: string, meta: SessionMeta): Promise<void>;
  /** Run the given operations atomically. */
  withTransaction<T>(fn: () => Promise<T>): Promise<T>;

  /* LNURL-auth challenges */
  lnurlInsertChallenge(k1: string, now: number, expiresAt: number): Promise<void>;
  lnurlGetChallenge(k1: string): Promise<LnurlChallengeRow | undefined>;
  lnurlMarkAuthenticated(
    k1: string,
    result: { linkingKey: string; pubkey: string; isNewAccount: boolean; sessionTokenHash: string },
  ): Promise<void>;
  lnurlDeleteChallenge(k1: string): Promise<void>;

  /* email OTP */
  emailCountRecentOtps(emailHash: string, since: number): Promise<number>;
  emailInsertOtp(codeHash: string, emailHash: string, expiresAt: number): Promise<void>;
  emailGetValidOtp(codeHash: string, emailHash: string, now: number): Promise<{ email_hash: string } | undefined>;
  emailMarkOtpUsed(codeHash: string): Promise<void>;
  /** Delete ALL outstanding OTPs for an email (lockout / post-success hygiene). Returns count removed. */
  emailDeleteOtpsForEmail(emailHash: string): Promise<number>;
  emailGetAccount(emailHash: string): Promise<EmailAccountRow | undefined>;
  emailInsertAccount(row: EmailAccountRow): Promise<boolean>;
  emailUpdateEncryptedNsec(emailHash: string, ciphertext: string, salt: string, iv: string): Promise<void>;

  /* telegram OIDC challenges */
  tgInsertChallenge(state: string, codeVerifier: string, now: number, expiresAt: number): Promise<void>;
  tgGetChallenge(state: string): Promise<OidcChallengeRow | undefined>;
  tgMarkAuthenticated(state: string, result: { authId: string; pubkey: string; isNewAccount: boolean }): Promise<void>;
  /** Atomically consume an authenticated challenge (prevents duplicate sessions). */
  tgConsumeAuthenticated(state: string): Promise<OidcChallengeRow | undefined>;
  tgDeleteChallenge(state: string): Promise<void>;
  tgDeleteExpired(now: number): Promise<void>;
}

/**
 * In-memory reference implementation. NOT for multi-process production use:
 * data is lost on restart and not shared between replicas.
 */
export class MemorySignerStorage implements SignerStorage {
  private credentials = new Map<string, StoredPasskeyCredential>();
  private accounts = new Map<string, StoredAccount & { nsec_hash: string; last_login_at: number; npub: string; nostr_only_mode: number }>();
  private authMethods = new Map<string, { method: string; authId: string; pubkey: string; last_used_at: number }>();
  private sessions = new Map<string, { pubkey: string; meta: SessionMeta }>();
  private lnurlChallenges = new Map<string, LnurlChallengeRow>();
  private emailAccounts = new Map<string, EmailAccountRow>();
  private otpTokens = new Map<string, { codeHash: string; emailHash: string; expiresAt: number; used: boolean; createdAt: number }>();
  private oidcChallenges = new Map<string, OidcChallengeRow>();

  /* ── accounts + passkeys ── */

  async getCredentialById(credentialId: string) {
    return this.credentials.get(credentialId);
  }

  async insertAccount(row: AccountInsert): Promise<void> {
    if (this.accounts.has(row.pubkey)) return; // ON CONFLICT DO NOTHING
    this.accounts.set(row.pubkey, {
      pubkey: row.pubkey,
      username: row.username,
      nsec_hash: row.nsec_hash,
      npub: row.npub ?? '',
      nostr_only_mode: row.nostr_only_mode ?? 0,
      last_login_at: row.now,
    });
  }

  async upsertAccount(row: AccountInsert): Promise<void> {
    const existing = this.accounts.get(row.pubkey);
    if (existing) {
      existing.last_login_at = row.now;
      // npub is deterministic from the pubkey — always safe to fill/refresh.
      if (row.npub) existing.npub = row.npub;
      // nostr-only is monotonic: once 1 (server never held the nsec), never
      // downgrade it on a later guest-style login.
      if (row.nostr_only_mode === 1) existing.nostr_only_mode = 1;
      return;
    }
    await this.insertAccount(row);
  }

  async insertAuthMethodIfAbsent(row: AuthMethodInsert): Promise<boolean> {
    const key = `${row.method}:${row.authId}`;
    if (this.authMethods.has(key)) return false;
    this.authMethods.set(key, { method: row.method, authId: row.authId, pubkey: row.pubkey, last_used_at: row.now });
    return true;
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

  async findAuthMethod(method: string, authId: string) {
    const row = this.authMethods.get(`${method}:${authId}`);
    return row ? { pubkey: row.pubkey } : undefined;
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

  /* ── LNURL-auth ── */

  async lnurlInsertChallenge(k1: string, now: number, expiresAt: number): Promise<void> {
    this.lnurlChallenges.set(k1, { k1, created_at: now, expires_at: expiresAt, authenticated: false });
  }

  async lnurlGetChallenge(k1: string) {
    return this.lnurlChallenges.get(k1);
  }

  async lnurlMarkAuthenticated(
    k1: string,
    result: { linkingKey: string; pubkey: string; isNewAccount: boolean; sessionTokenHash: string },
  ): Promise<void> {
    const row = this.lnurlChallenges.get(k1);
    if (!row) throw new Error(`lnurlMarkAuthenticated: unknown k1 ${k1}`);
    row.authenticated = true;
    row.linking_key = result.linkingKey;
    row.resolved_pubkey = result.pubkey;
    row.is_new_account = result.isNewAccount ? 1 : 0;
    row.session_token_hash = result.sessionTokenHash;
  }

  async lnurlDeleteChallenge(k1: string): Promise<void> {
    this.lnurlChallenges.delete(k1);
  }

  /* ── email OTP ── */

  async emailCountRecentOtps(emailHash: string, since: number): Promise<number> {
    return [...this.otpTokens.values()].filter(
      (t) => t.emailHash === emailHash && t.createdAt >= since,
    ).length;
  }

  async emailInsertOtp(codeHash: string, emailHash: string, expiresAt: number): Promise<void> {
    this.otpTokens.set(codeHash, { codeHash, emailHash, expiresAt, used: false, createdAt: Math.floor(Date.now() / 1000) });
  }

  async emailGetValidOtp(codeHash: string, emailHash: string, now: number) {
    const row = this.otpTokens.get(codeHash);
    if (!row || row.used || row.emailHash !== emailHash || row.expiresAt < now) return undefined;
    return { email_hash: row.emailHash };
  }

  async emailMarkOtpUsed(codeHash: string): Promise<void> {
    const row = this.otpTokens.get(codeHash);
    if (row) row.used = true;
  }

  async emailDeleteOtpsForEmail(emailHash: string): Promise<number> {
    let removed = 0;
    for (const [codeHash, row] of this.otpTokens) {
      if (row.emailHash === emailHash) {
        this.otpTokens.delete(codeHash);
        removed++;
      }
    }
    return removed;
  }

  async emailGetAccount(emailHash: string) {
    return this.emailAccounts.get(emailHash);
  }

  /** Returns true if inserted, false if the email already had an account. */
  async emailInsertAccount(row: EmailAccountRow): Promise<boolean> {
    if (this.emailAccounts.has(row.email_hash)) return false;
    this.emailAccounts.set(row.email_hash, { ...row });
    return true;
  }

  async emailUpdateEncryptedNsec(emailHash: string, ciphertext: string, salt: string, iv: string): Promise<void> {
    const row = this.emailAccounts.get(emailHash);
    if (row) {
      row.encrypted_nsec = ciphertext;
      row.nsec_salt = salt;
      row.nsec_iv = iv;
    }
  }

  /* ── telegram OIDC ── */

  async tgInsertChallenge(state: string, codeVerifier: string, now: number, expiresAt: number): Promise<void> {
    this.oidcChallenges.set(state, { state, code_verifier: codeVerifier, created_at: now, expires_at: expiresAt, authenticated: false });
  }

  async tgGetChallenge(state: string) {
    return this.oidcChallenges.get(state);
  }

  async tgMarkAuthenticated(state: string, result: { authId: string; pubkey: string; isNewAccount: boolean }): Promise<void> {
    const row = this.oidcChallenges.get(state);
    if (!row) throw new Error(`tgMarkAuthenticated: unknown state ${state}`);
    row.authenticated = true;
    row.auth_id = result.authId;
    row.resolved_pubkey = result.pubkey;
    row.is_new_account = result.isNewAccount ? 1 : 0;
  }

  async tgConsumeAuthenticated(state: string) {
    const row = this.oidcChallenges.get(state);
    if (!row || !row.authenticated) return undefined;
    this.oidcChallenges.delete(state); // atomic consume
    return row;
  }

  async tgDeleteChallenge(state: string): Promise<void> {
    this.oidcChallenges.delete(state);
  }

  async tgDeleteExpired(now: number): Promise<void> {
    for (const [state, row] of this.oidcChallenges) {
      if (row.expires_at < now) this.oidcChallenges.delete(state);
    }
  }
}
