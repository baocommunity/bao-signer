-- bao-signer — PostgreSQL reference schema
--
-- Minimal schema for a production SignerStorage implementation.
-- The in-memory reference implementation (storage.ts) is dev-only.

CREATE TABLE IF NOT EXISTS accounts (
  pubkey          TEXT PRIMARY KEY,              -- 64-char hex Nostr pubkey
  nsec_hash       TEXT NOT NULL,                 -- sha256(nsec_hex); server never stores plaintext
  username        TEXT NOT NULL DEFAULT '',
  login_count     INTEGER NOT NULL DEFAULT 0,
  created_at      BIGINT NOT NULL,               -- unix seconds
  last_login_at   BIGINT
);

CREATE TABLE IF NOT EXISTS account_auth_methods (
  method          TEXT NOT NULL,                 -- 'passkey', 'nostr', 'lnurl', ...
  auth_id         TEXT NOT NULL,                 -- credential_id for passkeys
  pubkey          TEXT NOT NULL REFERENCES accounts(pubkey),
  verified        INTEGER NOT NULL DEFAULT 1,
  verified_at     BIGINT,
  created_at      BIGINT NOT NULL,
  last_used_at    BIGINT,
  deleted_at      BIGINT,                        -- soft delete
  PRIMARY KEY (method, auth_id)
);

CREATE INDEX IF NOT EXISTS idx_auth_methods_pubkey ON account_auth_methods(pubkey);

CREATE TABLE IF NOT EXISTS passkey_credentials (
  credential_id   TEXT PRIMARY KEY,
  pubkey          TEXT NOT NULL REFERENCES accounts(pubkey),
  public_key      TEXT NOT NULL,                 -- base64url COSE key
  counter         BIGINT NOT NULL DEFAULT 0,     -- replay prevention: never decrease
  transports      TEXT NOT NULL DEFAULT '[]',    -- JSON array
  name            TEXT NOT NULL DEFAULT '',
  is_prf          INTEGER NOT NULL DEFAULT 0,    -- 1 = PRF-derived identity (server never saw nsec)
  created_at      BIGINT NOT NULL,
  last_used_at    BIGINT
);

CREATE INDEX IF NOT EXISTS idx_passkey_credentials_pubkey ON passkey_credentials(pubkey);

CREATE TABLE IF NOT EXISTS sessions (
  token           TEXT PRIMARY KEY,
  pubkey          TEXT NOT NULL REFERENCES accounts(pubkey),
  user_agent      TEXT NOT NULL DEFAULT '',
  ip_address      TEXT NOT NULL DEFAULT '',
  created_at      BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM now())::bigint),
  expires_at      BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_pubkey ON sessions(pubkey);

-- WebAuthn counters can regress legitimately with synced passkeys (iCloud
-- Keychain, Google Password Manager). The reference route logs and tolerates
-- regressions while NEVER storing a lower counter:
--
--   UPDATE passkey_credentials SET counter = $2, last_used_at = $3
--   WHERE credential_id = $1 AND counter <= $2;
