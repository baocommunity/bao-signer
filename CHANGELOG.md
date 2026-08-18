# Changelog

## 0.4.0 — unified GUI login module (BaoLoginPanel) + canonical seed math

The whole point of the package: ONE login module, every app, same UX.

- **`bao-signer/ui` → `<BaoLoginPanel>`** (React, peer-optional): the drop-in
  unified login GUI — extension (approval-popup, gesture-safe) / passkey /
  NIP-46 remote signer (bunker://) / collapsed key-paste recovery, and
  registration with FORCED backup (download-gated entry, paper path that
  keeps the reminder pending). Themeable via `--bao-*` CSS variables with
  newspaper defaults.
- **`seedIdentity`** — the canonical BIP-39 identity math (was duplicated in
  apps): 24-word 256-bit default, `baofund:identity:v1` domain preserved for
  cross-app parity, validated-scalar derivation, `createSeedIdentitySigner`.
- **`loginFlowMachine`** — the login UX as a pure framework-free state
  machine (the panel's testable brain; usable by non-React shells).

139/139 tests incl. the cross-app parity vector, tsc clean, dist build with
`./ui` export.

## 0.3.0 — shared login module: NIP-07 popup connect + NIP-46 remote signer

The login UX every BAO app shares, now in one public module:

- **`nip07`** — browser-extension connect ported from bao.markets'
  battle-tested flow: synchronous shape check (preserves the user gesture so
  the extension's approval POPUP actually opens), session-cached pubkey
  (hooks re-running never re-prompt), cached denial with `{ force: true }`
  retry, and an honest timeout ("check the extension popup") instead of a
  silent hang. `connectNip07Signer()` returns the standard signer shape
  (signEvent + optional nip44 pass-through).
- **`nip46`** — NIP-46 (Nostr Connect) remote-signer client, decoupled port
  of bao.markets' Nip46Client: NIP-44 only, response signature verification,
  expected-pubkey pinning, remote-event shape + Schnorr verification,
  bunker:// URL validation (npub + hex, relay URL credential stripping).
  `connectNip46Signer(bunkerUrl)` returns the same signer shape — apps swap
  extension / passkey / seed / remote without code changes.

126/126 tests (new nip07 + nip46 suites), tsc clean, dist build.

## 0.2.0 — pre-public-release security audit (two independent sessions)

Two independent audit sessions reviewed every file under `src/` (client +
server) before the first public release. Findings and fixes:

### Fixed

- **`nativePasskey`: PRF extraction from raw credentials.** `extractPrfSeed`
  read the `clientExtensionResults` *property* off a raw
  `PublicKeyCredential`, which only exposes results via the
  `getClientExtensionResults()` *method* — extraction always returned null,
  forcing a needless second authenticator prompt on every registration and
  failing registration entirely if that prompt was cancelled. Both shapes
  are now supported (`extractPrfSeed` is exported for consumers driving
  `navigator.credentials` directly).
- **`nativePasskey`: honest unlock errors.** User-cancel / timeout
  (`NotAllowedError` / `AbortError`) was swallowed and misreported as
  "PRF is not available on this authenticator". Cancellation now
  propagates distinctly (`isCancelError` exported).
- **`keyStorage`: versioned vault format.** Blobs are now
  `v2i{iterations}:` + base64(salt(32) ‖ iv(12) ‖ ciphertext) at 256k
  PBKDF2-SHA256 iterations — the iteration count is encoded in the blob so
  future parameter changes can never brick stored keys. Legacy v0 blobs
  (unprefixed, 16-byte salt, 250k) still decrypt.

### Verified (no action needed)

- NIP-44 is spec-compliant everywhere (`nostr-tools`
  `nip44.v2.utils.getConversationKey`); the bespoke ECDH
  `deriveBaoConversationKey` remains exported but `@deprecated` for
  legacy-data compatibility only.
- Derivation parity with bao.markets is byte-exact: `bao/<baoId>/<index>`
  HMAC-SHA256 per-community keys, `bao:nostr:v1:` PRF→Nostr derivation,
  `bao:prf:v1` WebAuthn salts.
- PRF-derived keys are scalar-validated (`ensureValidSecp256k1Scalar`) —
  the bao.markets equivalent can throw on the (astronomically rare)
  invalid-scalar edge case.
- Server: relay backup key derivation fails closed without an HMAC
  secret; the hold/consume nsec manager is TTL-bound (30 min) and
  one-shot; NIP-98 challenge binding verified.

### Second-session findings (also fixed)

- **HIGH — `/auth/email/register` email pre-hijack.** The endpoint bound any
  email to any caller-supplied nsec with zero proof of inbox ownership; a
  victim's later OTP login would have issued a session for the attacker's
  pubkey. Binding now requires a valid OTP for that inbox (idempotent
  same-key re-register stays code-free — the nsec itself proves control).
- **HIGH — flagship flow couldn't complete against the reference server.**
  The server rejects anonymous PRF registration
  (`PRF_ACCOUNT_LINK_REQUIRES_AUTH`) but the client had no functions for the
  authenticated `/auth/link/passkey/*` endpoints. Added
  `linkPasskeyOptions` / `linkPasskeyRegister` / `linkBreezPasskey`
  (Bearer-auth full flow: options → PRF-injected create → derive → link).
- **MED — LNURL poll minted a fresh session when the held token was gone.**
  Double-mint is now impossible: poll in the restart window fails 410
  (`LNURL_SESSION_CONSUMED`); the challenge is consumed atomically.
- **MED — email OTP brute-force window.** Added per-email failure lockout
  (10 failures invalidate ALL outstanding codes) and sibling-code deletion
  on success; dev OTP logging trimmed to 2 digits.
- **MED — package published raw `.ts` sources.** Now ships `dist/` (JS +
  `.d.ts`) via `tsc -p tsconfig.build.json`
  (`rewriteRelativeImportExtensions`); `exports` points at `dist`;
  `prepublishOnly` builds.
- **MED — trusted blob-embedded PBKDF2 iteration count.** A tampered
  `v2i{n}:` blob could hang or weaken the KDF; counts outside
  100k–10M now fail closed.
- **LOW — storage-prefix inconsistency.** `nativePasskeyAuth` and
  `quickStart` keys now derive from the shared configurable prefixes
  (`nativePasskeyStorageKey` / `keyStorageKey`), evaluated at call time;
  default-prefix names unchanged (existing enrollments unaffected).
- **LOW — Telegram `auth_date` future timestamps** rejected via absolute
  window; **LNURL high-S signatures** accepted (`lowS: false` — wallet
  interop); **NIP-98 `/bao-api` path strip** is now an option
  (`pathPrefixStrip`).

### Tests

108/108 — including regression tests for every finding
(`tests/client/nativePasskey.test.ts`, `tests/client/keyStorage.test.ts`,
`tests/client/linkPasskey.test.ts`, `tests/server/emailAuditFixes.test.ts`,
LNURL double-poll/restart-window tests).

### Documented residual risks (not fixed this release)

- Session tokens are stored plaintext in the reference `MemorySignerStorage`
  (a DB snapshot leaks live sessions) — hash at rest in production stores.
- First-login account creation is find-then-insert (not atomic) in the
  memory store; use unique constraints in a real database.
- JS zeroization of nsecs/PRF seeds is best-effort (language limitation).

## 0.1.0 — initial extraction

Passkey-first Nostr signing extracted from bao.markets: WebAuthn PRF
identity derivation, passkey-wrapped key storage, full login module
(guest, NIP-98, LNURL, email OTP, Telegram), Fastify auth server.

## 0.2.0 — pre-public-release security audit (two independent sessions)

Two independent audit sessions reviewed every file under `src/` (client +
server) before the first public release. Findings and fixes:

### Fixed

- **`nativePasskey`: PRF extraction from raw credentials.** `extractPrfSeed`
  read the `clientExtensionResults` *property* off a raw
  `PublicKeyCredential`, which only exposes results via the
  `getClientExtensionResults()` *method* — extraction always returned null,
  forcing a needless second authenticator prompt on every registration and
  failing registration entirely if that prompt was cancelled. Both shapes
  are now supported (`extractPrfSeed` is exported for consumers driving
  `navigator.credentials` directly).
- **`nativePasskey`: honest unlock errors.** User-cancel / timeout
  (`NotAllowedError` / `AbortError`) was swallowed and misreported as
  "PRF is not available on this authenticator". Cancellation now
  propagates distinctly (`isCancelError` exported).
- **`keyStorage`: versioned vault format.** Blobs are now
  `v2i{iterations}:` + base64(salt(32) ‖ iv(12) ‖ ciphertext) at 256k
  PBKDF2-SHA256 iterations — the iteration count is encoded in the blob so
  future parameter changes can never brick stored keys. Legacy v0 blobs
  (unprefixed, 16-byte salt, 250k) still decrypt.

### Verified (no action needed)

- NIP-44 is spec-compliant everywhere (`nostr-tools`
  `nip44.v2.utils.getConversationKey`); the bespoke ECDH
  `deriveBaoConversationKey` remains exported but `@deprecated` for
  legacy-data compatibility only.
- Derivation parity with bao.markets is byte-exact: `bao/<baoId>/<index>`
  HMAC-SHA256 per-community keys, `bao:nostr:v1:` PRF→Nostr derivation,
  `bao:prf:v1` WebAuthn salts.
- PRF-derived keys are scalar-validated (`ensureValidSecp256k1Scalar`) —
  the bao.markets equivalent can throw on the (astronomically rare)
  invalid-scalar edge case.
- Server: relay backup key derivation fails closed without an HMAC
  secret; the hold/consume nsec manager is TTL-bound (30 min) and
  one-shot; NIP-98 challenge binding verified.

### Second-session findings (also fixed)

- **HIGH — `/auth/email/register` email pre-hijack.** The endpoint bound any
  email to any caller-supplied nsec with zero proof of inbox ownership; a
  victim's later OTP login would have issued a session for the attacker's
  pubkey. Binding now requires a valid OTP for that inbox (idempotent
  same-key re-register stays code-free — the nsec itself proves control).
- **HIGH — flagship flow couldn't complete against the reference server.**
  The server rejects anonymous PRF registration
  (`PRF_ACCOUNT_LINK_REQUIRES_AUTH`) but the client had no functions for the
  authenticated `/auth/link/passkey/*` endpoints. Added
  `linkPasskeyOptions` / `linkPasskeyRegister` / `linkBreezPasskey`
  (Bearer-auth full flow: options → PRF-injected create → derive → link).
- **MED — LNURL poll minted a fresh session when the held token was gone.**
  Double-mint is now impossible: poll in the restart window fails 410
  (`LNURL_SESSION_CONSUMED`); the challenge is consumed atomically.
- **MED — email OTP brute-force window.** Added per-email failure lockout
  (10 failures invalidate ALL outstanding codes) and sibling-code deletion
  on success; dev OTP logging trimmed to 2 digits.
- **MED — package published raw `.ts` sources.** Now ships `dist/` (JS +
  `.d.ts`) via `tsc -p tsconfig.build.json`
  (`rewriteRelativeImportExtensions`); `exports` points at `dist`;
  `prepublishOnly` builds.
- **MED — trusted blob-embedded PBKDF2 iteration count.** A tampered
  `v2i{n}:` blob could hang or weaken the KDF; counts outside
  100k–10M now fail closed.
- **LOW — storage-prefix inconsistency.** `nativePasskeyAuth` and
  `quickStart` keys now derive from the shared configurable prefixes
  (`nativePasskeyStorageKey` / `keyStorageKey`), evaluated at call time;
  default-prefix names unchanged (existing enrollments unaffected).
- **LOW — Telegram `auth_date` future timestamps** rejected via absolute
  window; **LNURL high-S signatures** accepted (`lowS: false` — wallet
  interop); **NIP-98 `/bao-api` path strip** is now an option
  (`pathPrefixStrip`).

### Tests

108/108 — including regression tests for every finding
(`tests/client/nativePasskey.test.ts`, `tests/client/keyStorage.test.ts`,
`tests/client/linkPasskey.test.ts`, `tests/server/emailAuditFixes.test.ts`,
LNURL double-poll/restart-window tests).

### Documented residual risks (not fixed this release)

- Session tokens are stored plaintext in the reference `MemorySignerStorage`
  (a DB snapshot leaks live sessions) — hash at rest in production stores.
- First-login account creation is find-then-insert (not atomic) in the
  memory store; use unique constraints in a real database.
- JS zeroization of nsecs/PRF seeds is best-effort (language limitation).

## 0.1.0 — initial extraction

Passkey-first Nostr signing extracted from bao.markets: WebAuthn PRF
identity derivation, passkey-wrapped key storage, full login module
(guest, NIP-98, LNURL, email OTP, Telegram), Fastify auth server.

## 0.3.0 — shared login module: NIP-07 popup connect + NIP-46 remote signer

The login UX every BAO app shares, now in one public module:

- **`nip07`** — browser-extension connect ported from bao.markets'
  battle-tested flow: synchronous shape check (preserves the user gesture so
  the extension's approval POPUP actually opens), session-cached pubkey
  (hooks re-running never re-prompt), cached denial with `{ force: true }`
  retry, and an honest timeout ("check the extension popup") instead of a
  silent hang. `connectNip07Signer()` returns the standard signer shape
  (signEvent + optional nip44 pass-through).
- **`nip46`** — NIP-46 (Nostr Connect) remote-signer client, decoupled port
  of bao.markets' Nip46Client: NIP-44 only, response signature verification,
  expected-pubkey pinning, remote-event shape + Schnorr verification,
  bunker:// URL validation (npub + hex, relay URL credential stripping).
  `connectNip46Signer(bunkerUrl)` returns the same signer shape — apps swap
  extension / passkey / seed / remote without code changes.

126/126 tests (new nip07 + nip46 suites), tsc clean, dist build.

## 0.2.0 — pre-public-release security audit (two independent sessions)

Two independent audit sessions reviewed every file under `src/` (client +
server) before the first public release. Findings and fixes:

### Fixed

- **`nativePasskey`: PRF extraction from raw credentials.** `extractPrfSeed`
  read the `clientExtensionResults` *property* off a raw
  `PublicKeyCredential`, which only exposes results via the
  `getClientExtensionResults()` *method* — extraction always returned null,
  forcing a needless second authenticator prompt on every registration and
  failing registration entirely if that prompt was cancelled. Both shapes
  are now supported (`extractPrfSeed` is exported for consumers driving
  `navigator.credentials` directly).
- **`nativePasskey`: honest unlock errors.** User-cancel / timeout
  (`NotAllowedError` / `AbortError`) was swallowed and misreported as
  "PRF is not available on this authenticator". Cancellation now
  propagates distinctly (`isCancelError` exported).
- **`keyStorage`: versioned vault format.** Blobs are now
  `v2i{iterations}:` + base64(salt(32) ‖ iv(12) ‖ ciphertext) at 256k
  PBKDF2-SHA256 iterations — the iteration count is encoded in the blob so
  future parameter changes can never brick stored keys. Legacy v0 blobs
  (unprefixed, 16-byte salt, 250k) still decrypt.

### Verified (no action needed)

- NIP-44 is spec-compliant everywhere (`nostr-tools`
  `nip44.v2.utils.getConversationKey`); the bespoke ECDH
  `deriveBaoConversationKey` remains exported but `@deprecated` for
  legacy-data compatibility only.
- Derivation parity with bao.markets is byte-exact: `bao/<baoId>/<index>`
  HMAC-SHA256 per-community keys, `bao:nostr:v1:` PRF→Nostr derivation,
  `bao:prf:v1` WebAuthn salts.
- PRF-derived keys are scalar-validated (`ensureValidSecp256k1Scalar`) —
  the bao.markets equivalent can throw on the (astronomically rare)
  invalid-scalar edge case.
- Server: relay backup key derivation fails closed without an HMAC
  secret; the hold/consume nsec manager is TTL-bound (30 min) and
  one-shot; NIP-98 challenge binding verified.

### Second-session findings (also fixed)

- **HIGH — `/auth/email/register` email pre-hijack.** The endpoint bound any
  email to any caller-supplied nsec with zero proof of inbox ownership; a
  victim's later OTP login would have issued a session for the attacker's
  pubkey. Binding now requires a valid OTP for that inbox (idempotent
  same-key re-register stays code-free — the nsec itself proves control).
- **HIGH — flagship flow couldn't complete against the reference server.**
  The server rejects anonymous PRF registration
  (`PRF_ACCOUNT_LINK_REQUIRES_AUTH`) but the client had no functions for the
  authenticated `/auth/link/passkey/*` endpoints. Added
  `linkPasskeyOptions` / `linkPasskeyRegister` / `linkBreezPasskey`
  (Bearer-auth full flow: options → PRF-injected create → derive → link).
- **MED — LNURL poll minted a fresh session when the held token was gone.**
  Double-mint is now impossible: poll in the restart window fails 410
  (`LNURL_SESSION_CONSUMED`); the challenge is consumed atomically.
- **MED — email OTP brute-force window.** Added per-email failure lockout
  (10 failures invalidate ALL outstanding codes) and sibling-code deletion
  on success; dev OTP logging trimmed to 2 digits.
- **MED — package published raw `.ts` sources.** Now ships `dist/` (JS +
  `.d.ts`) via `tsc -p tsconfig.build.json`
  (`rewriteRelativeImportExtensions`); `exports` points at `dist`;
  `prepublishOnly` builds.
- **MED — trusted blob-embedded PBKDF2 iteration count.** A tampered
  `v2i{n}:` blob could hang or weaken the KDF; counts outside
  100k–10M now fail closed.
- **LOW — storage-prefix inconsistency.** `nativePasskeyAuth` and
  `quickStart` keys now derive from the shared configurable prefixes
  (`nativePasskeyStorageKey` / `keyStorageKey`), evaluated at call time;
  default-prefix names unchanged (existing enrollments unaffected).
- **LOW — Telegram `auth_date` future timestamps** rejected via absolute
  window; **LNURL high-S signatures** accepted (`lowS: false` — wallet
  interop); **NIP-98 `/bao-api` path strip** is now an option
  (`pathPrefixStrip`).

### Tests

108/108 — including regression tests for every finding
(`tests/client/nativePasskey.test.ts`, `tests/client/keyStorage.test.ts`,
`tests/client/linkPasskey.test.ts`, `tests/server/emailAuditFixes.test.ts`,
LNURL double-poll/restart-window tests).

### Documented residual risks (not fixed this release)

- Session tokens are stored plaintext in the reference `MemorySignerStorage`
  (a DB snapshot leaks live sessions) — hash at rest in production stores.
- First-login account creation is find-then-insert (not atomic) in the
  memory store; use unique constraints in a real database.
- JS zeroization of nsecs/PRF seeds is best-effort (language limitation).

## 0.1.0 — initial extraction

Passkey-first Nostr signing extracted from bao.markets: WebAuthn PRF
identity derivation, passkey-wrapped key storage, full login module
(guest, NIP-98, LNURL, email OTP, Telegram), Fastify auth server.

## 0.2.0 — pre-public-release security audit (two independent sessions)

Two independent audit sessions reviewed every file under `src/` (client +
server) before the first public release. Findings and fixes:

### Fixed

- **`nativePasskey`: PRF extraction from raw credentials.** `extractPrfSeed`
  read the `clientExtensionResults` *property* off a raw
  `PublicKeyCredential`, which only exposes results via the
  `getClientExtensionResults()` *method* — extraction always returned null,
  forcing a needless second authenticator prompt on every registration and
  failing registration entirely if that prompt was cancelled. Both shapes
  are now supported (`extractPrfSeed` is exported for consumers driving
  `navigator.credentials` directly).
- **`nativePasskey`: honest unlock errors.** User-cancel / timeout
  (`NotAllowedError` / `AbortError`) was swallowed and misreported as
  "PRF is not available on this authenticator". Cancellation now
  propagates distinctly (`isCancelError` exported).
- **`keyStorage`: versioned vault format.** Blobs are now
  `v2i{iterations}:` + base64(salt(32) ‖ iv(12) ‖ ciphertext) at 256k
  PBKDF2-SHA256 iterations — the iteration count is encoded in the blob so
  future parameter changes can never brick stored keys. Legacy v0 blobs
  (unprefixed, 16-byte salt, 250k) still decrypt.

### Verified (no action needed)

- NIP-44 is spec-compliant everywhere (`nostr-tools`
  `nip44.v2.utils.getConversationKey`); the bespoke ECDH
  `deriveBaoConversationKey` remains exported but `@deprecated` for
  legacy-data compatibility only.
- Derivation parity with bao.markets is byte-exact: `bao/<baoId>/<index>`
  HMAC-SHA256 per-community keys, `bao:nostr:v1:` PRF→Nostr derivation,
  `bao:prf:v1` WebAuthn salts.
- PRF-derived keys are scalar-validated (`ensureValidSecp256k1Scalar`) —
  the bao.markets equivalent can throw on the (astronomically rare)
  invalid-scalar edge case.
- Server: relay backup key derivation fails closed without an HMAC
  secret; the hold/consume nsec manager is TTL-bound (30 min) and
  one-shot; NIP-98 challenge binding verified.

### Second-session findings (also fixed)

- **HIGH — `/auth/email/register` email pre-hijack.** The endpoint bound any
  email to any caller-supplied nsec with zero proof of inbox ownership; a
  victim's later OTP login would have issued a session for the attacker's
  pubkey. Binding now requires a valid OTP for that inbox (idempotent
  same-key re-register stays code-free — the nsec itself proves control).
- **HIGH — flagship flow couldn't complete against the reference server.**
  The server rejects anonymous PRF registration
  (`PRF_ACCOUNT_LINK_REQUIRES_AUTH`) but the client had no functions for the
  authenticated `/auth/link/passkey/*` endpoints. Added
  `linkPasskeyOptions` / `linkPasskeyRegister` / `linkBreezPasskey`
  (Bearer-auth full flow: options → PRF-injected create → derive → link).
- **MED — LNURL poll minted a fresh session when the held token was gone.**
  Double-mint is now impossible: poll in the restart window fails 410
  (`LNURL_SESSION_CONSUMED`); the challenge is consumed atomically.
- **MED — email OTP brute-force window.** Added per-email failure lockout
  (10 failures invalidate ALL outstanding codes) and sibling-code deletion
  on success; dev OTP logging trimmed to 2 digits.
- **MED — package published raw `.ts` sources.** Now ships `dist/` (JS +
  `.d.ts`) via `tsc -p tsconfig.build.json`
  (`rewriteRelativeImportExtensions`); `exports` points at `dist`;
  `prepublishOnly` builds.
- **MED — trusted blob-embedded PBKDF2 iteration count.** A tampered
  `v2i{n}:` blob could hang or weaken the KDF; counts outside
  100k–10M now fail closed.
- **LOW — storage-prefix inconsistency.** `nativePasskeyAuth` and
  `quickStart` keys now derive from the shared configurable prefixes
  (`nativePasskeyStorageKey` / `keyStorageKey`), evaluated at call time;
  default-prefix names unchanged (existing enrollments unaffected).
- **LOW — Telegram `auth_date` future timestamps** rejected via absolute
  window; **LNURL high-S signatures** accepted (`lowS: false` — wallet
  interop); **NIP-98 `/bao-api` path strip** is now an option
  (`pathPrefixStrip`).

### Tests

108/108 — including regression tests for every finding
(`tests/client/nativePasskey.test.ts`, `tests/client/keyStorage.test.ts`,
`tests/client/linkPasskey.test.ts`, `tests/server/emailAuditFixes.test.ts`,
LNURL double-poll/restart-window tests).

### Documented residual risks (not fixed this release)

- Session tokens are stored plaintext in the reference `MemorySignerStorage`
  (a DB snapshot leaks live sessions) — hash at rest in production stores.
- First-login account creation is find-then-insert (not atomic) in the
  memory store; use unique constraints in a real database.
- JS zeroization of nsecs/PRF seeds is best-effort (language limitation).

## 0.1.0 — initial extraction

Passkey-first Nostr signing extracted from bao.markets: WebAuthn PRF
identity derivation, passkey-wrapped key storage, full login module
(guest, NIP-98, LNURL, email OTP, Telegram), Fastify auth server.
