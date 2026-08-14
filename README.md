# bao-signer

Passkey-first Nostr signing and authentication.

`bao-signer` turns a **passkey into a Nostr identity** — no seed phrases, no
extensions, no custodial key storage. Extracted from
[bao.markets](https://github.com/baocommunity/bao.markets) and hardened for
general use.

```
passkey (Touch ID / YubiKey / Windows Hello)
   │  WebAuthn PRF extension
   ▼
32-byte PRF seed ──sha256("bao:nostr:v1:"… + scalar check)──▶ Nostr keypair
```

The derived key is a **standard secp256k1 Nostr key** — fully compatible with
every relay, client, and NIP. The derivation only changes *where the entropy
comes from*: your authenticator instead of a random file on disk.

## What's inside

| Module | Side | Purpose |
|---|---|---|
| `bao-signer/client` → `passkeyAuth` | browser | PRF passkey register/login against a server; derives deterministic Nostr identity |
| `bao-signer/client` → `prf` | browser | WebAuthn PRF provider (also usable as a Breez SDK `PasskeyPrfProvider`) |
| `bao-signer/client` → `nativePasskey` | browser | Zero-dependency key wrapping: AES-256-GCM master key protected by passkey (platform PRF, YubiKey PRF, YubiKey largeBlob) |
| `bao-signer/client` → `nativePasskeyAuth` | browser | Pure client-side passkey-locked Nostr accounts (no server needed) |
| `bao-signer/client` → `quickStart` + `keyStorage` | browser | One-click guest onboarding; encrypted local key storage (PBKDF2 + AES-256-GCM) |
| `bao-signer/client` → `loginFlows` | browser | Thin clients for every server login method (guest, nostr, LNURL, email, Telegram) |
| `bao-signer/client` → `derivedKeys` | browser/node | Per-community key derivation (HMAC-SHA256, scalar-validated, unlinkable identities) |
| `bao-signer/server` → `passkeyAuthRoutes` | node | Passkey register/login + authenticated account linking |
| `bao-signer/server` → `guestAuthRoutes` / `nostrAuthRoutes` | node | NIP-98 (kind 27235) signed-event login — guest (24h) and full (30d) sessions |
| `bao-signer/server` → `lnurlAuthRoutes` | node | Lightning wallet login (k1 challenge → wallet signature → session) |
| `bao-signer/server` → `emailAuthRoutes` | node | Email OTP (6-digit, hashed, 5/hr cap) — sender hook injected, no creds in module |
| `bao-signer/server` → `telegramAuthRoutes` | node | Telegram Login Widget + OIDC QR — bot token/secret injected, PII discarded, HMAC auth ids |

## Quick start

### Client

```ts
import {
  configureBaoSignerClient,
  registerNativePasskeyAccount,
  loginNativePasskeyAccount,
} from "bao-signer/client";

// For server-assisted flows:
configureBaoSignerClient({ apiBaseUrl: "https://api.example.com/bao-api" });

// Pure local flow — passkey-locked Nostr account, no server:
const { identity, method } = await registerNativePasskeyAccount();
// → identity.npub / identity.nsec, method: "prf" | "largeBlob"

const session = await loginNativePasskeyAccount(); // touch → unlocked nsec
```

### Server

```ts
import Fastify from "fastify";
import { baoSignerAuthRoutes, MemorySignerStorage } from "bao-signer/server";

const app = Fastify();
const storage = new MemorySignerStorage(); // dev — see schema.sql for production

await app.register(baoSignerAuthRoutes, {
  storage,
  rpId: "example.com",
  expectedOrigins: ["https://example.com"],
  backupSecret: process.env.BACKUP_HMAC_SECRET!, // required — fails closed
  authenticate: async (req) => {
    const token = req.headers.authorization?.replace(/^Bearer /, "");
    const session = token ? await storage.getSession(token) : undefined;
    return session?.pubkey ?? null;
  },
});
```

`MemorySignerStorage` is for development. For production, implement the
`SignerStorage` interface over PostgreSQL — see [`schema.sql`](./schema.sql).

## Security model

Read [`SECURITY.md`](./SECURITY.md) before deploying. Highlights:

- **User verification is always required** (biometric/PIN, never just tap).
- **Anonymous PRF registration is rejected.** A WebAuthn attestation proves
  control of the *credential*, not of a claimed Nostr pubkey. PRF identities
  link through the authenticated account-link flow.
- **Fail-closed secrets.** The relay backup key requires an HMAC secret; no
  deterministic fallback is ever used.
- **`prfSeed` ≠ nsec.** The raw PRF output is *not* the Nostr private key.
  The key is `sha256("bao:nostr:v1:" + hex(seed))`, scalar-validated. Never
  encode the raw seed as an nsec.
- Non-PRF server-generated accounts deliver the nsec **once**; only
  `sha256(nsec)` is stored.

## Tests

```bash
pnpm install
pnpm test
pnpm typecheck
```

## License

MIT — BAO Community contributors.
