/**
 * bao-signer/client — browser-side passkey + Nostr key derivation.
 *
 * - `passkeyAuth`   — PRF passkey register/login against a bao-signer server,
 *                     deriving a deterministic Nostr identity from the
 *                     authenticator's PRF output.
 * - `prf`           — WebAuthn PRF extension provider (also usable as a
 *                     Breez SDK `PasskeyPrfProvider`).
 * - `nativePasskey` — zero-dependency local key wrapping: encrypt a Nostr
 *                     secret with a passkey-protected AES-256-GCM master key
 *                     (platform PRF, YubiKey PRF, YubiKey largeBlob).
 * - `nativePasskeyAuth` — pure client-side passkey-locked Nostr accounts
 *                     (no server interaction).
 * - `derivedKeys`   — deterministic per-community key derivation
 *                     (HMAC-SHA256, scalar-validated).
 */

export * from "./config.ts";
export * from "./prf.ts";
export * from "./passkeyAuth.ts";
export * from "./nativePasskey.ts";
export * from "./nativePasskeyAuth.ts";
export * from "./derivedKeys.ts";
