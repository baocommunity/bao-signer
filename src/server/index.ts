/**
 * bao-signer/server — Fastify plugins for passkey-first Nostr auth.
 *
 * ```ts
 * import Fastify from "fastify";
 * import {
 *   baoSignerAuthRoutes,      // passkeys
 *   nip98ChallengeRoutes,     // GET /auth/challenge (needed by guest/nostr)
 *   guestAuthRoutes,          // Quick Start
 *   nostrAuthRoutes,          // NIP-98 login
 *   lnurlAuthRoutes,          // Lightning wallet login
 *   emailAuthRoutes,          // email OTP
 *   telegramAuthRoutes,       // Telegram widget + OIDC QR
 *   MemorySignerStorage,
 * } from "bao-signer/server";
 * ```
 *
 * Every secret is injected via plugin options — nothing is read from env,
 * hardcoded, or defaulted to an insecure value.
 */

export * from "./passkeyAuthRoutes.ts";
export * from "./nip98.ts";
export * from "./guestAuthRoutes.ts";
export * from "./nostrAuthRoutes.ts";
export * from "./lnurlAuthRoutes.ts";
export * from "./emailAuthRoutes.ts";
export * from "./telegramAuthRoutes.ts";
export * from "./storage.ts";
export * from "./relayBackupKey.ts";
export * from "./webauthnChallenges.ts";
export * from "./nsecManager.ts";
