/**
 * bao-signer/server — Fastify plugin for passkey-based Nostr auth.
 *
 * ```ts
 * import Fastify from "fastify";
 * import { baoSignerAuthRoutes, MemorySignerStorage } from "bao-signer/server";
 *
 * const app = Fastify();
 * const storage = new MemorySignerStorage();
 * await app.register(baoSignerAuthRoutes, {
 *   storage,
 *   rpId: "example.com",
 *   expectedOrigins: ["https://example.com"],
 *   backupSecret: process.env.BACKUP_HMAC_SECRET!,
 *   authenticate: async (req) => {
 *     const token = req.headers.authorization?.replace(/^Bearer /, "");
 *     const session = token ? await storage.getSession(token) : undefined;
 *     return session?.pubkey ?? null;
 *   },
 * });
 * ```
 */

export * from "./passkeyAuthRoutes.ts";
export * from "./storage.ts";
export * from "./relayBackupKey.ts";
export * from "./webauthnChallenges.ts";
export * from "./nsecManager.ts";
