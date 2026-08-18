/**
 * Telegram auth route tests — Login Widget flow with real HMAC construction.
 */
import { describe, it, expect, beforeEach } from "vitest";
import { createHash, createHmac } from "crypto";
import Fastify from "fastify";
import { telegramAuthRoutes } from "../../src/server/telegramAuthRoutes.ts";
import { MemorySignerStorage } from "../../src/server/storage.ts";

const BOT_TOKEN = "test-bot-token";
const SECRET = "telegram-test-secret";

async function buildApp(opts: { withOidc?: boolean; noMint?: boolean } = {}) {
  const app = Fastify({ logger: false });
  const storage = new MemorySignerStorage();
  await app.register(telegramAuthRoutes, {
    storage,
    botToken: BOT_TOKEN,
    botUsername: "TestBot",
    backupSecret: SECRET,
    ...(opts.withOidc
      ? { clientId: "cid", clientSecret: "csecret", redirectUri: "http://localhost/cb" }
      : {}),
    ...(opts.noMint ? { allowServerKeyGeneration: false } : {}),
  });
  return { app, storage };
}

/** Build valid Telegram Login Widget data (mirrors Telegram's HMAC scheme). */
function makeWidgetData(overrides: Record<string, string | number> = {}) {
  const data: Record<string, string> = {
    id: "123456",
    auth_date: String(Math.floor(Date.now() / 1000)),
    first_name: "Alice",
    ...Object.fromEntries(Object.entries(overrides).map(([k, v]) => [k, String(v)])),
  };
  const checkString = Object.keys(data)
    .sort()
    .map((k) => `${k}=${data[k]}`)
    .join("\n");
  const secretKey = createHash("sha256").update(BOT_TOKEN).digest();
  data.hash = createHmac("sha256", secretKey).update(checkString).digest("hex");
  return data;
}

describe("telegram widget verify", () => {
  let app: any;
  let storage: MemorySignerStorage;
  beforeEach(async () => {
    ({ app, storage } = await buildApp());
  });

  it("accepts valid widget data and issues a session with one-shot nsec", async () => {
    const data = makeWidgetData();
    const res = await app.inject({ method: "POST", url: "/auth/telegram/verify", payload: data });
    expect(res.statusCode).toBe(200);
    const { session } = res.json();
    expect(session.pubkey).toMatch(/^[0-9a-f]{64}$/);
    expect(session.nsec).toMatch(/^nsec1/);
    expect(session.isNewAccount).toBe(true);
    expect(session.authMethod).toBe("telegram");
    expect(session.relayBackupKey).toMatch(/^[0-9a-f]{32}$/);
    expect(session.expires_at).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });

  it("returns the same account on second login, without nsec", async () => {
    const first = await app.inject({ method: "POST", url: "/auth/telegram/verify", payload: makeWidgetData() });
    const pk1 = first.json().session.pubkey;

    const second = await app.inject({ method: "POST", url: "/auth/telegram/verify", payload: makeWidgetData() });
    const s2 = second.json().session;
    expect(s2.pubkey).toBe(pk1);
    expect(s2.isNewAccount).toBe(false);
    expect(s2.nsec).toBeNull();
  });

  it("rejects a tampered hash", async () => {
    const data = makeWidgetData();
    data.first_name = "Mallory"; // tamper after signing
    const res = await app.inject({ method: "POST", url: "/auth/telegram/verify", payload: data });
    expect(res.statusCode).toBe(401);
  });

  it("rejects stale auth_date", async () => {
    const stale = Math.floor(Date.now() / 1000) - 600;
    const data = makeWidgetData({ auth_date: stale });
    const res = await app.inject({ method: "POST", url: "/auth/telegram/verify", payload: data });
    expect(res.statusCode).toBe(401);
    expect(res.json().error).toMatch(/expired/i);
  });

  it("self-custody mode: unknown user is refused (403) instead of minted a key", async () => {
    const { app } = await buildApp({ noMint: true });
    const res = await app.inject({ method: "POST", url: "/auth/telegram/verify", payload: makeWidgetData() });
    expect(res.statusCode).toBe(403);
    expect(res.json().error).toMatch(/account creation is disabled/i);
  });

  it("does not store telegram PII — only the derived auth id", async () => {
    await app.inject({ method: "POST", url: "/auth/telegram/verify", payload: makeWidgetData() });
    const expected = createHmac("sha256", BOT_TOKEN).update("123456").digest("hex");
    const method = await storage.findAuthMethod("telegram", expected);
    expect(method).toBeTruthy();
    // And the raw id must NOT resolve
    const raw = await storage.findAuthMethod("telegram", "123456");
    expect(raw).toBeUndefined();
  });
});

describe("telegram config + QR", () => {
  it("reports configured state", async () => {
    const { app } = await buildApp();
    const res = await app.inject({ method: "GET", url: "/auth/telegram/config" });
    expect(res.json()).toEqual({ botUsername: "TestBot", configured: true });
  });

  it("QR flow is 503 without OIDC config, works with it", async () => {
    const { app: noOidc } = await buildApp();
    const res503 = await noOidc.inject({ method: "GET", url: "/auth/telegram/qr" });
    expect(res503.statusCode).toBe(503);

    const { app: withOidc } = await buildApp({ withOidc: true });
    const res = await withOidc.inject({ method: "GET", url: "/auth/telegram/qr" });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.state).toMatch(/^[0-9a-f]{64}$/);
    expect(body.authUrl).toContain("oauth.telegram.org/auth");
    expect(body.authUrl).toContain("code_challenge=");
  });

  it("QR poll: 404 unknown state, pending for known state", async () => {
    const { app } = await buildApp({ withOidc: true });
    const unknown = await app.inject({ method: "GET", url: `/auth/telegram/qr/poll?state=${"ab".repeat(32)}` });
    expect(unknown.statusCode).toBe(404);

    const qr = await app.inject({ method: "GET", url: "/auth/telegram/qr" });
    const poll = await app.inject({ method: "GET", url: `/auth/telegram/qr/poll?state=${qr.json().state}` });
    expect(poll.statusCode).toBe(200);
    expect(poll.json().authenticated).toBe(false);
  });
});
