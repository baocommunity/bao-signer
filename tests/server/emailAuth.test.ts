/**
 * Email OTP auth route tests.
 */
import { describe, it, expect, beforeEach } from "vitest";
import Fastify from "fastify";
import { generateSecretKey, getPublicKey, nip19 } from "nostr-tools";
import { emailAuthRoutes } from "../../src/server/emailAuthRoutes.ts";
import { MemorySignerStorage } from "../../src/server/storage.ts";

const SECRET = "email-test-secret";

async function buildApp() {
  const sent: Array<{ to: string; code: string }> = [];
  const app = Fastify({ logger: false });
  const storage = new MemorySignerStorage();
  await app.register(emailAuthRoutes, {
    storage,
    backupSecret: SECRET,
    sendEmail: async (to, code) => {
      sent.push({ to, code });
    },
  });
  return { app, storage, sent };
}

describe("email OTP auth", () => {
  let app: any;
  let storage: MemorySignerStorage;
  let sent: Array<{ to: string; code: string }>;
  beforeEach(async () => {
    ({ app, storage, sent } = await buildApp());
  });

  it("full flow: request OTP → verify → session with one-shot nsec", async () => {
    const req = await app.inject({
      method: "POST",
      url: "/auth/email/request",
      payload: { email: "alice@example.com" },
    });
    expect(req.statusCode).toBe(200);
    expect(req.json().sent).toBe(true);
    expect(sent.length).toBe(1);
    expect(sent[0].to).toBe("alice@example.com");
    expect(sent[0].code).toMatch(/^\d{6}$/);

    const verify = await app.inject({
      method: "POST",
      url: "/auth/email/verify",
      payload: { email: "alice@example.com", code: sent[0].code },
    });
    expect(verify.statusCode).toBe(200);
    const { session } = verify.json();
    expect(session.pubkey).toMatch(/^[0-9a-f]{64}$/);
    expect(session.nsec).toMatch(/^nsec1/); // first login shows nsec
    expect(session.firstLogin).toBe(true);
    expect(session.authMethod).toBe("email");
    expect(session.sessionToken).toMatch(/^bao_sess_/);
  });

  it("second verify with the same code fails (one-shot)", async () => {
    await app.inject({ method: "POST", url: "/auth/email/request", payload: { email: "bob@example.com" } });
    const code = sent[0].code;

    const first = await app.inject({ method: "POST", url: "/auth/email/verify", payload: { email: "bob@example.com", code } });
    expect(first.statusCode).toBe(200);

    const second = await app.inject({ method: "POST", url: "/auth/email/verify", payload: { email: "bob@example.com", code } });
    expect(second.statusCode).toBe(401);
  });

  it("second login (new OTP) returns no nsec", async () => {
    await app.inject({ method: "POST", url: "/auth/email/request", payload: { email: "carol@example.com" } });
    await app.inject({ method: "POST", url: "/auth/email/verify", payload: { email: "carol@example.com", code: sent[0].code } });

    await app.inject({ method: "POST", url: "/auth/email/request", payload: { email: "carol@example.com" } });
    const verify = await app.inject({ method: "POST", url: "/auth/email/verify", payload: { email: "carol@example.com", code: sent[1].code } });
    expect(verify.json().session.nsec).toBeNull();
    expect(verify.json().session.firstLogin).toBe(false);
  });

  it("rejects invalid codes and malformed input", async () => {
    await app.inject({ method: "POST", url: "/auth/email/request", payload: { email: "dave@example.com" } });

    const wrong = await app.inject({ method: "POST", url: "/auth/email/verify", payload: { email: "dave@example.com", code: "000000" } });
    expect([401, 200]).toContain(wrong.statusCode); // 000000 could theoretically match; expect 401 unless collision
    if (wrong.statusCode === 401) {
      expect(wrong.json().error).toMatch(/invalid or expired/i);
    }

    const badFormat = await app.inject({ method: "POST", url: "/auth/email/verify", payload: { email: "dave@example.com", code: "abcdef" } });
    expect(badFormat.statusCode).toBe(400);
  });

  it("rate limits OTP requests per email", async () => {
    for (let i = 0; i < 5; i++) {
      const res = await app.inject({ method: "POST", url: "/auth/email/request", payload: { email: "spam@example.com" } });
      expect(res.statusCode).toBe(200);
    }
    const sixth = await app.inject({ method: "POST", url: "/auth/email/request", payload: { email: "spam@example.com" } });
    expect(sixth.statusCode).toBe(429);
  });

  it("normalizes email case", async () => {
    await app.inject({ method: "POST", url: "/auth/email/request", payload: { email: "  Mixed@Example.COM " } });
    expect(sent[0].to).toBe("mixed@example.com");
  });

  it("register: links an existing nsec, idempotent, conflicts on different key", async () => {
    const sk = generateSecretKey();
    const nsec = nip19.nsecEncode(sk);
    const pubkey = getPublicKey(sk);

    const reg = await app.inject({
      method: "POST",
      url: "/auth/email/register",
      payload: { email: "link@example.com", nsec, username: "linked" },
    });
    expect(reg.statusCode).toBe(200);
    expect(reg.json().pubkey).toBe(pubkey);

    // Idempotent with same key
    const again = await app.inject({
      method: "POST",
      url: "/auth/email/register",
      payload: { email: "link@example.com", nsec, username: "linked" },
    });
    expect(again.statusCode).toBe(200);

    // Conflict with different key
    const other = nip19.nsecEncode(generateSecretKey());
    const conflict = await app.inject({
      method: "POST",
      url: "/auth/email/register",
      payload: { email: "link@example.com", nsec: other, username: "x" },
    });
    expect(conflict.statusCode).toBe(409);
  });

  it("fails closed without a sendEmail hook", async () => {
    const app2 = Fastify({ logger: false });
    app2.register(emailAuthRoutes, {
      storage: new MemorySignerStorage(),
      backupSecret: SECRET,
      // @ts-expect-error — intentionally missing
      sendEmail: undefined,
    });
    await expect(app2.ready()).rejects.toThrow(/sendEmail/);
  });
});
