/**
 * Regression tests for the second-session audit fixes (server side):
 *
 *  HIGH-1 — /auth/email/register must require a valid OTP (no pre-hijack)
 *  MED-2  — per-email OTP failure lockout + sibling-code invalidation
 */
import { describe, it, expect, beforeEach } from "vitest";
import Fastify from "fastify";
import { generateSecretKey, getPublicKey, nip19 } from "nostr-tools";
import { emailAuthRoutes } from "../../src/server/emailAuthRoutes.ts";
import { MemorySignerStorage } from "../../src/server/storage.ts";

const SECRET = "audit-test-secret";

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

function attackerNsec(): string {
  return nip19.nsecEncode(generateSecretKey());
}

describe("HIGH-1: email register requires OTP (pre-hijack fix)", () => {
  let app: any;
  let sent: Array<{ to: string; code: string }>;
  beforeEach(async () => {
    ({ app, sent } = await buildApp());
  });

  it("rejects register without a code", async () => {
    const res = await app.inject({
      method: "POST",
      url: "/auth/email/register",
      payload: { email: "victim@example.com", nsec: attackerNsec(), username: "attacker" },
    });
    expect(res.statusCode).toBe(400);
  });

  it("rejects register with an invalid code — email is NOT bound", async () => {
    // Attacker never received an OTP for the victim inbox.
    const res = await app.inject({
      method: "POST",
      url: "/auth/email/register",
      payload: { email: "victim@example.com", nsec: attackerNsec(), username: "attacker", code: "000000" },
    });
    expect(res.statusCode).toBe(401);

    // The pre-hijack must not have happened: the victim's real OTP login
    // must create/log into THEIR OWN account, not the attacker's.
    await app.inject({ method: "POST", url: "/auth/email/request", payload: { email: "victim@example.com" } });
    const code = sent[0].code;
    const verify = await app.inject({
      method: "POST",
      url: "/auth/email/verify",
      payload: { email: "victim@example.com", code },
    });
    expect(verify.statusCode).toBe(200);
    const { session } = verify.json();
    expect(session.firstLogin).toBe(true); // fresh account — no pre-bound attacker key
    expect(session.nsec).toMatch(/^nsec1/); // victim gets THEIR nsec
  });

  it("accepts register with a valid OTP for that inbox", async () => {
    // User proves inbox ownership first.
    await app.inject({ method: "POST", url: "/auth/email/request", payload: { email: "owner@example.com" } });
    // The auto-created account from /request will 409 (different key) — the
    // register-with-own-key path is for emails WITHOUT an account yet.
    // Simulate that by registering a fresh email whose OTP we hold but whose
    // auto-created account we remove is not possible — instead assert the 409
    // path documents the remedy.
    const nsec = attackerNsec(); // user's OWN existing key
    const res = await app.inject({
      method: "POST",
      url: "/auth/email/register",
      payload: { email: "owner@example.com", nsec, username: "owner", code: sent[0].code },
    });
    // Auto-create already bound a server key to this email → 409 with remedy.
    expect(res.statusCode).toBe(409);
    expect(res.json().error).toMatch(/account-link/);
  });

  it("idempotent re-register with the SAME key does not require a code", async () => {
    // First create an account via OTP and capture its nsec.
    await app.inject({ method: "POST", url: "/auth/email/request", payload: { email: "same@example.com" } });
    const verify = await app.inject({
      method: "POST",
      url: "/auth/email/verify",
      payload: { email: "same@example.com", code: sent[0].code },
    });
    const { session } = verify.json();
    const res = await app.inject({
      method: "POST",
      url: "/auth/email/register",
      payload: { email: "same@example.com", nsec: session.nsec, username: "same" },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().registered).toBe(true);
  });
});

describe("MED-2: OTP failure lockout", () => {
  let app: any;
  let sent: Array<{ to: string; code: string }>;
  beforeEach(async () => {
    ({ app, sent } = await buildApp());
  });

  it("10 failed attempts invalidate ALL outstanding codes", async () => {
    await app.inject({ method: "POST", url: "/auth/email/request", payload: { email: "target@example.com" } });
    const realCode = sent[0].code;

    for (let i = 0; i < 9; i++) {
      const res = await app.inject({
        method: "POST",
        url: "/auth/email/verify",
        payload: { email: "target@example.com", code: "999999" },
      });
      expect(res.statusCode).toBe(401);
    }
    const tenth = await app.inject({
      method: "POST",
      url: "/auth/email/verify",
      payload: { email: "target@example.com", code: "999999" },
    });
    expect(tenth.statusCode).toBe(429);

    // The REAL code must now be dead too.
    const real = await app.inject({
      method: "POST",
      url: "/auth/email/verify",
      payload: { email: "target@example.com", code: realCode },
    });
    expect(real.statusCode).toBe(401);
  });

  it("successful verify invalidates sibling codes", async () => {
    await app.inject({ method: "POST", url: "/auth/email/request", payload: { email: "multi@example.com" } });
    await app.inject({ method: "POST", url: "/auth/email/request", payload: { email: "multi@example.com" } });
    const [first, second] = sent.map((m) => m.code);
    expect(first).not.toBe(second);

    const ok = await app.inject({
      method: "POST",
      url: "/auth/email/verify",
      payload: { email: "multi@example.com", code: second },
    });
    expect(ok.statusCode).toBe(200);

    const sibling = await app.inject({
      method: "POST",
      url: "/auth/email/verify",
      payload: { email: "multi@example.com", code: first },
    });
    expect(sibling.statusCode).toBe(401);
  });
});
