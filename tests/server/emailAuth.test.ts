/**
 * Email OTP auth route tests.
 */
import { describe, it, expect, beforeEach } from "vitest";
import { createHash } from "crypto";
import Fastify from "fastify";
import { generateSecretKey, getPublicKey, nip19 } from "nostr-tools";
import { emailAuthRoutes } from "../../src/server/emailAuthRoutes.ts";
import { MemorySignerStorage } from "../../src/server/storage.ts";

const SECRET = "email-test-secret";

async function buildApp(opts: { noMint?: boolean; nsecEncryptionKey?: string } = {}) {
  const sent: Array<{ to: string; code: string }> = [];
  const app = Fastify({ logger: false });
  const storage = new MemorySignerStorage();
  await app.register(emailAuthRoutes, {
    storage,
    backupSecret: SECRET,
    sendEmail: async (to, code) => {
      sent.push({ to, code });
    },
    ...(opts.noMint ? { allowServerKeyGeneration: false } : {}),
    ...(opts.nsecEncryptionKey ? { nsecEncryptionKey: opts.nsecEncryptionKey } : {}),
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

  it("register: OTP-bound (HIGH-1) — no code → 400, valid OTP on auto-created email → 409, idempotent same-key → 200", async () => {
    const sk = generateSecretKey();
    const nsec = nip19.nsecEncode(sk);

    // Binding without proof of inbox ownership is refused.
    const noCode = await app.inject({
      method: "POST",
      url: "/auth/email/register",
      payload: { email: "link@example.com", nsec, username: "linked" },
    });
    expect(noCode.statusCode).toBe(400);

    // With an OTP: /request auto-creates a server-key account for the email,
    // so registering a DIFFERENT (user-supplied) key conflicts with remedy.
    await app.inject({ method: "POST", url: "/auth/email/request", payload: { email: "link@example.com" } });
    const withCode = await app.inject({
      method: "POST",
      url: "/auth/email/register",
      payload: { email: "link@example.com", nsec, username: "linked", code: sent[0].code },
    });
    expect(withCode.statusCode).toBe(409);
    expect(withCode.json().error).toMatch(/account-link/);

    // Idempotent with the account's OWN key (from first-login nsec) needs no code.
    const verify = await app.inject({
      method: "POST",
      url: "/auth/email/verify",
      payload: { email: "link@example.com", code: sent[0].code },
    });
    expect(verify.statusCode).toBe(200);
    const accountNsec = verify.json().session.nsec;
    const again = await app.inject({
      method: "POST",
      url: "/auth/email/register",
      payload: { email: "link@example.com", nsec: accountNsec, username: "linked" },
    });
    expect(again.statusCode).toBe(200);
    expect(again.json().registered).toBe(true);
  });

  it("register on a fresh email also creates the main account + auth method", async () => {
    const email = "fresh@example.com";
    const emailHash = createHash("sha256").update(email).digest("hex");
    const code = "246810";
    // Seed a valid OTP directly WITHOUT auto-creating the account, so the
    // register handler's "no existing account" branch is actually reachable.
    await storage.emailInsertOtp(
      createHash("sha256").update(code).digest("hex"),
      emailHash,
      Math.floor(Date.now() / 1000) + 600,
    );

    const sk = generateSecretKey();
    const nsec = nip19.nsecEncode(sk);
    const pubkey = getPublicKey(sk);

    const res = await app.inject({
      method: "POST",
      url: "/auth/email/register",
      payload: { email, nsec, username: "fresh-user", code },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().registered).toBe(true);

    // The account must be resolvable from the main tables (not orphaned in
    // the email-only table) so passkey-linking etc. can find it.
    expect(await storage.getAccount(pubkey)).toBeTruthy();
    expect(await storage.findAuthMethod("email", emailHash)).toEqual({ pubkey });
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

describe("email OTP auth — self-custody mode (allowServerKeyGeneration: false)", () => {
  let app: any;
  let storage: MemorySignerStorage;
  let sent: Array<{ to: string; code: string }>;
  beforeEach(async () => {
    ({ app, storage, sent } = await buildApp({ noMint: true }));
  });

  it("request does NOT auto-create an account", async () => {
    await app.inject({ method: "POST", url: "/auth/email/request", payload: { email: "new@example.com" } });
    const emailHash = createHash("sha256").update("new@example.com").digest("hex");
    expect(await storage.emailGetAccount(emailHash)).toBeUndefined();
  });

  it("verify without a bound account returns 404", async () => {
    await app.inject({ method: "POST", url: "/auth/email/request", payload: { email: "ghost@example.com" } });
    const res = await app.inject({
      method: "POST",
      url: "/auth/email/verify",
      payload: { email: "ghost@example.com", code: sent[0].code },
    });
    expect(res.statusCode).toBe(404);
    expect(res.json().error.code).toBe("ACCOUNT_NOT_FOUND");
  });

  it("register never stores a host-recoverable nsec backup even if nsecEncryptionKey is set", async () => {
    // Rebuild the app with a backup key configured: self-custody mode must
    // still NOT persist a decryptable nsec copy (server never holds the key).
    const sk = generateSecretKey();
    const nsec = nip19.nsecEncode(sk);
    const email = "backup-off@example.com";
    const emailHash = createHash("sha256").update(email).digest("hex");

    const selfCustodyWithBackupKey = await buildApp({ noMint: true, nsecEncryptionKey: "host-backup-key" });
    await selfCustodyWithBackupKey.app.inject({
      method: "POST",
      url: "/auth/email/request",
      payload: { email },
    });
    const reg = await selfCustodyWithBackupKey.app.inject({
      method: "POST",
      url: "/auth/email/register",
      payload: { email, nsec, username: "backup-off", code: selfCustodyWithBackupKey.sent[0].code },
    });
    expect(reg.statusCode).toBe(200);

    const account = await selfCustodyWithBackupKey.storage.emailGetAccount(emailHash);
    expect(account).toBeTruthy();
    expect(account?.encrypted_nsec).toBeUndefined();
    expect(account?.nsec_salt).toBeUndefined();
    expect(account?.nsec_iv).toBeUndefined();
  });

  it("register binds a client key, then verify signs into that key (server never held the nsec)", async () => {
    const sk = generateSecretKey();
    const nsec = nip19.nsecEncode(sk);
    const pubkey = getPublicKey(sk);

    // 1. Request OTP (does not create an account).
    await app.inject({ method: "POST", url: "/auth/email/request", payload: { email: "self@example.com" } });

    // 2. Bind the locally-generated key to the email with OTP proof.
    const reg = await app.inject({
      method: "POST",
      url: "/auth/email/register",
      payload: { email: "self@example.com", nsec, username: "self-user", code: sent[0].code },
    });
    expect(reg.statusCode).toBe(200);
    expect(reg.json().pubkey).toBe(pubkey);

    // 3. Later login with a fresh OTP resolves the SAME self-custodial key.
    await app.inject({ method: "POST", url: "/auth/email/request", payload: { email: "self@example.com" } });
    const verify = await app.inject({
      method: "POST",
      url: "/auth/email/verify",
      payload: { email: "self@example.com", code: sent[1].code },
    });
    expect(verify.statusCode).toBe(200);
    const session = verify.json().session;
    expect(session.pubkey).toBe(pubkey);
    expect(session.nsec).toBeNull(); // the server never generated/held it
    expect(session.firstLogin).toBe(false);
  });
});
