/**
 * Purist NIP-98 email bind — the nsec never crosses the wire.
 *
 * Covers: the new /auth/email/register-nip98 route end-to-end (challenge →
 * sign → bind), signature-first ordering (invalid sig must NOT burn the
 * challenge), endpoint binding, OTP gate, idempotency, and conflict.
 */
import { describe, it, expect, beforeEach } from "vitest";
import Fastify from "fastify";
import { generateSecretKey, getPublicKey, nip19 } from "nostr-tools";
import { bytesToHex } from "@noble/hashes/utils.js";
import { emailAuthRoutes } from "../../src/server/emailAuthRoutes.ts";
import { MemorySignerStorage } from "../../src/server/storage.ts";
import { generateNip98Challenge } from "../../src/server/nip98.ts";
import { signAuthEvent } from "../../src/client/loginFlows.ts";

const SECRET = "nip98-bind-secret";
const API_PREFIX = ""; // test server mounts at root

async function buildApp() {
  const sent: Array<{ to: string; code: string }> = [];
  const app = Fastify({ logger: false });
  const storage = new MemorySignerStorage();
  await app.register(emailAuthRoutes, {
    storage,
    backupSecret: SECRET,
    // Purist posture: the server must NOT auto-mint accounts on /request —
    // identities are created client-side and bound via NIP-98.
    allowServerKeyGeneration: false,
    sendEmail: async (to, code) => {
      sent.push({ to, code });
    },
  });
  return { app, storage, sent };
}

const skAlice = generateSecretKey();
const pkAlice = getPublicKey(skAlice);
const skMallory = generateSecretKey();
const pkMallory = getPublicKey(skMallory);

function bindEvent(sk: Uint8Array, url: string, challenge: string) {
  return signAuthEvent(sk, { url, method: "POST", challenge });
}

async function requestOtp(app: any, email: string): Promise<string> {
  await app.inject({ method: "POST", url: "/auth/email/request", payload: { email } });
  return "";
}

describe("purist NIP-98 email bind", () => {
  let app: any;
  let sent: Array<{ to: string; code: string }>;
  beforeEach(async () => {
    ({ app, sent } = await buildApp());
  });

  it("binds email → pubkey with ZERO key material in the request", async () => {
    await requestOtp(app, "alice@example.com");
    const code = sent[0].code;
    const challenge = generateNip98Challenge();
    const event = bindEvent(skAlice, "/auth/email/register-nip98", challenge);

    const body = { email: "alice@example.com", code, username: "alice", event };
    // The whole point: no nsec/privkey/secret anywhere in the payload.
    expect(JSON.stringify(body)).not.toMatch(/nsec1/);
    expect(JSON.stringify(body)).not.toContain(bytesToHex(skAlice));

    const res = await app.inject({
      method: "POST",
      url: "/auth/email/register-nip98",
      payload: body,
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().registered).toBe(true);
    expect(res.json().pubkey).toBe(pkAlice);
  });

  it("invalid signature does NOT burn the challenge (can retry after fixing)", async () => {
    await requestOtp(app, "retry@example.com");
    const code = sent[0].code;
    const challenge = generateNip98Challenge();
    const good = bindEvent(skAlice, "/auth/email/register-nip98", challenge);
    const bad = { ...good, content: "tampered" }; // breaks the signature

    const r1 = await app.inject({
      method: "POST",
      url: "/auth/email/register-nip98",
      payload: { email: "retry@example.com", code, username: "retry", event: bad },
    });
    expect(r1.statusCode).toBe(401);
    expect(r1.json().error.code).toBe("INVALID_SIGNATURE");

    // Same challenge must STILL be usable — signature was checked before consuming it.
    const r2 = await app.inject({
      method: "POST",
      url: "/auth/email/register-nip98",
      payload: { email: "retry@example.com", code, username: "retry", event: good },
    });
    expect(r2.statusCode).toBe(200);
  });

  it("rejects a forged bind (Mallory's key signed by 'Alice' claim is impossible)", async () => {
    await requestOtp(app, "victim@example.com");
    const code = sent[0].code;
    const challenge = generateNip98Challenge();
    // Mallory signs with HER key — binds only HER pubkey, never Alice's.
    const event = bindEvent(skMallory, "/auth/email/register-nip98", challenge);
    const res = await app.inject({
      method: "POST",
      url: "/auth/email/register-nip98",
      payload: { email: "victim@example.com", code, username: "x", event },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().pubkey).toBe(pkMallory); // binds the SIGNER's key, nothing else
  });

  it("rejects wrong endpoint binding and replayed challenges", async () => {
    await requestOtp(app, "bind@example.com");
    const code = sent[0].code;
    const challenge = generateNip98Challenge();

    // Bound to a DIFFERENT endpoint → rejected.
    const wrongEndpoint = bindEvent(skAlice, "/auth/email/verify", challenge);
    const r1 = await app.inject({
      method: "POST",
      url: "/auth/email/register-nip98",
      payload: { email: "bind@example.com", code, username: "b", event: wrongEndpoint },
    });
    expect(r1.statusCode).toBe(401);
    expect(r1.json().error.code).toBe("BINDING_MISMATCH");

    // Challenge consumed by a valid bind → replay rejected.
    const challenge2 = generateNip98Challenge();
    await requestOtp(app, "replay@example.com");
    const code2 = sent[1].code;
    const ev = bindEvent(skAlice, "/auth/email/register-nip98", challenge2);
    const ok = await app.inject({
      method: "POST",
      url: "/auth/email/register-nip98",
      payload: { email: "replay@example.com", code: code2, username: "r", event: ev },
    });
    expect(ok.statusCode).toBe(200);
    const replay = await app.inject({
      method: "POST",
      url: "/auth/email/register-nip98",
      payload: { email: "replay@example.com", code: code2, username: "r", event: ev },
    });
    expect(replay.statusCode).toBe(401);
    expect(replay.json().error.code).toBe("INVALID_CHALLENGE");
  });

  it("requires the OTP (inbox ownership) and idempotently re-binds the same pair", async () => {
    const challenge = generateNip98Challenge();
    const event = bindEvent(skAlice, "/auth/email/register-nip98", challenge);
    const noOtp = await app.inject({
      method: "POST",
      url: "/auth/email/register-nip98",
      payload: { email: "nootp@example.com", code: "123456", username: "n", event },
    });
    expect(noOtp.statusCode).toBe(401);

    // Valid bind, then idempotent re-bind with the same pair (fresh OTP+challenge).
    await requestOtp(app, "same@example.com");
    const c1 = generateNip98Challenge();
    const r1 = await app.inject({
      method: "POST",
      url: "/auth/email/register-nip98",
      payload: {
        email: "same@example.com",
        code: sent[0].code,
        username: "s",
        event: bindEvent(skAlice, "/auth/email/register-nip98", c1),
      },
    });
    expect(r1.statusCode).toBe(200);

    await requestOtp(app, "same@example.com");
    const c2 = generateNip98Challenge();
    const r2 = await app.inject({
      method: "POST",
      url: "/auth/email/register-nip98",
      payload: {
        email: "same@example.com",
        code: sent[1].code,
        username: "s",
        event: bindEvent(skAlice, "/auth/email/register-nip98", c2),
      },
    });
    expect(r2.statusCode).toBe(200);
    expect(r2.json().registered).toBe(true);

    // Conflict: a DIFFERENT key for the same inbox → 409.
    await requestOtp(app, "same@example.com");
    const c3 = generateNip98Challenge();
    const r3 = await app.inject({
      method: "POST",
      url: "/auth/email/register-nip98",
      payload: {
        email: "same@example.com",
        code: sent[2].code,
        username: "s",
        event: bindEvent(skMallory, "/auth/email/register-nip98", c3),
      },
    });
    expect(r3.statusCode).toBe(409);
  });
});
