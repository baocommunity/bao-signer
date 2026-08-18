/**
 * LNURL-auth route tests — real secp256k1 signatures over k1.
 */
import { describe, it, expect, beforeEach } from "vitest";
import Fastify from "fastify";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { lnurlAuthRoutes, __dropHeldSessionTokenForTest } from "../../src/server/lnurlAuthRoutes.ts";
import { MemorySignerStorage } from "../../src/server/storage.ts";

const SECRET = "lnurl-test-secret";

async function buildApp() {
  const app = Fastify({ logger: false });
  const storage = new MemorySignerStorage();
  await app.register(lnurlAuthRoutes, {
    storage,
    publicBaseUrl: "http://localhost/v1",
    secret: SECRET,
  });
  return { app, storage };
}

function makeWallet() {
  const privKey = secp256k1.utils.randomSecretKey();
  const pubKey = secp256k1.getPublicKey(privKey, true); // compressed
  return { privKey, pubKeyHex: bytesToHex(pubKey) };
}

function signK1(privKey: Uint8Array, k1Hex: string): string {
  // @noble/curves v2: sign() returns the 64-byte compact signature directly
  const sig = secp256k1.sign(Buffer.from(k1Hex, "hex"), privKey);
  return bytesToHex(sig);
}

async function startChallenge(app: any) {
  const res = await app.inject({ method: "GET", url: "/auth/lnurl" });
  expect(res.statusCode).toBe(200);
  const body = res.json();
  expect(body.lnurl).toMatch(/^lnurl1/);
  return body as { lnurl: string; k1: string; expiresAt: number };
}

describe("LNURL-auth", () => {
  let app: any;
  let storage: MemorySignerStorage;
  beforeEach(async () => {
    ({ app, storage } = await buildApp());
  });

  it("completes the full login flow and shows nsec once for new accounts", async () => {
    const { k1 } = await startChallenge(app);
    const wallet = makeWallet();

    // Pending before callback
    const pending = await app.inject({ method: "GET", url: `/auth/lnurl/poll?k1=${k1}` });
    expect(pending.json().authenticated).toBe(false);

    const sig = signK1(wallet.privKey, k1);
    const cb = await app.inject({
      method: "GET",
      url: `/auth/lnurl/callback?tag=login&k1=${k1}&sig=${sig}&key=${wallet.pubKeyHex}`,
    });
    expect(cb.json().status).toBe("OK");

    const poll = await app.inject({ method: "GET", url: `/auth/lnurl/poll?k1=${k1}` });
    const body = poll.json();
    expect(body.authenticated).toBe(true);
    expect(body.session.sessionToken).toMatch(/^bao_sess_/);
    expect(body.session.authMethod).toBe("lightning");
    expect(body.session.isNewAccount).toBe(true);
    expect(body.session.nsec).toMatch(/^nsec1/); // shown once
    expect(body.session.relayBackupKey).toMatch(/^[0-9a-f]{32}$/);
  });

  it("returning wallet gets no nsec and is not a new account", async () => {
    const wallet = makeWallet();

    // First login
    const c1 = await startChallenge(app);
    const sig1 = signK1(wallet.privKey, c1.k1);
    await app.inject({ method: "GET", url: `/auth/lnurl/callback?tag=login&k1=${c1.k1}&sig=${sig1}&key=${wallet.pubKeyHex}` });
    const p1 = await app.inject({ method: "GET", url: `/auth/lnurl/poll?k1=${c1.k1}` });
    expect(p1.json().session.isNewAccount).toBe(true);

    // Second login
    const c2 = await startChallenge(app);
    const sig2 = signK1(wallet.privKey, c2.k1);
    await app.inject({ method: "GET", url: `/auth/lnurl/callback?tag=login&k1=${c2.k1}&sig=${sig2}&key=${wallet.pubKeyHex}` });
    const p2 = await app.inject({ method: "GET", url: `/auth/lnurl/poll?k1=${c2.k1}` });
    const s2 = p2.json().session;
    expect(s2.isNewAccount).toBe(false);
    expect(s2.nsec).toBeNull();
    expect(s2.pubkey).toBe(p1.json().session.pubkey); // stable identity
  });

  it("rejects an invalid signature", async () => {
    const { k1 } = await startChallenge(app);
    const wallet = makeWallet();
    const otherWallet = makeWallet();
    const sig = signK1(otherWallet.privKey, k1); // signed by wrong key
    const cb = await app.inject({
      method: "GET",
      url: `/auth/lnurl/callback?tag=login&k1=${k1}&sig=${sig}&key=${wallet.pubKeyHex}`,
    });
    expect(cb.json().status).toBe("ERROR");
    expect(cb.json().reason).toMatch(/invalid signature/i);
  });

  it("rejects replay of a used challenge", async () => {
    const { k1 } = await startChallenge(app);
    const wallet = makeWallet();
    const sig = signK1(wallet.privKey, k1);
    const url = `/auth/lnurl/callback?tag=login&k1=${k1}&sig=${sig}&key=${wallet.pubKeyHex}`;
    await app.inject({ method: "GET", url });
    const replay = await app.inject({ method: "GET", url });
    expect(replay.json().status).toBe("ERROR");
    expect(replay.json().reason).toMatch(/already used/i);
  });

  it("rejects unknown k1 at poll", async () => {
    const res = await app.inject({ method: "GET", url: `/auth/lnurl/poll?k1=${"ab".repeat(32)}` });
    expect(res.statusCode).toBe(404);
  });

  it("fails closed without a secret", async () => {
    const app2 = Fastify({ logger: false });
    app2.register(lnurlAuthRoutes, {
      storage: new MemorySignerStorage(),
      publicBaseUrl: "http://localhost/v1",
      secret: "",
    });
    await expect(app2.ready()).rejects.toThrow(/secret/);
  });

  it("MED-1: second poll gets 410 — no fresh session is minted", async () => {
    const { k1 } = await startChallenge(app);
    const wallet = makeWallet();
    const sig = signK1(wallet.privKey, k1);
    await app.inject({
      method: "GET",
      url: `/auth/lnurl/callback?tag=login&k1=${k1}&sig=${sig}&key=${wallet.pubKeyHex}`,
    });

    const first = await app.inject({ method: "GET", url: `/auth/lnurl/poll?k1=${k1}` });
    expect(first.json().authenticated).toBe(true);
    const token1 = first.json().session.sessionToken;

    // The challenge is deleted on first poll — a second poll is simply gone.
    const second = await app.inject({ method: "GET", url: `/auth/lnurl/poll?k1=${k1}` });
    expect(second.statusCode).toBe(404);
    expect(token1).toMatch(/^bao_sess_/);
  });

  it("MED-1: poll in the restart window (challenge alive, held token gone) fails 410 — no fresh session minted", async () => {
    const { k1 } = await startChallenge(app);
    const wallet = makeWallet();
    const sig = signK1(wallet.privKey, k1);
    await app.inject({
      method: "GET",
      url: `/auth/lnurl/callback?tag=login&k1=${k1}&sig=${sig}&key=${wallet.pubKeyHex}`,
    });

    // Simulate process restart: persistent challenge survives, in-memory
    // held token is lost.
    __dropHeldSessionTokenForTest(k1);

    const poll = await app.inject({ method: "GET", url: `/auth/lnurl/poll?k1=${k1}` });
    expect(poll.statusCode).toBe(410);
    expect(poll.json().error.code).toBe("LNURL_SESSION_CONSUMED");
    expect(poll.json().session?.sessionToken).toBeUndefined();
  });
});
