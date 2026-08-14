/**
 * Guest + Nostr NIP-98 auth route tests — real signatures, no crypto mocks.
 */
import { describe, it, expect, beforeEach } from "vitest";
import Fastify from "fastify";
import { finalizeEvent, generateSecretKey, getPublicKey } from "nostr-tools";
import { nip98ChallengeRoutes } from "../../src/server/nip98.ts";
import { guestAuthRoutes } from "../../src/server/guestAuthRoutes.ts";
import { nostrAuthRoutes } from "../../src/server/nostrAuthRoutes.ts";
import { MemorySignerStorage } from "../../src/server/storage.ts";

async function buildApp() {
  const app = Fastify({ logger: false });
  const storage = new MemorySignerStorage();
  await app.register(nip98ChallengeRoutes);
  await app.register(guestAuthRoutes, { storage });
  await app.register(nostrAuthRoutes, { storage });
  return { app, storage };
}

async function getChallenge(app: any): Promise<string> {
  const res = await app.inject({ method: "GET", url: "/auth/challenge" });
  expect(res.statusCode).toBe(200);
  return res.json().challenge;
}

function signEvent(
  secretKey: Uint8Array,
  path: string,
  challenge: string,
  overrides: Partial<{ kind: number; created_at: number; u: string }> = {},
) {
  return finalizeEvent(
    {
      kind: overrides.kind ?? 27235,
      created_at: overrides.created_at ?? Math.floor(Date.now() / 1000),
      tags: [
        ["u", overrides.u ?? `http://localhost${path}`],
        ["method", "POST"],
        ["challenge", challenge],
      ],
      content: "",
    },
    secretKey,
  );
}

describe("POST /auth/guest", () => {
  let app: any;
  let storage: MemorySignerStorage;
  beforeEach(async () => {
    ({ app, storage } = await buildApp());
  });

  it("issues a guest session for a valid signed event", async () => {
    const sk = generateSecretKey();
    const challenge = await getChallenge(app);
    const event = signEvent(sk, "/auth/guest", challenge);

    const res = await app.inject({ method: "POST", url: "/auth/guest", payload: { event } });
    expect(res.statusCode).toBe(201);
    const body = res.json();
    expect(body.sessionToken).toMatch(/^bao_sess_/);
    expect(body.pubkey).toBe(getPublicKey(sk));
    expect(body.authMethod).toBe("guest");
  });

  it("rejects replay of the same challenge", async () => {
    const sk = generateSecretKey();
    const challenge = await getChallenge(app);
    const event = signEvent(sk, "/auth/guest", challenge);

    const first = await app.inject({ method: "POST", url: "/auth/guest", payload: { event } });
    expect(first.statusCode).toBe(201);

    const second = await app.inject({ method: "POST", url: "/auth/guest", payload: { event } });
    expect(second.statusCode).toBe(401);
    expect(second.json().error.code).toBe("INVALID_CHALLENGE");
  });

  it("rejects wrong kind", async () => {
    const sk = generateSecretKey();
    const challenge = await getChallenge(app);
    const event = signEvent(sk, "/auth/guest", challenge, { kind: 1 });
    const res = await app.inject({ method: "POST", url: "/auth/guest", payload: { event } });
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe("INVALID_KIND");
  });

  it("rejects stale events", async () => {
    const sk = generateSecretKey();
    const challenge = await getChallenge(app);
    const event = signEvent(sk, "/auth/guest", challenge, {
      created_at: Math.floor(Date.now() / 1000) - 600,
    });
    const res = await app.inject({ method: "POST", url: "/auth/guest", payload: { event } });
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe("EVENT_TOO_OLD");
  });

  it("rejects events bound to a different endpoint", async () => {
    const sk = generateSecretKey();
    const challenge = await getChallenge(app);
    const event = signEvent(sk, "/auth/guest", challenge, { u: "http://localhost/auth/nostr" });
    const res = await app.inject({ method: "POST", url: "/auth/guest", payload: { event } });
    expect(res.statusCode).toBe(401);
    expect(res.json().error.code).toBe("INVALID_NIP98_BINDING");
  });

  it("rejects invalid signatures", async () => {
    const sk = generateSecretKey();
    const challenge = await getChallenge(app);
    const event = signEvent(sk, "/auth/guest", challenge);
    event.sig = "ff".repeat(64); // tamper
    const res = await app.inject({ method: "POST", url: "/auth/guest", payload: { event } });
    expect(res.statusCode).toBe(401);
  });
});

describe("POST /auth/nostr", () => {
  let app: any;
  let storage: MemorySignerStorage;
  beforeEach(async () => {
    ({ app, storage } = await buildApp());
  });

  it("issues a long-lived session and creates a nostr-only account", async () => {
    const sk = generateSecretKey();
    const challenge = await getChallenge(app);
    const event = signEvent(sk, "/auth/nostr", challenge);

    const res = await app.inject({ method: "POST", url: "/auth/nostr", payload: { event } });
    expect(res.statusCode).toBe(201);
    const body = res.json();
    expect(body.sessionToken).toMatch(/^bao_sess_/);
    expect(body.expires_at - Math.floor(Date.now() / 1000)).toBeGreaterThan(29 * 24 * 3600);
    expect(await storage.getAccount(getPublicKey(sk))).toBeTruthy();
  });
});
