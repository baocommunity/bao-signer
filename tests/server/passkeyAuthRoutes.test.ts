/**
 * Route-level tests for the bao-signer server plugin.
 *
 * @simplewebauthn/server is mocked — these tests exercise the route policy
 * (challenge lifecycle, PRF rejection, pubkey binding, session issuance),
 * not the WebAuthn crypto itself (which SimpleWebAuthn's own suite covers).
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

const mockGenerateRegistrationOptions = vi.hoisted(() => vi.fn());
const mockVerifyRegistrationResponse = vi.hoisted(() => vi.fn());
const mockGenerateAuthenticationOptions = vi.hoisted(() => vi.fn());
const mockVerifyAuthenticationResponse = vi.hoisted(() => vi.fn());

vi.mock("@simplewebauthn/server", () => ({
  generateRegistrationOptions: mockGenerateRegistrationOptions,
  verifyRegistrationResponse: mockVerifyRegistrationResponse,
  generateAuthenticationOptions: mockGenerateAuthenticationOptions,
  verifyAuthenticationResponse: mockVerifyAuthenticationResponse,
}));

import Fastify from "fastify";
import { baoSignerAuthRoutes } from "../../src/server/passkeyAuthRoutes.ts";
import { MemorySignerStorage } from "../../src/server/storage.ts";
import { untrustedPasskeyRegistrationError } from "../../src/server/passkeyAuthRoutes.ts";

const SECRET = "test-backup-secret";

async function buildApp(opts: { withAuth?: boolean; noMint?: boolean } = {}) {
  const app = Fastify({ logger: false });
  const storage = new MemorySignerStorage();
  await app.register(baoSignerAuthRoutes, {
    storage,
    rpId: "localhost",
    expectedOrigins: ["http://localhost:3000"],
    backupSecret: SECRET,
    ...(opts.withAuth
      ? {
          authenticate: async (req: any) => {
            const token = req.headers.authorization?.replace(/^Bearer /, "");
            const session = token ? await storage.getSession(token) : undefined;
            return session?.pubkey ?? null;
          },
        }
      : {}),
    ...(opts.noMint ? { allowServerKeyGeneration: false } : {}),
  });
  return { app, storage };
}

async function getRegisterOptions(app: any, username = "alice") {
  mockGenerateRegistrationOptions.mockResolvedValue({
    challenge: "reg-challenge",
    rp: { name: "BAO Signer", id: "localhost" },
  });
  const res = await app.inject({
    method: "POST",
    url: "/auth/passkey/register-options",
    payload: { username },
  });
  expect(res.statusCode).toBe(200);
  return res.json();
}

function verifiedRegistration(credentialId = "cred-1") {
  mockVerifyRegistrationResponse.mockResolvedValue({
    verified: true,
    registrationInfo: {
      credential: {
        id: credentialId,
        publicKey: new Uint8Array(33).fill(2),
        counter: 1,
        transports: ["internal"],
      },
    },
  });
}

describe("untrustedPasskeyRegistrationError", () => {
  it("rejects client-supplied pubkeys", () => {
    expect(untrustedPasskeyRegistrationError("a".repeat(64))).toBe(
      "PRF_ACCOUNT_LINK_REQUIRES_AUTH",
    );
  });
  it("accepts server-generated flow", () => {
    expect(untrustedPasskeyRegistrationError()).toBeNull();
  });
});

describe("POST /auth/passkey/register", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("rejects anonymous PRF registration (client-supplied pubkey)", async () => {
    const { app } = await buildApp();
    const { challengeId } = await getRegisterOptions(app);
    verifiedRegistration();

    const res = await app.inject({
      method: "POST",
      url: "/auth/passkey/register",
      payload: {
        challengeId,
        credential: { id: "cred-1", type: "public-key", response: {} },
        pubkey: "ab".repeat(32),
      },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe("PRF_ACCOUNT_LINK_REQUIRES_AUTH");
  });

  it("registers a server-generated account and shows nsec once", async () => {
    const { app } = await buildApp();
    const { challengeId } = await getRegisterOptions(app);
    verifiedRegistration();

    const res = await app.inject({
      method: "POST",
      url: "/auth/passkey/register",
      payload: {
        challengeId,
        credential: { id: "cred-1", type: "public-key", response: {} },
      },
    });

    expect(res.statusCode).toBe(200);
    const { session } = res.json();
    expect(session.pubkey).toMatch(/^[0-9a-f]{64}$/);
    expect(session.nsec).toMatch(/^nsec1/);
    expect(session.sessionToken).toBeTruthy();
    expect(session.relayBackupKey).toMatch(/^[0-9a-f]{32}$/);
    expect(session.firstLogin).toBe(true);
  });

  it("rejects unknown/expired challenges", async () => {
    const { app } = await buildApp();
    const res = await app.inject({
      method: "POST",
      url: "/auth/passkey/register",
      payload: {
        challengeId: "nope",
        credential: { id: "cred-1", type: "public-key", response: {} },
      },
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe("PASSKEY_CHALLENGE_NOT_FOUND");
  });

  it("self-custody mode: rejects anonymous server-key registration (403)", async () => {
    const { app } = await buildApp({ noMint: true });
    const { challengeId } = await getRegisterOptions(app);
    verifiedRegistration();

    const res = await app.inject({
      method: "POST",
      url: "/auth/passkey/register",
      payload: {
        challengeId,
        credential: { id: "cred-1", type: "public-key", response: {} },
      },
    });

    expect(res.statusCode).toBe(403);
    expect(res.json().error.code).toBe("ACCOUNT_CREATION_DISABLED");
  });

  it("rejects duplicate credential registration", async () => {
    const { app } = await buildApp();
    const first = await getRegisterOptions(app);
    verifiedRegistration("cred-dup");
    const res1 = await app.inject({
      method: "POST",
      url: "/auth/passkey/register",
      payload: {
        challengeId: first.challengeId,
        credential: { id: "cred-dup", type: "public-key", response: {} },
      },
    });
    expect(res1.statusCode).toBe(200);

    const second = await getRegisterOptions(app);
    verifiedRegistration("cred-dup");
    const res2 = await app.inject({
      method: "POST",
      url: "/auth/passkey/register",
      payload: {
        challengeId: second.challengeId,
        credential: { id: "cred-dup", type: "public-key", response: {} },
      },
    });
    expect(res2.statusCode).toBe(400);
    expect(res2.json().error.code).toBe("PASSKEY_ALREADY_REGISTERED");
  });
});

describe("POST /auth/passkey/login", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  async function registerAccount(app: any) {
    const { challengeId } = await getRegisterOptions(app);
    verifiedRegistration("cred-login");
    const res = await app.inject({
      method: "POST",
      url: "/auth/passkey/register",
      payload: {
        challengeId,
        credential: { id: "cred-login", type: "public-key", response: {} },
      },
    });
    return res.json().session;
  }

  it("logs in with the bound pubkey and bumps the counter", async () => {
    const { app, storage } = await buildApp();
    const session = await registerAccount(app);

    mockGenerateAuthenticationOptions.mockResolvedValue({ challenge: "login-challenge" });
    const optRes = await app.inject({ method: "POST", url: "/auth/passkey/login-options" });
    const { challengeId } = optRes.json();

    mockVerifyAuthenticationResponse.mockResolvedValue({
      verified: true,
      authenticationInfo: { newCounter: 2 },
    });
    const res = await app.inject({
      method: "POST",
      url: "/auth/passkey/login",
      payload: {
        challengeId,
        credential: { id: "cred-login", type: "public-key", response: {} },
        pubkey: session.pubkey,
      },
    });

    expect(res.statusCode).toBe(200);
    expect(res.json().session.pubkey).toBe(session.pubkey);
    expect((await storage.getCredentialById("cred-login"))?.counter).toBe(2);
  });

  it("rejects a wrong pubkey for the credential", async () => {
    const { app } = await buildApp();
    await registerAccount(app);

    mockGenerateAuthenticationOptions.mockResolvedValue({ challenge: "login-challenge" });
    const optRes = await app.inject({ method: "POST", url: "/auth/passkey/login-options" });
    const { challengeId } = optRes.json();

    const res = await app.inject({
      method: "POST",
      url: "/auth/passkey/login",
      payload: {
        challengeId,
        credential: { id: "cred-login", type: "public-key", response: {} },
        pubkey: "cd".repeat(32),
      },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error.code).toBe("PUBKEY_MISMATCH");
  });

  it("never stores a lower counter (synced-passkey regression)", async () => {
    const { app, storage } = await buildApp();
    const session = await registerAccount(app);

    // First login at counter 5
    mockGenerateAuthenticationOptions.mockResolvedValue({ challenge: "c1" });
    const o1 = await app.inject({ method: "POST", url: "/auth/passkey/login-options" });
    mockVerifyAuthenticationResponse.mockResolvedValue({
      verified: true,
      authenticationInfo: { newCounter: 5 },
    });
    await app.inject({
      method: "POST",
      url: "/auth/passkey/login",
      payload: {
        challengeId: o1.json().challengeId,
        credential: { id: "cred-login", type: "public-key", response: {} },
        pubkey: session.pubkey,
      },
    });
    expect((await storage.getCredentialById("cred-login"))?.counter).toBe(5);

    // Regression to 0 (synced passkey): tolerated, but counter stays 5
    const o2 = await app.inject({ method: "POST", url: "/auth/passkey/login-options" });
    mockVerifyAuthenticationResponse.mockResolvedValue({
      verified: true,
      authenticationInfo: { newCounter: 0 },
    });
    const res = await app.inject({
      method: "POST",
      url: "/auth/passkey/login",
      payload: {
        challengeId: o2.json().challengeId,
        credential: { id: "cred-login", type: "public-key", response: {} },
        pubkey: session.pubkey,
      },
    });
    expect(res.statusCode).toBe(200);
    expect((await storage.getCredentialById("cred-login"))?.counter).toBe(5);
  });
});

describe("plugin configuration", () => {
  it("fails closed without a backup secret", async () => {
    const app = Fastify({ logger: false });
    app.register(baoSignerAuthRoutes, {
      storage: new MemorySignerStorage(),
      rpId: "localhost",
      expectedOrigins: ["http://localhost:3000"],
      backupSecret: "",
    });
    await expect(app.ready()).rejects.toThrow(/backupSecret/);
  });
});

describe("authenticated link flow", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("links a passkey to the session's account only", async () => {
    const { app, storage } = await buildApp({ withAuth: true });

    // Register an account first (server-generated path)
    const { challengeId } = await getRegisterOptions(app);
    verifiedRegistration("cred-base");
    const regRes = await app.inject({
      method: "POST",
      url: "/auth/passkey/register",
      payload: {
        challengeId,
        credential: { id: "cred-base", type: "public-key", response: {} },
      },
    });
    const session = regRes.json().session;

    // Get link options with the session token
    mockGenerateRegistrationOptions.mockResolvedValue({ challenge: "link-challenge" });
    const optRes = await app.inject({
      method: "POST",
      url: "/auth/link/passkey/options",
      headers: { authorization: `Bearer ${session.sessionToken}` },
    });
    expect(optRes.statusCode).toBe(200);

    verifiedRegistration("cred-linked");
    const linkRes = await app.inject({
      method: "POST",
      url: "/auth/link/passkey/register",
      headers: { authorization: `Bearer ${session.sessionToken}` },
      payload: {
        challengeId: optRes.json().challengeId,
        credential: { id: "cred-linked", type: "public-key", response: {} },
      },
    });
    expect(linkRes.statusCode).toBe(200);
    expect(linkRes.json().linked).toBe(true);
    expect((await storage.getCredentialById("cred-linked"))?.pubkey).toBe(session.pubkey);
  });

  it("rejects link attempts without a session", async () => {
    const { app } = await buildApp({ withAuth: true });
    const res = await app.inject({ method: "POST", url: "/auth/link/passkey/options" });
    expect(res.statusCode).toBe(401);
  });
});
