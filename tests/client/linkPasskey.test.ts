/**
 * Regression tests for HIGH-2: the client can now complete the authenticated
 * account-link passkey flow against the reference server
 * (/auth/link/passkey/options + /auth/link/passkey/register with Bearer auth).
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

const mockStartRegistration = vi.hoisted(() => vi.fn());
const mockStartAuthentication = vi.hoisted(() => vi.fn());
const mockFetch = vi.hoisted(() => vi.fn());

vi.mock("@simplewebauthn/browser", () => ({
  startRegistration: mockStartRegistration,
  startAuthentication: mockStartAuthentication,
  bufferToBase64URLString: (buf: ArrayBuffer) => {
    const bytes = new Uint8Array(buf);
    let binary = "";
    for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  },
}));

import { configureBaoSignerClient } from "../../src/client/config.ts";
import {
  linkPasskeyOptions,
  linkPasskeyRegister,
  linkBreezPasskey,
} from "../../src/client/passkeyAuth.ts";

const TEST_API_BASE = "http://localhost:4100/bao-api";
const SESSION = "bao_sess_testtoken";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  mockFetch.mockReset();
  mockStartRegistration.mockReset();
  configureBaoSignerClient({ apiBaseUrl: TEST_API_BASE });
  vi.stubGlobal("fetch", mockFetch);
  vi.stubGlobal("window", { location: { hostname: "localhost" } });
});

describe("linkPasskeyOptions", () => {
  it("posts with Bearer auth and returns challengeId + options", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({ challengeId: "ch_1", options: { challenge: "abc", rp: { id: "localhost" } } }),
    );
    const out = await linkPasskeyOptions({ sessionToken: SESSION });
    expect(out.challengeId).toBe("ch_1");
    const [url, init] = mockFetch.mock.calls[0];
    expect(url).toBe(`${TEST_API_BASE}/v1/auth/link/passkey/options`);
    expect(init.method).toBe("POST");
    expect(init.headers.Authorization).toBe(`Bearer ${SESSION}`);
    // Regression: JSON-typed POSTs MUST carry a body (server 400s bodiless JSON).
    expect(init.body).toBe("{}");
  });

  it("throws on server error", async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({}, 401));
    await expect(linkPasskeyOptions({ sessionToken: SESSION })).rejects.toThrow(/401/);
  });
});

describe("linkPasskeyRegister", () => {
  it("posts challengeId + credential with Bearer auth", async () => {
    mockFetch.mockResolvedValueOnce(jsonResponse({ linked: true, credentialId: "cred_1" }));
    const out = await linkPasskeyRegister({
      sessionToken: SESSION,
      challengeId: "ch_1",
      credential: { id: "cred_1" } as never,
    });
    expect(out.linked).toBe(true);
    const [url, init] = mockFetch.mock.calls[0];
    expect(url).toBe(`${TEST_API_BASE}/v1/auth/link/passkey/register`);
    expect(init.headers.Authorization).toBe(`Bearer ${SESSION}`);
    const body = JSON.parse(init.body);
    expect(body.challengeId).toBe("ch_1");
    expect(body.credential.id).toBe("cred_1");
  });

  it("surfaces the server error detail", async () => {
    mockFetch.mockResolvedValueOnce(
      jsonResponse({ error: { code: "CHALLENGE_MISMATCH", message: "Challenge does not belong to current session" } }, 401),
    );
    await expect(
      linkPasskeyRegister({ sessionToken: SESSION, challengeId: "ch_x", credential: { id: "c" } as never }),
    ).rejects.toThrow(/CHALLENGE_MISMATCH|does not belong/);
  });
});

describe("linkBreezPasskey (full flow)", () => {
  it("options → PRF-injected create → derive → register, all with Bearer", async () => {
    const seed = new Uint8Array(32).fill(0x11);
    mockFetch
      .mockResolvedValueOnce(jsonResponse({
        challengeId: "ch_link",
        options: { challenge: "abc", rp: { id: "localhost", name: "BAO" }, user: { id: "u" }, pubKeyCredParams: [] },
      }))
      .mockResolvedValueOnce(jsonResponse({ linked: true, credentialId: "cred_link" }));

    mockStartRegistration.mockResolvedValueOnce({
      id: "cred_link",
      rawId: "cred_link",
      clientExtensionResults: { prf: { results: { first: seed.buffer } } },
    });

    const out = await linkBreezPasskey({ sessionToken: SESSION });

    // PRF extension was injected into the server-provided options
    const regArgs = mockStartRegistration.mock.calls[0][0];
    expect(regArgs.optionsJSON.extensions.prf.eval.first).toBeDefined();

    // Deterministic identity derived from the PRF seed
    expect(out.pubkeyHex).toMatch(/^[0-9a-f]{64}$/);
    expect(out.nsec).toMatch(/^nsec1/);
    expect(out.credentialId).toBe("cred_link");

    // Both HTTP calls carried the Bearer token
    for (const call of mockFetch.mock.calls) {
      expect(call[1].headers.Authorization).toBe(`Bearer ${SESSION}`);
    }
    // Register call sent the session-bound challengeId
    const regBody = JSON.parse(mockFetch.mock.calls[1][1].body);
    expect(regBody.challengeId).toBe("ch_link");
  });
});
