/**
 * passkeyAuth.test.ts
 *
 * Unit tests for the PRF passkey auth client:
 * - deriveNostrKeysFromPrfSeed
 * - extractPrfSeedFromResponse
 * - registerBreezPasskey
 * - loginBreezPasskey
 * - Error code consistency
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { bytesToHex } from "@noble/hashes/utils.js";

// ---------------------------------------------------------------------------
// Hoisted mocks
// ---------------------------------------------------------------------------

const mockStartRegistration = vi.hoisted(() => vi.fn());
const mockStartAuthentication = vi.hoisted(() => vi.fn());
const mockFetch = vi.hoisted(() => vi.fn());

function mockBufferToBase64URLString(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

vi.mock("@simplewebauthn/browser", () => ({
  startRegistration: mockStartRegistration,
  startAuthentication: mockStartAuthentication,
  bufferToBase64URLString: mockBufferToBase64URLString,
}));

import { configureBaoSignerClient } from "../../src/client/config.ts";

const TEST_API_BASE = "https://test-api.example.com";

vi.mock("../../src/client/prf", () => ({
  BAO_PRF_CONTEXT: "bao:prf:v1",
  BreezPasskeyError: {
    PRF_NOT_SUPPORTED: "PRF_NOT_SUPPORTED",
    PRF_RESULT_NOT_AVAILABLE: "PRF_RESULT_NOT_AVAILABLE",
    REGISTRATION_FAILED: "REGISTRATION_FAILED",
    LOGIN_FAILED: "LOGIN_FAILED",
    TIMEOUT: "TIMEOUT",
    SERVER_ERROR: "SERVER_ERROR",
  },
  BrowserPasskeyPrfProvider: class {
    async isPrfAvailable() {
      return true;
    }
  },
  base64URLStringToBuffer: (base64URLString: string) => {
    const base64 = base64URLString.replace(/-/g, "+").replace(/_/g, "/");
    const padLength = (4 - (base64.length % 4)) % 4;
    const padded = base64.padEnd(base64.length + padLength, "=");
    const binary = atob(padded);
    const buffer = new ArrayBuffer(binary.length);
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return buffer;
  },
  extractPrfFromAuthenticationResponse: () => null,
}));

// ---------------------------------------------------------------------------
// Imports (after mocks)
// ---------------------------------------------------------------------------

import type {
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
} from "@simplewebauthn/browser";
import {
  deriveNostrKeysFromPrfSeed,
  extractPrfSeedFromResponse,
  registerBreezPasskey,
  loginBreezPasskey,
  BreezPasskeyError,
} from "../../src/client/passkeyAuth.ts";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function mockResponse(body: unknown, ok = true, status = 200) {
  return Promise.resolve({
    ok,
    status,
    json: async () => body,
    text: async () => JSON.stringify(body),
  });
}

function makePrfCredential(opts: {
  prfResult?: Uint8Array;
  prfEnabled?: boolean;
}): RegistrationResponseJSON {
  const clientExtensionResults: Record<string, unknown> = {};
  if (opts.prfResult) {
    clientExtensionResults.prf = {
      results: { first: opts.prfResult.buffer },
    };
  } else if (opts.prfEnabled) {
    clientExtensionResults.prf = { enabled: true };
  }

  return {
    id: "test-cred-id",
    rawId: "dGVzdC1jcmVkLWlk",
    type: "public-key",
    response: {
      clientDataJSON: "e30",
      attestationObject: "AA",
    },
    clientExtensionResults,
    authenticatorAttachment: "platform",
  } as unknown as RegistrationResponseJSON;
}

function makeAuthCredential(opts: {
  prfResult?: Uint8Array;
}): AuthenticationResponseJSON {
  return {
    id: "test-cred-id",
    rawId: "dGVzdC1jcmVkLWlk",
    type: "public-key",
    response: {
      clientDataJSON: "e30",
      authenticatorData: "AA",
      signature: "AA",
      userHandle: "dXNlcg",
    },
    clientExtensionResults: opts.prfResult
      ? { prf: { results: { first: opts.prfResult.buffer } } }
      : {},
    authenticatorAttachment: "platform",
  } as unknown as AuthenticationResponseJSON;
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

beforeEach(() => {
  vi.clearAllMocks();
  mockFetch.mockReset();
  mockStartRegistration.mockReset();
  mockStartAuthentication.mockReset();

  configureBaoSignerClient({ apiBaseUrl: TEST_API_BASE });

  vi.stubGlobal("fetch", mockFetch);
  vi.stubGlobal("crypto", {
    getRandomValues: (arr: Uint8Array) => {
      arr.fill(0x42);
      return arr;
    },
  });
  vi.stubGlobal("navigator", {
    credentials: {
      get: vi.fn().mockResolvedValue(null),
    },
  });
  vi.stubGlobal("window", {
    location: { hostname: "localhost" },
  });
});

// ---------------------------------------------------------------------------
// deriveNostrKeysFromPrfSeed
// ---------------------------------------------------------------------------

describe("deriveNostrKeysFromPrfSeed", () => {
  it("returns deterministic keys for a known seed", () => {
    const seed = new Uint8Array(Array(32).fill(0x01));
    const result1 = deriveNostrKeysFromPrfSeed(seed);
    const result2 = deriveNostrKeysFromPrfSeed(seed);

    expect(result1.pubkeyHex).toBe(result2.pubkeyHex);
    expect(result1.npub).toBe(result2.npub);
    expect(result1.nsec).toBe(result2.nsec);
    expect(result1.privKeyBytes).toEqual(result2.privKeyBytes);
  });

  it("derives a valid-looking pubkey hex (64 chars)", () => {
    const seed = new Uint8Array(Array(32).fill(0xab));
    const { pubkeyHex } = deriveNostrKeysFromPrfSeed(seed);
    expect(pubkeyHex).toMatch(/^[0-9a-f]{64}$/);
  });

  it("derives npub and nsec that start with correct prefixes", () => {
    const seed = crypto.getRandomValues(new Uint8Array(32));
    const { npub, nsec } = deriveNostrKeysFromPrfSeed(seed);
    expect(npub).toMatch(/^npub1/);
    expect(nsec).toMatch(/^nsec1/);
  });

  it("privKeyBytes is 32 bytes", () => {
    const seed = new Uint8Array(Array(32).fill(0xcd));
    const { privKeyBytes } = deriveNostrKeysFromPrfSeed(seed);
    expect(privKeyBytes).toBeInstanceOf(Uint8Array);
    expect(privKeyBytes.length).toBe(32);
  });
});

// ---------------------------------------------------------------------------
// extractPrfSeedFromResponse
// ---------------------------------------------------------------------------

describe("extractPrfSeedFromResponse", () => {
  it("extracts PRF seed when prf.results.first is present", () => {
    const expected = new Uint8Array(Array(32).fill(0x42));
    const credential = makePrfCredential({ prfResult: expected });
    const result = extractPrfSeedFromResponse(credential);
    expect(result).toEqual(expected);
  });

  it("returns null when prf.results.first is absent", () => {
    const credential = makePrfCredential({});
    const result = extractPrfSeedFromResponse(credential);
    expect(result).toBeNull();
  });

  it("returns null when prf is absent", () => {
    const credential = {
      id: "cred-1",
      rawId: "cmF3",
      type: "public-key",
      response: {},
      clientExtensionResults: {},
    } as unknown as RegistrationResponseJSON;
    expect(extractPrfSeedFromResponse(credential)).toBeNull();
  });

  it("works with AuthenticationResponseJSON too", () => {
    const expected = new Uint8Array(Array(32).fill(0x99));
    const credential = makeAuthCredential({ prfResult: expected });
    const result = extractPrfSeedFromResponse(credential);
    expect(result).toEqual(expected);
  });
});

// ---------------------------------------------------------------------------
// registerBreezPasskey
// ---------------------------------------------------------------------------

describe("registerBreezPasskey", () => {
  it("completes full registration flow with PRF seed", async () => {
    const prfSeed = new Uint8Array(Array(32).fill(0xab));
    const credential = makePrfCredential({ prfResult: prfSeed });

    mockFetch
      .mockResolvedValueOnce(
        mockResponse({
          challengeId: "ch-1",
          options: { rp: { id: "localhost" } },
        }),
      )
      .mockResolvedValueOnce(
        mockResponse({
          session: {
            sessionToken: "token-1",
            expires_at: 1234567890,
            firstLogin: true,
            relayBackupKey: "backup-1",
            username: "testuser",
          },
        }),
      );

    mockStartRegistration.mockResolvedValue(credential);

    const result = await registerBreezPasskey({
      username: "testuser",
      displayName: "Test User",
    });

    expect(result.credential).toBe(credential);
    expect(result.prfSeed).toEqual(prfSeed);
    // prfSeedHex is the raw PRF seed (hex) — NOT the Nostr private key.
    expect(result.prfSeedHex).toBe(bytesToHex(prfSeed));
    // The actual Nostr secret key must differ from the raw PRF seed.
    const { privKeyBytes } = deriveNostrKeysFromPrfSeed(prfSeed);
    expect(bytesToHex(privKeyBytes)).not.toBe(result.prfSeedHex);
    expect(result.credentialId).toBe("test-cred-id");
    expect(result.session?.sessionToken).toBe("token-1");
    expect(result.pubkeyHex).toMatch(/^[0-9a-f]{64}$/);
    expect(result.npub).toMatch(/^npub1/);
    expect(result.nsec).toMatch(/^nsec1/);

    // Verify fetch calls
    const [call1, call2] = mockFetch.mock.calls;
    expect(call1[0]).toContain("/v1/auth/passkey/register-options");
    expect(call2[0]).toContain("/v1/auth/passkey/register");
    const regBody = JSON.parse(call2[1].body);
    expect(regBody.challengeId).toBe("ch-1");
    expect(regBody.pubkey).toBe(result.pubkeyHex);
  });

  it("throws SERVER_ERROR when register-options fetch fails", async () => {
    mockFetch.mockResolvedValueOnce(mockResponse({}, false, 500));

    await expect(registerBreezPasskey()).rejects.toThrow(
      BreezPasskeyError.SERVER_ERROR,
    );
  });

  it("throws REGISTRATION_FAILED when register endpoint fails", async () => {
    const prfSeed = new Uint8Array(Array(32).fill(0xab));
    mockFetch
      .mockResolvedValueOnce(
        mockResponse({ challengeId: "ch-1", options: { rp: { id: "localhost" } } }),
      )
      .mockResolvedValueOnce(mockResponse({}, false, 400));

    mockStartRegistration.mockResolvedValue(
      makePrfCredential({ prfResult: prfSeed }),
    );

    await expect(registerBreezPasskey()).rejects.toThrow(
      BreezPasskeyError.REGISTRATION_FAILED,
    );
  });

  it("throws PRF_NOT_SUPPORTED when PRF result is missing and prf.enabled is false", async () => {
    mockFetch.mockResolvedValueOnce(
      mockResponse({ challengeId: "ch-1", options: { rp: { id: "localhost" } } }),
    );

    mockStartRegistration.mockResolvedValue(makePrfCredential({}));

    await expect(registerBreezPasskey()).rejects.toThrow(
      BreezPasskeyError.PRF_NOT_SUPPORTED,
    );
  });

  it("throws PRF_RESULT_NOT_AVAILABLE when self-auth throws", async () => {
    mockFetch.mockResolvedValueOnce(
      mockResponse({ challengeId: "ch-1", options: { rp: { id: "localhost" } } }),
    );

    mockStartRegistration.mockResolvedValue(
      makePrfCredential({ prfEnabled: true }),
    );

    mockStartAuthentication.mockRejectedValue(
      new Error("Self-auth failed"),
    );

    await expect(registerBreezPasskey()).rejects.toThrow(
      BreezPasskeyError.PRF_RESULT_NOT_AVAILABLE,
    );
  });

  it("recovers PRF seed via self-auth when creation returns enabled but no result", async () => {
    const prfSeed = new Uint8Array(Array(32).fill(0xde));
    mockFetch
      .mockResolvedValueOnce(
        mockResponse({
          challengeId: "ch-1",
          options: { rp: { id: "localhost" } },
        }),
      )
      .mockResolvedValueOnce(
        mockResponse({
          session: {
            sessionToken: "token-2",
            expires_at: 1234567890,
            firstLogin: true,
            relayBackupKey: "backup-2",
            username: "testuser2",
          },
        }),
      );

    mockStartRegistration.mockResolvedValue(
      makePrfCredential({ prfEnabled: true }),
    );

    mockStartAuthentication.mockResolvedValue(
      makeAuthCredential({ prfResult: prfSeed }),
    );

    const result = await registerBreezPasskey();
    expect(result.prfSeed).toEqual(prfSeed);
    expect(mockStartAuthentication).toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// loginBreezPasskey
// ---------------------------------------------------------------------------

describe("loginBreezPasskey", () => {
  it("completes full login flow with PRF seed", async () => {
    const prfSeed = new Uint8Array(Array(32).fill(0xef));
    const assertion = makeAuthCredential({ prfResult: prfSeed });

    mockFetch
      .mockResolvedValueOnce(
        mockResponse({ challengeId: "ch-login", options: { rpId: "localhost" } }),
      )
      .mockResolvedValueOnce(
        mockResponse({
          session: {
            sessionToken: "login-token",
            pubkey: "a".repeat(64),
            npub: "npub1login",
            username: "loguser",
          },
        }),
      );

    mockStartAuthentication.mockResolvedValue(assertion);

    const result = await loginBreezPasskey();

    expect(result.assertion).toBe(assertion);
    expect(result.prfSeed).toEqual(prfSeed);
    expect(result.credentialId).toBe("test-cred-id");
    expect(result.session.sessionToken).toBe("login-token");
    expect(result.pubkeyHex).toMatch(/^[0-9a-f]{64}$/);

    const [call1, call2] = mockFetch.mock.calls;
    expect(call1[0]).toContain("/v1/auth/passkey/login-options");
    expect(call2[0]).toContain("/v1/auth/passkey/login");
    const loginBody = JSON.parse(call2[1].body);
    expect(loginBody.pubkey).toBe(result.pubkeyHex);
  });

  it("throws SERVER_ERROR when login-options fetch fails", async () => {
    mockFetch.mockResolvedValueOnce(mockResponse({}, false, 500));

    await expect(loginBreezPasskey()).rejects.toThrow(
      BreezPasskeyError.SERVER_ERROR,
    );
  });

  it("throws PRF_NOT_SUPPORTED when assertion has no PRF result", async () => {
    mockFetch.mockResolvedValueOnce(
      mockResponse({ challengeId: "ch-login", options: { rpId: "localhost" } }),
    );

    mockStartAuthentication.mockResolvedValue(makeAuthCredential({}));

    await expect(loginBreezPasskey()).rejects.toThrow(
      BreezPasskeyError.PRF_NOT_SUPPORTED,
    );
  });

  it("throws LOGIN_FAILED when login endpoint fails", async () => {
    const prfSeed = new Uint8Array(Array(32).fill(0xef));
    mockFetch
      .mockResolvedValueOnce(
        mockResponse({ challengeId: "ch-login", options: { rpId: "localhost" } }),
      )
      .mockResolvedValueOnce(mockResponse({}, false, 400));

    mockStartAuthentication.mockResolvedValue(
      makeAuthCredential({ prfResult: prfSeed }),
    );

    await expect(loginBreezPasskey()).rejects.toThrow(
      BreezPasskeyError.LOGIN_FAILED,
    );
  });
});

// ---------------------------------------------------------------------------
// Error code consistency
// ---------------------------------------------------------------------------

describe("Error code consistency", () => {
  it("all register errors contain BreezPasskeyError codes", async () => {
    const tests = [
      {
        name: "register-options 500",
        setup: () => mockFetch.mockResolvedValueOnce(mockResponse({}, false, 500)),
        expected: BreezPasskeyError.SERVER_ERROR,
        fn: () => registerBreezPasskey(),
      },
      {
        name: "missing PRF result",
        setup: () => {
          mockFetch.mockResolvedValueOnce(
            mockResponse({ challengeId: "ch-1", options: { rp: { id: "localhost" } } }),
          );
          mockStartRegistration.mockResolvedValue(makePrfCredential({}));
        },
        expected: BreezPasskeyError.PRF_NOT_SUPPORTED,
        fn: () => registerBreezPasskey(),
      },
      {
        name: "register endpoint 400",
        setup: () => {
          mockFetch
            .mockResolvedValueOnce(
              mockResponse({ challengeId: "ch-1", options: { rp: { id: "localhost" } } }),
            )
            .mockResolvedValueOnce(mockResponse({}, false, 400));
          mockStartRegistration.mockResolvedValue(
            makePrfCredential({ prfResult: new Uint8Array(32) }),
          );
        },
        expected: BreezPasskeyError.REGISTRATION_FAILED,
        fn: () => registerBreezPasskey(),
      },
    ];

    for (const t of tests) {
      vi.clearAllMocks();
      mockFetch.mockReset();
      mockStartRegistration.mockReset();
      mockStartAuthentication.mockReset();
      t.setup();
      await expect(t.fn()).rejects.toThrow(t.expected);
    }
  });

  it("all login errors contain BreezPasskeyError codes", async () => {
    const tests = [
      {
        name: "login-options 500",
        setup: () => mockFetch.mockResolvedValueOnce(mockResponse({}, false, 500)),
        expected: BreezPasskeyError.SERVER_ERROR,
        fn: () => loginBreezPasskey(),
      },
      {
        name: "missing PRF on auth",
        setup: () => {
          mockFetch.mockResolvedValueOnce(
            mockResponse({ challengeId: "ch-login", options: { rpId: "localhost" } }),
          );
          mockStartAuthentication.mockResolvedValue(makeAuthCredential({}));
        },
        expected: BreezPasskeyError.PRF_NOT_SUPPORTED,
        fn: () => loginBreezPasskey(),
      },
      {
        name: "login endpoint 400",
        setup: () => {
          mockFetch
            .mockResolvedValueOnce(
              mockResponse({ challengeId: "ch-login", options: { rpId: "localhost" } }),
            )
            .mockResolvedValueOnce(mockResponse({}, false, 400));
          mockStartAuthentication.mockResolvedValue(
            makeAuthCredential({ prfResult: new Uint8Array(32) }),
          );
        },
        expected: BreezPasskeyError.LOGIN_FAILED,
        fn: () => loginBreezPasskey(),
      },
    ];

    for (const t of tests) {
      vi.clearAllMocks();
      mockFetch.mockReset();
      mockStartRegistration.mockReset();
      mockStartAuthentication.mockReset();
      t.setup();
      await expect(t.fn()).rejects.toThrow(t.expected);
    }
  });
});
