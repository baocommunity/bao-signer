/**
 * loginFlows.test.ts — self-custody onboarding helpers:
 * createSelfCustodyAccount (client-only key generation) and emailRegisterKey
 * (bind a client key to an email via the server).
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { nip19 } from "nostr-tools";
import { createSelfCustodyAccount, emailRegisterKey } from "../../src/client/loginFlows.ts";
import { createSeedIdentitySigner } from "../../src/client/seedIdentity.ts";
import { configureBaoSignerClient } from "../../src/client/config.ts";

describe("createSelfCustodyAccount", () => {
  it("returns a 24-word phrase and a matching self-custodial identity", () => {
    const acct = createSelfCustodyAccount();
    expect(acct.phrase.split(" ")).toHaveLength(24);

    // The returned pubkey/nsec must match a fresh derivation from the phrase.
    const direct = createSeedIdentitySigner(acct.phrase);
    expect(acct.pubkey).toBe(direct.pubkey);
    expect(acct.nsec).toBe(direct.nsec);
    expect(acct.npub).toBe(nip19.npubEncode(acct.pubkey));

    const decoded = nip19.decode(acct.nsec);
    expect(decoded.type).toBe("nsec");
  });

  it("produces distinct identities per call", () => {
    const a = createSelfCustodyAccount();
    const b = createSelfCustodyAccount();
    expect(a.pubkey).not.toBe(b.pubkey);
    expect(a.phrase).not.toBe(b.phrase);
  });
});

describe("emailRegisterKey", () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    configureBaoSignerClient({ apiBaseUrl: "https://api.example.com" });
    fetchMock.mockReset();
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("posts the nsec + code to /auth/email/register", async () => {
    fetchMock.mockResolvedValue({
      ok: true,
      json: async () => ({ registered: true, pubkey: "ab".repeat(32) }),
    });

    const out = await emailRegisterKey({
      email: "a@b.com",
      nsec: "nsec1test",
      username: "u",
      code: "123456",
    });

    expect(out).toEqual({ registered: true, pubkey: "ab".repeat(32) });
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("https://api.example.com/v1/auth/email/register");
    expect(JSON.parse(init.body)).toEqual({
      email: "a@b.com",
      nsec: "nsec1test",
      username: "u",
      code: "123456",
    });
  });

  it("surfaces the server error message", async () => {
    fetchMock.mockResolvedValue({
      ok: false,
      status: 409,
      json: async () => ({ error: "already registered" }),
    });

    await expect(
      emailRegisterKey({ email: "a@b.com", nsec: "nsec1test", username: "u", code: "123456" }),
    ).rejects.toThrow(/already registered/);
  });
});
