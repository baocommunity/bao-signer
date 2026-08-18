/**
 * nip07 tests — gesture-safe extension connect, cached pubkey, denial cache,
 * popup-honest timeout. Mocks window.nostr (no real extension needed).
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  clearNip07PublicKeyCache,
  connectNip07Signer,
  getNip07Extension,
  getNip07PublicKey,
  isNip07Available,
} from "../../src/client/nip07.ts";

const PK = "a".repeat(64);

function stubNostr(impl?: {
  getPublicKey?: () => Promise<string>;
  signEvent?: (e: unknown) => Promise<unknown>;
  nip44?: { encrypt: (p: string, t: string) => Promise<string>; decrypt: (p: string, c: string) => Promise<string> };
}) {
  vi.stubGlobal("window", {
    nostr: impl ?? {
      getPublicKey: vi.fn().mockResolvedValue(PK),
      signEvent: vi.fn().mockImplementation((e) => Promise.resolve({ ...e, id: "id", pubkey: PK, sig: "sig" })),
    },
  });
}

beforeEach(() => {
  clearNip07PublicKeyCache();
  vi.unstubAllGlobals();
});

describe("detection", () => {
  it("detects a well-formed extension", () => {
    stubNostr();
    expect(isNip07Available()).toBe(true);
    expect(getNip07Extension()).not.toBeNull();
  });

  it("rejects missing or wrong-shape nostr objects", () => {
    vi.stubGlobal("window", {});
    expect(isNip07Available()).toBe(false);
    vi.stubGlobal("window", { nostr: { notGetPublicKey: 1 } });
    expect(isNip07Available()).toBe(false);
  });
});

describe("getNip07PublicKey caching", () => {
  it("prompts once — subsequent calls reuse the cache", async () => {
    stubNostr();
    const a = await getNip07PublicKey();
    const b = await getNip07PublicKey();
    expect(a).toBe(PK);
    expect(b).toBe(PK);
    expect((window as never as { nostr: { getPublicKey: unknown } }).nostr.getPublicKey).toHaveBeenCalledTimes(1);
  });

  it("dedupes concurrent calls into one prompt", async () => {
    stubNostr();
    const [a, b] = await Promise.all([getNip07PublicKey(), getNip07PublicKey()]);
    expect(a).toBe(PK);
    expect(b).toBe(PK);
    expect((window as never as { nostr: { getPublicKey: unknown } }).nostr.getPublicKey).toHaveBeenCalledTimes(1);
  });

  it("caches a denial and does not re-prompt without force", async () => {
    stubNostr({ getPublicKey: vi.fn().mockRejectedValue(new Error("user rejected")) });
    await expect(getNip07PublicKey()).rejects.toThrow("user rejected");
    await expect(getNip07PublicKey()).rejects.toThrow("user rejected");
    expect(
      ((window as never as { nostr: { getPublicKey: { mock: { calls: unknown[] } } } }).nostr.getPublicKey.mock.calls).length,
    ).toBe(1);
  });

  it("force:true retries after a denial", async () => {
    const fn = vi.fn()
      .mockRejectedValueOnce(new Error("user rejected"))
      .mockResolvedValueOnce(PK);
    stubNostr({ getPublicKey: fn });
    await expect(getNip07PublicKey()).rejects.toThrow("user rejected");
    await expect(getNip07PublicKey({ force: true })).resolves.toBe(PK);
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it("rejects empty pubkeys", async () => {
    stubNostr({ getPublicKey: vi.fn().mockResolvedValue("") });
    await expect(getNip07PublicKey()).rejects.toThrow(/empty public key/);
  });
});

describe("connectNip07Signer", () => {
  it("returns a full signer session (signEvent works, no nip44 by default)", async () => {
    stubNostr();
    const s = await connectNip07Signer();
    expect(s.pubkey).toBe(PK);
    expect(s.hasNip44).toBe(false);
    expect(s.signer.nip44Encrypt).toBeNull();
    const ev = await s.signer.signEvent({ kind: 1, created_at: 1, tags: [], content: "x" } as never);
    expect((ev as unknown as { sig: string }).sig).toBe("sig");
  });

  it("exposes nip44 helpers when the extension supports them", async () => {
    stubNostr({
      getPublicKey: vi.fn().mockResolvedValue(PK),
      signEvent: vi.fn(),
      nip44: {
        encrypt: vi.fn().mockResolvedValue("enc"),
        decrypt: vi.fn().mockResolvedValue("dec"),
      },
    });
    const s = await connectNip07Signer();
    expect(s.hasNip44).toBe(true);
    await expect(s.signer.nip44Encrypt!("b".repeat(64), "hello")).resolves.toBe("enc");
  });

  it("times out with an actionable popup message instead of hanging", async () => {
    stubNostr({ getPublicKey: vi.fn().mockImplementation(() => new Promise(() => {})) });
    await expect(connectNip07Signer({ timeoutMs: 50 })).rejects.toThrow(/extension popup/i);
  });

  it("throws synchronously-detectable error when no extension", async () => {
    vi.stubGlobal("window", {});
    await expect(connectNip07Signer()).rejects.toThrow(/No Nostr extension/);
  });
});
