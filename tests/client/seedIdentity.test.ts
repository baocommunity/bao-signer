/**
 * seedIdentity + loginFlowMachine tests — the canonical math and the
 * unified login brain.
 *
 * Parity vector: deriveIdentityPrivkey MUST match the bao-fund derivation
 * (baofund:identity:v1 domain) for a known phrase — this is what keeps
 * identities stable across apps.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { mnemonicToSeedSync, validateMnemonic, generateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import {
  newSeedPhrase,
  validateSeedPhrase,
  deriveIdentityPrivkey,
  createSeedIdentitySigner,
  DEFAULT_IDENTITY_DOMAIN,
} from "../../src/client/seedIdentity.ts";
import { createLoginFlow } from "../../src/client/loginFlowMachine.ts";

const KNOWN_PHRASE =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

describe("seedIdentity math", () => {
  it("generates 24-word phrases by default (256-bit)", () => {
    const phrase = newSeedPhrase();
    expect(phrase.split(" ").length).toBe(24);
    expect(validateMnemonic(phrase, wordlist)).toBe(true);
  });

  it("can still generate 12-word when explicitly requested", () => {
    expect(newSeedPhrase(128).split(" ").length).toBe(12);
  });

  it("validates phrases (checksum + normalization)", () => {
    const phrase = newSeedPhrase();
    expect(validateSeedPhrase(phrase)).toBe(true);
    expect(validateSeedPhrase("  " + phrase.toUpperCase() + " ")).toBe(true); // normalized
    expect(validateSeedPhrase("abandon ".repeat(23) + "zoo")).toBe(false);
  });

  it("PARITY: derives the exact bao-fund identity key for a known phrase", () => {
    // Reference computation (bao-fund's identity.ts):
    const seed = mnemonicToSeedSync(KNOWN_PHRASE);
    const expected = sha256(
      new Uint8Array([...new TextEncoder().encode("baofund:identity:v1"), ...seed]),
    );
    const derived = deriveIdentityPrivkey(KNOWN_PHRASE);
    expect(bytesToHex(derived)).toBe(bytesToHex(expected));
    expect(derived.length).toBe(32);
  });

  it("is deterministic and domain-stable (DEFAULT_IDENTITY_DOMAIN unchanged)", () => {
    expect(DEFAULT_IDENTITY_DOMAIN).toBe("baofund:identity:v1");
    const a = deriveIdentityPrivkey(KNOWN_PHRASE);
    const b = deriveIdentityPrivkey(KNOWN_PHRASE);
    expect(bytesToHex(a)).toBe(bytesToHex(b));
    // A different domain derives a DIFFERENT key (namespacing works)
    const other = deriveIdentityPrivkey(KNOWN_PHRASE, "other:domain:v1");
    expect(bytesToHex(other)).not.toBe(bytesToHex(a));
  });

  it("rejects invalid phrases", () => {
    expect(() => deriveIdentityPrivkey("not a seed phrase")).toThrow(/Invalid BIP-39/);
  });

  it("createSeedIdentitySigner yields a working spec-NIP-44 signer", async () => {
    const id = createSeedIdentitySigner(KNOWN_PHRASE);
    expect(id.pubkey).toMatch(/^[0-9a-f]{64}$/);
    expect(id.nsec).toMatch(/^nsec1/);
    const other = createSeedIdentitySigner(newSeedPhrase());
    const ct = await id.nip44Encrypt(other.pubkey, "hello");
    expect(await other.nip44Decrypt(id.pubkey, ct!)).toBe("hello");
  });
});

describe("loginFlowMachine", () => {
  beforeEach(() => {
    vi.unstubAllGlobals();
  });

  it("registers with a 24-word phrase + backup file text", async () => {
    const m = createLoginFlow();
    const { phrase, result } = await m.registerSeed();
    expect(phrase.split(" ").length).toBe(24);
    expect(result.method).toBe("seed");
    expect(result.pubkey).toMatch(/^[0-9a-f]{64}$/);
    expect(result.backupFileText).toContain("nsec1");
    expect(result.backupFileText).toContain(phrase);
    expect(result.backupFileText).toContain(result.pubkey);
  });

  it("logs in with a valid seed phrase (same identity as register)", async () => {
    const m = createLoginFlow();
    const r = await m.loginSeed(KNOWN_PHRASE);
    expect(r.method).toBe("seed");
    const direct = createSeedIdentitySigner(KNOWN_PHRASE);
    expect(r.pubkey).toBe(direct.pubkey);
  });

  it("logs in with an nsec (no phrase needed)", async () => {
    const id = createSeedIdentitySigner(newSeedPhrase());
    const m = createLoginFlow();
    const r = await m.loginSeed(id.nsec);
    expect(r.pubkey).toBe(id.pubkey);
  });

  it("rejects bad key material with a clear message", async () => {
    const m = createLoginFlow();
    await expect(m.loginSeed("garbage words here")).rejects.toThrow(/24 mnemonic words or the nsec key/);
  });

  it("validates bunker URLs without connecting", () => {
    const m = createLoginFlow();
    expect(m.validateBunkerUrl("bunker://bad").ok).toBe(false);
    const good = m.validateBunkerUrl(
      "bunker://" + "a".repeat(64) + "?relay=wss://r.example.com",
    );
    expect(good.ok).toBe(true);
  });

  it("reports extension availability from the environment", () => {
    vi.stubGlobal("window", { nostr: { getPublicKey: async () => "x" } });
    const m = createLoginFlow();
    expect(m.nip07Available).toBe(true);
  });
});
