import { describe, it, expect } from "vitest";
import {
  deriveBaoKeypair,
  ensureValidSecp256k1Scalar,
  constantTimeEqual,
  verifyDerivedPubkey,
  getBaoDerivationPath,
  parseDerivationPath,
} from "../../src/client/derivedKeys.ts";

const MASTER = "ab".repeat(32); // 64 hex chars

describe("deriveBaoKeypair", () => {
  it("is deterministic", () => {
    const a = deriveBaoKeypair(MASTER, "community-1", 0);
    const b = deriveBaoKeypair(MASTER, "community-1", 0);
    expect(a).toEqual(b);
  });

  it("produces distinct keys per community and index", () => {
    const a = deriveBaoKeypair(MASTER, "community-1", 0);
    const b = deriveBaoKeypair(MASTER, "community-2", 0);
    const c = deriveBaoKeypair(MASTER, "community-1", 1);
    expect(a.pubkey).not.toBe(b.pubkey);
    expect(a.pubkey).not.toBe(c.pubkey);
  });

  it("returns x-only 64-char pubkeys and 64-char privkeys", () => {
    const { pubkey, privkey } = deriveBaoKeypair(MASTER, "community-1", 0);
    expect(pubkey).toMatch(/^[0-9a-f]{64}$/);
    expect(privkey).toMatch(/^[0-9a-f]{64}$/);
  });

  it("rejects invalid master keys", () => {
    expect(() => deriveBaoKeypair("zz", "x")).toThrow();
    expect(() => deriveBaoKeypair("ab".repeat(31), "x")).toThrow();
  });

  it("rejects oversized community ids", () => {
    expect(() => deriveBaoKeypair(MASTER, "x".repeat(257))).toThrow(/too long/i);
  });
});

describe("ensureValidSecp256k1Scalar", () => {
  it("passes through valid scalars", () => {
    const valid = new Uint8Array(32).fill(1);
    expect(ensureValidSecp256k1Scalar(valid)).toEqual(valid);
  });

  it("re-derives zero", () => {
    const zero = new Uint8Array(32);
    const result = ensureValidSecp256k1Scalar(zero);
    expect(result).not.toEqual(zero);
    expect(result.length).toBe(32);
  });

  it("re-derives values >= curve order", () => {
    const n = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    const bytes = new Uint8Array(32);
    let v = n;
    for (let i = 31; i >= 0; i--) {
      bytes[i] = Number(v & 0xffn);
      v >>= 8n;
    }
    const result = ensureValidSecp256k1Scalar(bytes);
    expect(result).not.toEqual(bytes);
  });
});

describe("constantTimeEqual", () => {
  it("compares equal strings", () => {
    expect(constantTimeEqual("abc", "abc")).toBe(true);
    expect(constantTimeEqual("abc", "abd")).toBe(false);
    expect(constantTimeEqual("abc", "abcd")).toBe(false);
  });
});

describe("verifyDerivedPubkey", () => {
  it("finds the matching derived key", () => {
    const derived = deriveBaoKeypair(MASTER, "community-1", 2);
    const found = verifyDerivedPubkey(MASTER, "community-1", derived.pubkey, 5);
    expect(found?.index).toBe(2);
  });

  it("rejects malformed pubkeys", () => {
    expect(verifyDerivedPubkey(MASTER, "community-1", "not-hex")).toBeNull();
  });
});

describe("derivation paths", () => {
  it("round-trips", () => {
    const path = getBaoDerivationPath("community-1", 3);
    expect(path).toBe("bao/community-1/3");
    expect(parseDerivationPath(path)).toEqual({ baoId: "community-1", index: 3 });
  });
});
