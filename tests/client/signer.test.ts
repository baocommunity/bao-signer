// tests/client/signer.test.ts

import { describe, expect, it } from "vitest";
import * as nip44 from "nostr-tools/nip44";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { createNip44IdentitySigner } from "../../src/client/signer";

const PRIV_A = hexToBytes("11".repeat(32));
const PRIV_B = hexToBytes("22".repeat(32));

describe("createNip44IdentitySigner", () => {
  it("derives pubkey + nsec from the 32-byte key", () => {
    const id = createNip44IdentitySigner(PRIV_A);
    expect(id.pubkey).toMatch(/^[0-9a-f]{64}$/);
    expect(id.nsec.startsWith("nsec1")).toBe(true);
    expect(id.signer).toBeDefined();
  });

  it("rejects non-32-byte keys", () => {
    expect(() => createNip44IdentitySigner(new Uint8Array(16))).toThrow(/32 bytes/);
    expect(() => createNip44IdentitySigner({} as Uint8Array)).toThrow(/32 bytes/);
  });

  it("signs events deterministically with the identity key", async () => {
    const idA = createNip44IdentitySigner(PRIV_A);
    const ev = await idA.signer.signEvent({
      kind: 17375,
      created_at: 1_700_000_000,
      tags: [["m", "https://mint.example.com"]],
      content: "x",
    });
    expect(ev.pubkey).toBe(idA.pubkey);
    expect(ev.sig).toMatch(/^[0-9a-f]{128}$/);
  });

  it("NIP-44 round-trips between two parties (spec-compliant key)", async () => {
    const a = createNip44IdentitySigner(PRIV_A);
    const b = createNip44IdentitySigner(PRIV_B);
    const cipher = (await a.nip44Encrypt(b.pubkey, "wallet-config-secret")) as string;
    expect(cipher).toBeTruthy();
    const plain = await b.nip44Decrypt(a.pubkey, cipher);
    expect(plain).toBe("wallet-config-secret");
  });

  it("is spec-interoperable: nostr-tools nip44 decrypts our ciphertext and vice versa", async () => {
    const a = createNip44IdentitySigner(PRIV_A);
    const b = createNip44IdentitySigner(PRIV_B);
    // our wrapper encrypts → spec path decrypts
    const cipher = (await a.nip44Encrypt(b.pubkey, "interop")) as string;
    const ck = nip44.v2.utils.getConversationKey(PRIV_B, a.pubkey);
    expect(nip44.v2.decrypt(cipher, ck)).toBe("interop");
    // spec path encrypts → our wrapper decrypts
    const specCipher = nip44.v2.encrypt("interop-back", nip44.v2.utils.getConversationKey(PRIV_B, a.pubkey));
    expect(await a.nip44Decrypt(b.pubkey, specCipher)).toBe("interop-back");
  });

  it("fails decryption cleanly (null) for a third party", async () => {
    const a = createNip44IdentitySigner(PRIV_A);
    const b = createNip44IdentitySigner(PRIV_B);
    const c = createNip44IdentitySigner(hexToBytes("33".repeat(32)));
    const cipher = (await a.nip44Encrypt(b.pubkey, "secret-to-b")) as string;
    expect(await c.nip44Decrypt(a.pubkey, cipher)).toBeNull();
  });
});
