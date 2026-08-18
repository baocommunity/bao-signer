/**
 * Regression tests for the keyStorage vault v2 format:
 *
 *  - encryptForStorage emits the versioned "v2i{iterations}:" prefix so future
 *    iteration-count changes can never brick stored keys (bao.markets lesson).
 *  - decryptFromStorage round-trips v2 blobs AND still reads legacy v0 blobs
 *    (unprefixed, 16-byte salt, 250k iterations).
 *  - Tampered / foreign blobs fail closed (null).
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  configureKeyStorage,
  decryptFromStorage,
  encryptForStorage,
} from "../../src/client/keyStorage.ts";

function stubLocalStorage() {
  const map = new Map<string, string>();
  vi.stubGlobal("localStorage", {
    getItem: (k: string) => map.get(k) ?? null,
    setItem: (k: string, v: string) => void map.set(k, String(v)),
    removeItem: (k: string) => void map.delete(k),
    clear: () => map.clear(),
    get length() { return map.size; },
    key: (i: number) => [...map.keys()][i] ?? null,
  });
  return map;
}

const V2_PREFIX_RE = /^v2i(\d+):/;

describe("keyStorage vault v2", () => {
  beforeEach(() => {
    stubLocalStorage();
    configureKeyStorage({ appEntropy: "bao-signer", storagePrefix: "bao_signer" });
  });

  it("encrypts with the versioned prefix and round-trips", async () => {
    const blob = await encryptForStorage("deadbeef".repeat(8));
    expect(blob).toMatch(V2_PREFIX_RE);
    const iterations = parseInt(blob.match(V2_PREFIX_RE)![1], 10);
    expect(iterations).toBe(256_000);
    const back = await decryptFromStorage(blob);
    expect(back).toBe("deadbeef".repeat(8));
  });

  it("still decrypts legacy v0 blobs (16-byte salt, 250k iterations)", async () => {
    // Ensure the install secret exists (created lazily on first encrypt).
    await encryptForStorage("warmup");
    const installSecret = localStorage.getItem("bao_signer_install_secret");
    expect(installSecret).toBeTruthy();
    // Construct a legacy blob with the OLD format by hand.
    const password = `bao-signer:${installSecret}`;
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveKey"],
    );
    const key = await crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: salt as unknown as BufferSource, iterations: 250_000, hash: "SHA-256" },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt"],
    );
    const ct = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv as unknown as BufferSource },
        key,
        new TextEncoder().encode("legacy-secret"),
      ),
    );
    const combined = new Uint8Array(16 + 12 + ct.length);
    combined.set(salt);
    combined.set(iv, 16);
    combined.set(ct, 28);
    let binary = "";
    for (let i = 0; i < combined.length; i++) binary += String.fromCharCode(combined[i]);
    const legacyBlob = btoa(binary);

    const back = await decryptFromStorage(legacyBlob);
    expect(back).toBe("legacy-secret");
  });

  it("fails closed on tampered ciphertext", async () => {
    const blob = await encryptForStorage("sensitive");
    const prefix = blob.match(V2_PREFIX_RE)![0];
    const raw = atob(blob.slice(prefix.length));
    // Flip a byte in the ciphertext region
    const bytes = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
    bytes[bytes.length - 1] ^= 0xff;
    let binary = "";
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    const tampered = prefix + btoa(binary);
    expect(await decryptFromStorage(tampered)).toBeNull();
  });

  it("fails closed on garbage input", async () => {
    expect(await decryptFromStorage("not-a-blob")).toBeNull();
    expect(await decryptFromStorage("v2i256000:!!!")).toBeNull();
  });

  it("MED-4: rejects blobs with out-of-window iteration counts (tamper DoS guard)", async () => {
    const blob = await encryptForStorage("sensitive");
    const raw = blob.slice(blob.indexOf(":") + 1);
    // Astronomical count → would hang PBKDF2 for minutes if trusted.
    expect(await decryptFromStorage("v2i2000000000:" + raw)).toBeNull();
    // Weakened count → silently-accepted weak KDF if trusted.
    expect(await decryptFromStorage("v2i1000:" + raw)).toBeNull();
    // Boundary sanity: the legit count still decrypts.
    expect(await decryptFromStorage(blob)).toBe("sensitive");
  });
});
