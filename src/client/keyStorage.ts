/**
 * keyStorage — local encrypted Nostr key storage for bao-signer.
 *
 * Scheme (ported from bao.markets nostrKeyManager):
 *   device secret (random, per-installation, localStorage)
 *   → PBKDF2-SHA256 (250k iterations, random salt)
 *   → AES-256-GCM ciphertext blob in localStorage
 *
 * THREAT MODEL: this protects the key against casual device inspection and
 * trivial localStorage dumps. It does NOT protect against XSS (an attacker
 * running JS in your origin can read the device secret too). For real
 * protection, wrap the key with a passkey — see `nativePasskeyAuth.ts`.
 */

import { generateSecretKey, getPublicKey, nip19 } from "nostr-tools";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

// Vault format v2: "v2i{iterations}:" + base64(salt(32) || iv(12) || ciphertext).
// The prefix encodes the exact iteration count so decryption never depends on
// the code's current default (lesson from bao.markets' v1→v2 migration pain).
// Unprefixed blobs are the legacy v0 layout (salt(16) || iv(12) || ct, 250k).
const PBKDF2_ITERATIONS = 256_000;
const LEGACY_PBKDF2_ITERATIONS = 250_000;
const SALT_BYTES = 32;
const LEGACY_SALT_BYTES = 16;
const V2_PREFIX = `v2i${PBKDF2_ITERATIONS}:`;
// MED-4: the iteration count inside a stored blob is attacker-controlled
// (localStorage tamper). Clamp to a sane window so a tampered count can
// neither DoS the unlock path (huge count) nor weaken KDF silently (low count).
const MIN_BLOB_ITERATIONS = 100_000;
const MAX_BLOB_ITERATIONS = 10_000_000;
const DEFAULT_STORAGE_PREFIX = "bao_signer";

export interface NostrKeyPairHex {
  privateKey: string; // hex
  publicKey: string; // hex
}

export interface KeyStorageConfig {
  /** Application context mixed into the PBKDF2 password. Change per app. */
  appEntropy?: string;
  /** localStorage key prefix. */
  storagePrefix?: string;
}

let keyStorageConfig: Required<KeyStorageConfig> = {
  appEntropy: "bao-signer",
  storagePrefix: DEFAULT_STORAGE_PREFIX,
};

export function configureKeyStorage(config: KeyStorageConfig): void {
  keyStorageConfig = { ...keyStorageConfig, ...config };
}

/** Namespaced localStorage key. Exported so sibling modules (quickStart)
 * share the SAME configurable prefix — call at use time, not import time. */
export function keyStorageKey(suffix: string): string {
  return `${keyStorageConfig.storagePrefix}_${suffix}`;
}

/** Generate a fresh Nostr keypair (hex). */
export function generateKeyPair(): NostrKeyPairHex {
  const privateKeyBytes = generateSecretKey();
  const privateKey = bytesToHex(privateKeyBytes);
  const publicKey = getPublicKey(privateKeyBytes);
  return { privateKey, publicKey };
}

export function encodeNsec(privateKey: string): string {
  return nip19.nsecEncode(hexToBytes(privateKey));
}

export function decodeNsec(nsec: string): string {
  const decoded = nip19.decode(nsec);
  if (decoded.type !== "nsec") throw new Error("Invalid nsec format");
  return bytesToHex(decoded.data as Uint8Array);
}

export function encodeNpub(publicKey: string): string {
  return nip19.npubEncode(publicKey);
}

export function decodeNpub(npub: string): string {
  const decoded = nip19.decode(npub);
  if (decoded.type !== "npub") throw new Error("Invalid npub format");
  return decoded.data as string;
}

function getInstallSecret(): string {
  let secret = localStorage.getItem(keyStorageKey("install_secret"));
  if (!secret) {
    secret = crypto.randomUUID();
    localStorage.setItem(keyStorageKey("install_secret"), secret);
  }
  return secret;
}

function toB64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function fromB64(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function deriveStorageKeyWithIterations(salt: Uint8Array, iterations: number): Promise<CryptoKey> {
  const password = `${keyStorageConfig.appEntropy}:${getInstallSecret()}`;
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt as unknown as BufferSource, iterations, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/** Encrypt a string for localStorage.
 *  Returns "v2i{iterations}:" + base64(salt(32) || iv(12) || ciphertext). */
export async function encryptForStorage(value: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveStorageKeyWithIterations(salt, PBKDF2_ITERATIONS);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv as unknown as BufferSource }, key, new TextEncoder().encode(value)),
  );
  const combined = new Uint8Array(salt.length + iv.length + ciphertext.length);
  combined.set(salt);
  combined.set(iv, salt.length);
  combined.set(ciphertext, salt.length + iv.length);
  return V2_PREFIX + toB64(combined);
}

/** Decrypt a blob produced by {@link encryptForStorage}. Returns null on any error.
 *  Reads both the v2 format (prefixed) and legacy v0 blobs (unprefixed). */
export async function decryptFromStorage(blob: string): Promise<string | null> {
  try {
    if (blob.startsWith("v2i")) {
      const match = blob.match(/^v2i(\d+):/);
      if (!match) return null;
      const iterations = parseInt(match[1], 10);
      if (!Number.isFinite(iterations) || iterations < MIN_BLOB_ITERATIONS || iterations > MAX_BLOB_ITERATIONS) {
        return null;
      }
      const combined = fromB64(blob.slice(match[0].length));
      const salt = combined.slice(0, SALT_BYTES);
      const iv = combined.slice(SALT_BYTES, SALT_BYTES + 12);
      const ciphertext = combined.slice(SALT_BYTES + 12);
      const key = await deriveStorageKeyWithIterations(salt, iterations);
      const plaintext = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: iv as unknown as BufferSource },
        key,
        ciphertext as unknown as BufferSource,
      );
      return new TextDecoder().decode(plaintext);
    }
    // Legacy v0: base64(salt(16) || iv(12) || ct) at 250k iterations.
    const combined = fromB64(blob);
    const salt = combined.slice(0, LEGACY_SALT_BYTES);
    const iv = combined.slice(LEGACY_SALT_BYTES, LEGACY_SALT_BYTES + 12);
    const ciphertext = combined.slice(LEGACY_SALT_BYTES + 12);
    const key = await deriveStorageKeyWithIterations(salt, LEGACY_PBKDF2_ITERATIONS);
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv as unknown as BufferSource },
      key,
      ciphertext as unknown as BufferSource,
    );
    return new TextDecoder().decode(plaintext);
  } catch {
    return null;
  }
}

/** Generate or encrypt-and-store a keypair. The nsec is NEVER stored in plaintext. */
export async function storeKeyPair(keyPair: NostrKeyPairHex): Promise<void> {
  const encrypted = await encryptForStorage(keyPair.privateKey);
  localStorage.setItem(keyStorageKey("nsec"), encrypted);
  localStorage.setItem(keyStorageKey("pubkey"), keyPair.publicKey);
}

/** Load and decrypt the stored private key (hex). Returns null when absent/undecryptable. */
export async function loadStoredPrivateKey(): Promise<string | null> {
  const encrypted = localStorage.getItem(keyStorageKey("nsec"));
  if (!encrypted) return null;
  return decryptFromStorage(encrypted);
}

/** Load the stored public key (hex), if any. */
export function loadStoredPublicKey(): string | null {
  return localStorage.getItem(keyStorageKey("pubkey"));
}

/** Remove all stored key material. */
export function clearStoredKeys(): void {
  for (const suffix of ["nsec", "pubkey"]) {
    try {
      localStorage.removeItem(keyStorageKey(suffix));
    } catch {
      /* ignore */
    }
  }
}
