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

const PBKDF2_ITERATIONS = 250_000;
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

function storageKey(suffix: string): string {
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
  let secret = localStorage.getItem(storageKey("install_secret"));
  if (!secret) {
    secret = crypto.randomUUID();
    localStorage.setItem(storageKey("install_secret"), secret);
  }
  return secret;
}

async function deriveStorageKey(salt: Uint8Array): Promise<CryptoKey> {
  const password = `${keyStorageConfig.appEntropy}:${getInstallSecret()}`;
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt as unknown as BufferSource, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
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

/** Encrypt a string for localStorage. Returns base64(salt || iv || ciphertext). */
export async function encryptForStorage(value: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveStorageKey(salt);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv as unknown as BufferSource }, key, new TextEncoder().encode(value)),
  );
  const combined = new Uint8Array(salt.length + iv.length + ciphertext.length);
  combined.set(salt);
  combined.set(iv, salt.length);
  combined.set(ciphertext, salt.length + iv.length);
  return toB64(combined);
}

/** Decrypt a blob produced by {@link encryptForStorage}. Returns null on any error. */
export async function decryptFromStorage(blob: string): Promise<string | null> {
  try {
    const combined = fromB64(blob);
    const salt = combined.slice(0, 16);
    const iv = combined.slice(16, 28);
    const ciphertext = combined.slice(28);
    const key = await deriveStorageKey(salt);
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
  localStorage.setItem(storageKey("nsec"), encrypted);
  localStorage.setItem(storageKey("pubkey"), keyPair.publicKey);
}

/** Load and decrypt the stored private key (hex). Returns null when absent/undecryptable. */
export async function loadStoredPrivateKey(): Promise<string | null> {
  const encrypted = localStorage.getItem(storageKey("nsec"));
  if (!encrypted) return null;
  return decryptFromStorage(encrypted);
}

/** Load the stored public key (hex), if any. */
export function loadStoredPublicKey(): string | null {
  return localStorage.getItem(storageKey("pubkey"));
}

/** Remove all stored key material. */
export function clearStoredKeys(): void {
  for (const suffix of ["nsec", "pubkey"]) {
    try {
      localStorage.removeItem(storageKey(suffix));
    } catch {
      /* ignore */
    }
  }
}
