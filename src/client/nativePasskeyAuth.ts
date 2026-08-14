/**
 * Native Passkey Authentication Bridge for bao-signer.
 *
 * Connects the zero-dependency native passkey module (`nativePasskey.ts`)
 * with passkey-locked Nostr accounts. Generates Nostr keypairs, encrypts the private
 * key with a passkey-derived master key, and stores it locally.
 *
 * No server interaction required. Pure client-side.
 */

import {
  registerPlatformPasskey,
  registerYubiKeyWithPrf,
  registerYubiKeyPasskey,
  unlockWithPasskey,
  hasPasskeyEnrolled,
  getPasskeyEnrollment,
  removePasskeyEnrollment,
  isPrfAvailable,
  isWebAuthnAvailable,
  isLargeBlobAvailable,
} from "./nativePasskey.ts";

import { generateSecretKey, getPublicKey, nip19 } from "nostr-tools";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

/* ── Constants ─────────────────────────────────────────────── */

const NATIVE_PASSKEY_ENC_SK_KEY = "bao_native_passkey_encrypted_sk";
const NATIVE_PASSKEY_PUBKEY_KEY = "bao_native_passkey_pubkey";
const NATIVE_PASSKEY_METHOD_KEY = "bao_native_passkey_method";

/* ── Types ─────────────────────────────────────────────────── */

export interface NativePasskeyIdentity {
  pubkey: string;
  npub: string;
  nsec: string;
  secretKey: string; // hex
}

export interface NativePasskeyRegistrationResult {
  identity: NativePasskeyIdentity;
  method: "prf" | "largeBlob";
}

export interface NativePasskeyAvailability {
  /** WebAuthn is available in this browser */
  available: boolean;
  /** PRF extension is supported */
  prf: boolean;
  /** largeBlob extension is supported (YubiKey fallback) */
  largeBlob: boolean;
  /** User has already enrolled a native passkey */
  enrolled: boolean;
}

/* ── Utilities ─────────────────────────────────────────────── */

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const buffer = new ArrayBuffer(binary.length);
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return buffer;
}

/** Generate a random AES-GCM master key. */
async function generateMasterKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
    "encrypt",
    "decrypt",
  ]);
}

/** Encrypt nsec with the master key. Returns base64(IV || ciphertext). */
async function encryptSk(nsec: string, masterKey: CryptoKey): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoder = new TextEncoder();
  const plaintext = encoder.encode(nsec);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, masterKey, plaintext);

  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(ciphertext), iv.length);

  return arrayBufferToBase64(combined.buffer);
}

/** Decrypt nsec with the master key. */
async function decryptSk(encB64: string, masterKey: CryptoKey): Promise<string> {
  const combined = new Uint8Array(base64ToArrayBuffer(encB64));
  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);
  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv as unknown as BufferSource }, masterKey, ciphertext as unknown as BufferSource);
  return new TextDecoder().decode(plaintext);
}

/* ── Registration ──────────────────────────────────────────── */

/**
 * Register a new native passkey account.
 *
 * 1. Generate a new Nostr keypair.
 * 2. Create a random AES master key.
 * 3. Enroll a passkey (platform → YubiKey PRF → YubiKey largeBlob).
 * 4. Encrypt the nsec with the master key.
 * 5. Store encrypted nsec + pubkey in localStorage.
 *
 * Returns the identity and which method was used.
 */
export async function registerNativePasskeyAccount(): Promise<NativePasskeyRegistrationResult> {
  // 1. Generate Nostr keypair
  const secretKeyBytes = generateSecretKey();
  const secretKey = bytesToHex(secretKeyBytes);
  const pubkey = getPublicKey(secretKeyBytes);
  const nsec = nip19.nsecEncode(secretKeyBytes);
  const npub = nip19.npubEncode(pubkey);

  // 2. Generate random AES master key
  const masterKey = await generateMasterKey();

  // 3. Enroll passkey — try platform first, then YubiKey PRF, then largeBlob
  let method: "prf" | "largeBlob";

  try {
    // Try platform authenticator (Touch ID, Face ID, Windows Hello, Android)
    await registerPlatformPasskey(masterKey);
    method = "prf";
  } catch (err: any) {
    if (err.message?.includes("PRF_NOT_SUPPORTED")) {
      // Platform doesn't support PRF — try YubiKey with PRF
      try {
        await registerYubiKeyWithPrf(masterKey);
        method = "prf";
      } catch (yubiErr: any) {
        if (yubiErr.message?.includes("PRF_NOT_SUPPORTED")) {
          // YubiKey doesn't support PRF either — try largeBlob
          await registerYubiKeyPasskey(masterKey);
          method = "largeBlob";
        } else {
          throw yubiErr;
        }
      }
    } else {
      throw err;
    }
  }

  // 4. Encrypt nsec with master key
  const cipherText = await encryptSk(nsec, masterKey);

  // 5. Store — value is AES-GCM ciphertext, never plaintext.
  localStorage.setItem(
    NATIVE_PASSKEY_ENC_SK_KEY,
    cipherText,
  );
  localStorage.setItem(NATIVE_PASSKEY_PUBKEY_KEY, pubkey);
  localStorage.setItem(NATIVE_PASSKEY_METHOD_KEY, method);

  return {
    identity: { pubkey, npub, nsec, secretKey },
    method,
  };
}

/* ── Login ─────────────────────────────────────────────────── */

/**
 * Login with a previously enrolled native passkey.
 *
 * 1. Unlock the passkey to retrieve the master key.
 * 2. Decrypt the stored nsec.
 * 3. Return the identity.
 */
export async function loginNativePasskeyAccount(): Promise<NativePasskeyIdentity> {
  if (!hasPasskeyEnrolled()) {
    throw new Error("No native passkey account found. Please register first.");
  }

  // 1. Unlock passkey
  const { masterKey } = await unlockWithPasskey();

  // 2. Decrypt nsec
  const cipherText = localStorage.getItem(NATIVE_PASSKEY_ENC_SK_KEY);
  if (!cipherText) {
    throw new Error("Native passkey account is corrupted (missing encrypted key).");
  }

  const nsec = await decryptSk(cipherText, masterKey);
  const { type, data } = nip19.decode(nsec);
  if (type !== "nsec") {
    throw new Error("Decryption produced an invalid nsec.");
  }
  const secretKeyBytes = data as Uint8Array;
  const secretKey = bytesToHex(secretKeyBytes);
  const pubkey = getPublicKey(secretKeyBytes);
  const npub = nip19.npubEncode(pubkey);

  return { pubkey, npub, nsec, secretKey };
}

/* ── Status & Availability ─────────────────────────────────── */

/** Check if the user has a native passkey account stored locally. */
export function hasNativePasskeyAccount(): boolean {
  return hasPasskeyEnrolled() && !!localStorage.getItem(NATIVE_PASSKEY_ENC_SK_KEY);
}

/** Get detailed availability info for the native passkey flow. */
export async function getNativePasskeyAvailability(): Promise<NativePasskeyAvailability> {
  const [prf, largeBlob, enrolled] = await Promise.all([
    isPrfAvailable(),
    isLargeBlobAvailable(),
    Promise.resolve(hasNativePasskeyAccount()),
  ]);

  return {
    available: isWebAuthnAvailable(),
    prf,
    largeBlob,
    enrolled,
  };
}

/** Remove all native passkey account data. */
export function removeNativePasskeyAccount(): void {
  removePasskeyEnrollment();
  try {
    localStorage.removeItem(NATIVE_PASSKEY_ENC_SK_KEY);
  } catch {
    /* ignore */
  }
  try {
    localStorage.removeItem(NATIVE_PASSKEY_PUBKEY_KEY);
  } catch {
    /* ignore */
  }
  try {
    localStorage.removeItem(NATIVE_PASSKEY_METHOD_KEY);
  } catch {
    /* ignore */
  }
}

/* ── Error Helpers ─────────────────────────────────────────── */

export const NativePasskeyError = {
  NOT_AVAILABLE: "Passkeys are not available on this browser.",
  NO_ACCOUNT: "No passkey account found. Please create one first.",
  CANCELLED: "Authentication was cancelled.",
  CORRUPTED: "Passkey data is corrupted. Please remove and re-enroll.",
} as const;
