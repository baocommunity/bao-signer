/**
 * BAO Derived Keys Service
 *
 * Generates BAO-specific derived keypairs for privacy.
 *
 * SECURITY PRINCIPLES:
 * - Each BAO gets a unique keypair derived from user's master key
 * - Prevents correlation across BAOs (unlinkable identity)
 * - Uses HMAC-SHA256 for deterministic derivation
 * - Keys can be rotated by incrementing index
 *
 * DERIVATION PATH FORMAT:
 * `bao/<baoId>/<index>`
 *
 * Example: bao/abc123/0 = first key for BAO "abc123"
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { hmac } from '@noble/hashes/hmac.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import * as secp256k1 from '@noble/secp256k1';

/** Derived keypair for a specific community/context identity. */
export interface DerivedKeyPair {
  /** Public key (hex, x-only / BIP-340) */
  pubkey: string;
  /** Private key (hex) */
  privkey: string;
  /** Derivation path used */
  derivationPath: string;
  /** Community/context ID this key is derived for */
  baoId: string;
  /** Key index for rotation */
  index: number;
}

// Crypto key length constants
const HEX_PRIVKEY_LENGTH = 64;  // 32 bytes = 64 hex chars (secp256k1 private key)

/**
 * N - order of secp256k1 curve (max valid private key value + 1)
 * Private keys must be in range [1, N-1]
 */
const SECP256K1_ORDER = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');

/**
 * Convert bytes to BigInt for scalar validation
 */
function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = BigInt(0);
  for (let i = 0; i < bytes.length; i++) {
    result = (result << BigInt(8)) + BigInt(bytes[i]);
  }
  return result;
}

/**
 * Ensure derived key is a valid secp256k1 scalar
 * Must be in range [1, N-1] where N is curve order
 */
const MAX_SCALAR_RETRIES = 100;

function ensureValidScalar(derived: Uint8Array, depth: number = 0): Uint8Array {
  if (depth >= MAX_SCALAR_RETRIES) {
    throw new Error(
      `ensureValidScalar: failed to produce a valid scalar after ${MAX_SCALAR_RETRIES} attempts. ` +
      'This is astronomically unlikely and may indicate a bug in the derivation logic.'
    );
  }

  const scalar = bytesToBigInt(derived);

  // If scalar is 0 or >= N, we need to derive again with different tweak
  if (scalar === BigInt(0) || scalar >= SECP256K1_ORDER) {
    // Extremely rare edge case - hash again with salt
    const tweaked = hmac(sha256, derived, new TextEncoder().encode('scalar-tweak'));
    return ensureValidScalar(tweaked, depth + 1);
  }

  return derived;
}

/**
 * Public wrapper for {@link ensureValidScalar} — validates/re-derives a 32-byte
 * value until it is a valid secp256k1 private key scalar (1 <= k < N).
 * Use this for ANY hash-derived private key (e.g. PRF-derived Nostr keys).
 */
export function ensureValidSecp256k1Scalar(derived: Uint8Array): Uint8Array {
  return ensureValidScalar(derived);
}

/**
 * Derive a unique keypair for a specific BAO
 *
 * @param masterPrivkey - User's main private key (hex string, 64 chars)
 * @param baoId - BAO identifier (unique per BAO)
 * @param index - Key index for rotation (default 0)
 * @returns DerivedKeyPair with pubkey, privkey, and derivation info
 *
 * SECURITY: The derived key is deterministic - same inputs always produce same key.
 * This allows recovery across devices using only the master key and BAO membership list.
 */
export function deriveBaoKeypair(
  masterPrivkey: string,
  baoId: string,
  index: number = 0
): DerivedKeyPair {
  // Validate inputs
  if (!masterPrivkey || masterPrivkey.length !== HEX_PRIVKEY_LENGTH) {
    throw new Error('Invalid master private key: must be 64 hex characters');
  }
  if (!/^[0-9a-fA-F]+$/.test(masterPrivkey)) {
    throw new Error('Invalid master private key: contains non-hex characters');
  }
  if (!baoId || typeof baoId !== 'string') {
    throw new Error('Invalid BAO ID: must be a non-empty string');
  }
  if (typeof index !== 'number' || index < 0 || !Number.isInteger(index)) {
    throw new Error('Invalid index: must be a non-negative integer');
  }
  // BDK-228A-001 FIX: cap baoId length to prevent large HMAC inputs / localStorage key overflow
  if (baoId.length > 256) {
    throw new Error('Invalid BAO ID: too long (max 256 characters)');
  }

  // Create derivation path
  const derivationPath = `bao/${baoId}/${index}`;

  // Derive child key using HMAC-SHA256
  // HMAC(key=masterPrivkey, message=derivationPath)
  const seed = hexToBytes(masterPrivkey);
  const path = new TextEncoder().encode(derivationPath);
  const derived = hmac(sha256, seed, path);

  // Ensure valid secp256k1 scalar
  const privkeyBytes = ensureValidScalar(derived);

  // Get public key from private key
  const pubkeyBytes = secp256k1.getPublicKey(privkeyBytes, true); // compressed

  // Return x-only pubkey for Nostr (32 bytes, no prefix).
  // BIP-340 / Schnorr: x-only pubkeys always assume even Y-coordinate.
  // The 02/03 prefix from the compressed key is stripped; only the x-coordinate
  // is used. This is correct per the BIP-340 specification.
  const xOnlyPubkey = pubkeyBytes.slice(1); // Remove 02/03 prefix

  return {
    pubkey: bytesToHex(xOnlyPubkey),
    privkey: bytesToHex(privkeyBytes),
    derivationPath,
    baoId,
    index,
  };
}

/**
 * Get all derived keys for a user across their BAO memberships
 *
 * @param masterPrivkey - User's main private key
 * @param baoMemberships - Array of BAO IDs the user is a member of
 * @returns Map of baoId -> DerivedKeyPair
 */
export function getAllDerivedKeys(
  masterPrivkey: string,
  baoMemberships: string[]
): Map<string, DerivedKeyPair> {
  const keys = new Map<string, DerivedKeyPair>();

  for (const baoId of baoMemberships) {
    try {
      keys.set(baoId, deriveBaoKeypair(masterPrivkey, baoId, 0));
    } catch (error) {
      console.error(`Failed to derive key for BAO ${baoId}:`, error);
      // Continue with other BAOs
    }
  }

  return keys;
}

/**
 * Rotate key for a BAO by incrementing index
 *
 * @param masterPrivkey - User's main private key
 * @param baoId - BAO identifier
 * @param currentIndex - Current key index
 * @returns New DerivedKeyPair with incremented index
 */
export function rotateBaoKey(
  masterPrivkey: string,
  baoId: string,
  currentIndex: number
): DerivedKeyPair {
  return deriveBaoKeypair(masterPrivkey, baoId, currentIndex + 1);
}

/**
 * Verify that a pubkey matches a derived key for a given BAO
 *
 * @param masterPrivkey - User's main private key
 * @param baoId - BAO identifier
 * @param pubkey - Public key to verify
 * @param maxIndex - Maximum index to check (for key rotation)
 * @returns The matching DerivedKeyPair or null if no match
 */
/**
 * Constant-time comparison of two hex strings to prevent timing attacks.
 * Returns true if both strings are equal, using XOR accumulation to avoid
 * early exit on mismatch.
 */
export function constantTimeEqual(a: string, b: string): boolean {
  // FIX: Accumulate length difference instead of early return to prevent timing leak
  const maxLen = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;
  for (let i = 0; i < maxLen; i++) {
    const charA = i < a.length ? a.charCodeAt(i) : 0;
    const charB = i < b.length ? b.charCodeAt(i) : 0;
    diff |= charA ^ charB;
  }
  return diff === 0;
}

export function verifyDerivedPubkey(
  masterPrivkey: string,
  baoId: string,
  pubkey: string,
  maxIndex: number = 10
): DerivedKeyPair | null {
  // SECURITY (R2-M-02): Validate pubkey format before calling constantTimeEqual.
  // The length check inside constantTimeEqual returns false immediately on mismatch,
  // leaking timing info. By validating format upfront, all calls to constantTimeEqual
  // are guaranteed to compare equal-length strings.
  if (!/^[0-9a-fA-F]{64}$/.test(pubkey)) return null;

  for (let i = 0; i <= maxIndex; i++) {
    const derived = deriveBaoKeypair(masterPrivkey, baoId, i);
    if (constantTimeEqual(derived.pubkey, pubkey)) {
      return derived;
    }
  }
  return null;
}

/**
 * Get the derivation path for a BAO key
 */
export function getBaoDerivationPath(baoId: string, index: number = 0): string {
  return `bao/${baoId}/${index}`;
}

/**
 * Parse a derivation path into components
 */
export function parseDerivationPath(path: string): { baoId: string; index: number } | null {
  const match = path.match(/^bao\/([^/]+)\/(\d+)$/);
  if (!match) return null;

  return {
    baoId: match[1],
    index: parseInt(match[2], 10),
  };
}

/**
 * Derive a conversation key for NIP-44 encryption between two BAO members
 * Uses ECDH to create a shared secret
 *
 * @deprecated This function uses a custom ECDH+SHA-256 derivation that is NOT compatible
 * with NIP-44's expected conversation key format (which uses HKDF with specific parameters).
 * For NIP-44 encryption, use `nip44.utils.v2.getConversationKey()` from nostr-tools instead.
 * This function is retained only for backward compatibility with data encrypted using it.
 *
 * @param senderPrivkey - Sender's derived private key
 * @param recipientPubkey - Recipient's derived public key
 * @returns Shared secret (32 bytes hex) — NOT a valid NIP-44 conversation key
 */
export function deriveBaoConversationKey(
  senderPrivkey: string,
  recipientPubkey: string
): string {
  // Validate inputs
  if (!senderPrivkey || senderPrivkey.length !== HEX_PRIVKEY_LENGTH) {
    throw new Error('Invalid sender private key');
  }
  if (!recipientPubkey || recipientPubkey.length !== HEX_PRIVKEY_LENGTH) {
    throw new Error('Invalid recipient public key');
  }

  // Get shared point using ECDH
  const privkeyBytes = hexToBytes(senderPrivkey);

  // Add 02 prefix for compressed pubkey (assuming even Y-coordinate).
  // Per BIP-340/Schnorr, x-only pubkeys always use the even Y-coordinate.
  // The 0x02 prefix encodes "even Y" in the SEC compressed format, which is
  // the canonical lift for x-only keys as specified in BIP-340.
  const pubkeyBytes = hexToBytes(recipientPubkey);
  const fullPubkey = new Uint8Array(1 + pubkeyBytes.length);
  fullPubkey[0] = 0x02;
  fullPubkey.set(pubkeyBytes, 1);

  const sharedPoint = secp256k1.getSharedSecret(privkeyBytes, fullPubkey, true);

  // Hash the x-coordinate of shared point for conversation key
  const xCoord = sharedPoint.slice(1); // Remove prefix
  const conversationKey = sha256(xCoord);

  return bytesToHex(conversationKey);
}

/**
 * SECURITY: Derived key caching removed to prevent plaintext private keys in localStorage.
 * Derivation uses HMAC-SHA256 which is fast enough to re-derive on demand.
 * Function signatures are preserved for API compatibility.
 */

/**
 * Cache derived keys - NO-OP for security.
 * Derivation is re-done on demand using HMAC-SHA256 (fast).
 */
export function cacheDerivedKeys(
  _userPubkey: string,
  _keys: Map<string, DerivedKeyPair>
): void {
  // No-op: derived keys are no longer cached in localStorage to avoid
  // storing plaintext private key material. HMAC-SHA256 derivation is
  // fast enough to re-derive on each session.
}

/**
 * Load cached derived keys - always returns null.
 * Derivation is re-done on demand using HMAC-SHA256 (fast).
 */
export function loadCachedDerivedKeys(
  _userPubkey: string
): Map<string, DerivedKeyPair> | null {
  // Always return null: derived keys are no longer cached in localStorage.
  // Callers should re-derive keys on demand via deriveBaoKeypair().
  return null;
}

/**
 * Clear cached derived keys - NO-OP for security.
 * No keys are cached, so nothing to clear.
 */
export function clearCachedDerivedKeys(userPubkey: string): void {
  // No-op: no derived keys are cached in localStorage.
  // For backward compat, also clean up any legacy cached keys.
  try {
    const key = `bao-derived-keys-${userPubkey}`;
    localStorage.removeItem(key);
  } catch {
    // Ignore cleanup errors
  }
}
