/**
 * seedIdentity — BIP-39 seed-phrase identity for bao-signer.
 *
 * The recovery root of the unified login stack: a 24-word (256-bit) BIP-39
 * mnemonic derives the Nostr identity key. Logging in with the SAME phrase
 * in any app yields the same identity pubkey → the same kind:10002 relays +
 * NIP-60 wallet config → the same balance across apps and devices.
 *
 * The math (sound, deterministic, cross-app):
 *   mnemonic (256-bit entropy, BIP-39 checksum)
 *   → PBKDF2-HMAC-SHA512 (2048 rounds, BIP-39 standard) → 64-byte seed
 *   → SHA-256(domainSeparator ‖ seed) → 32-byte secp256k1 scalar
 *     (validated: secp256k1.getPublicKey throws on invalid scalars — the
 *     ~2⁻¹²⁸ invalid case surfaces loudly instead of producing a bad key)
 *
 * The default domain separator ('baofund:identity:v1') matches existing
 * bao-fund / bao.markets derivations — do NOT change it without a migration
 * plan, or existing users would derive DIFFERENT identities from the same
 * backup phrase.
 */

import { mnemonicToSeedSync, generateMnemonic, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { getPublicKey } from "nostr-tools/pure";
import { createNip44IdentitySigner } from "./signer.ts";

/** Default derivation domain — MUST stay stable for cross-app parity. */
export const DEFAULT_IDENTITY_DOMAIN = "baofund:identity:v1";

/**
 * Generate a new BIP-39 seed phrase.
 * Strong entropy by default: 24 words / 256 bits. A 12-word (128-bit)
 * mnemonic is below the 256-bit floor we want for on-chain Nostr keys — the
 * phrase is the single point of failure for wallet recovery, and weak
 * entropy lets an offline attacker brute-force it.
 */
export function newSeedPhrase(bits: 128 | 256 = 256): string {
  return generateMnemonic(wordlist, bits);
}

/** Validate a BIP-39 seed phrase (checksum + wordlist). */
export function validateSeedPhrase(phrase: string): boolean {
  return validateMnemonic(phrase.trim().toLowerCase(), wordlist);
}

/**
 * Derive the 32-byte identity private key from a BIP-39 seed phrase.
 * Throws on invalid phrases. Deterministic: same phrase + same domain →
 * same key, always, in every app.
 */
export function deriveIdentityPrivkey(
  seedPhrase: string,
  domain: string = DEFAULT_IDENTITY_DOMAIN,
): Uint8Array {
  const trimmed = seedPhrase.trim().toLowerCase();
  if (!validateMnemonic(trimmed, wordlist)) {
    throw new Error("Invalid BIP-39 seed phrase");
  }
  const seed = mnemonicToSeedSync(trimmed);
  const digest = sha256(
    new Uint8Array([...new TextEncoder().encode(domain), ...seed]),
  );
  // Validate the derived scalar — secp256k1.getPublicKey throws on invalid
  // input (0 or ≥ n). Astronomically rare (~2⁻¹²⁸), but a silent bad key
  // would be catastrophic: fail loudly instead.
  getPublicKey(digest);
  return digest;
}

/**
 * Full spec-compliant NIP-44 identity signer from a seed phrase.
 * Convenience wrapper: phrase → validated key → createNip44IdentitySigner.
 */
export function createSeedIdentitySigner(
  seedPhrase: string,
  domain: string = DEFAULT_IDENTITY_DOMAIN,
): ReturnType<typeof createNip44IdentitySigner> {
  return createNip44IdentitySigner(deriveIdentityPrivkey(seedPhrase, domain));
}
