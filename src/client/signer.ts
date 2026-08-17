// src/client/signer.ts
//
// NIP-44-capable Nostr signer for passkey-derived (and seed-derived)
// identities. This is the bridge between an unlocked keypair and the
// apps that need BOTH signing AND NIP-44 encryption — e.g. the NIP-60
// wallet (encrypted kind:17375 config / kind:7375 token events on the
// user's relays) and NIP-98 request signing.
//
// Compatibility note: the conversation key MUST come from
// nostr-tools nip44.v2.utils.getConversationKey (the NIP-44 spec
// implementation), NOT a bespoke ECDH+SHA-256 variant — custom
// derivations are not interoperable with other NIP-44 clients, which
// silently breaks cross-app wallet/config decryption.

import * as nostrNip44 from "nostr-tools/nip44";
import { nip19 } from "nostr-tools";
import { hexToBytes, bytesToHex } from "@noble/hashes/utils.js";
import { getPublicKey, finalizeEvent, type Event as NostrEvent } from "nostr-tools/pure";

export interface Nip44Identity {
  /** Hex public key (x-only, 64 hex chars). */
  pubkey: string;
  /** Bech32-encoded nsec. */
  nsec: string;
  /** Raw private key bytes (32). */
  secretKey: Uint8Array;
}

export type EventTemplate = {
  kind: number;
  created_at: number;
  tags: string[][];
  content: string;
};

export interface NostrSignerLike {
  signEvent(event: EventTemplate): Promise<NostrEvent>;
  nip44: {
    encrypt(pubkey: string, plaintext: string): Promise<string>;
    decrypt(pubkey: string, ciphertext: string): Promise<string>;
  };
}

/**
 * Build a signer with spec-compliant NIP-44 from an unlocked keypair.
 * The returned object satisfies both `bao-signer`-style signing and the
 * NIP-60 signer shape (createNip60Signer-compatible: pubkey, signEvent,
 * nip44Encrypt/nip44Decrypt).
 */
export function createNip44IdentitySigner(
  privkey: Uint8Array,
): Nip44Identity & {
  signer: NostrSignerLike;
  nip44Encrypt: (pubkey: string, plaintext: string) => Promise<string | null>;
  nip44Decrypt: (pubkey: string, ciphertext: string) => Promise<string | null>;
} {
  if (!(privkey instanceof Uint8Array) || privkey.length !== 32) {
    throw new Error("Identity private key must be exactly 32 bytes");
  }

  const pubkey = getPublicKey(privkey);
  const nsec = nip19.nsecEncode(privkey);

  const nip44Encrypt = async (target: string, plaintext: string): Promise<string | null> => {
    try {
      const conversationKey = nostrNip44.v2.utils.getConversationKey(privkey, target);
      return nostrNip44.v2.encrypt(plaintext, conversationKey);
    } catch (e) {
      return null;
    }
  };
  const nip44Decrypt = async (sender: string, ciphertext: string): Promise<string | null> => {
    try {
      const conversationKey = nostrNip44.v2.utils.getConversationKey(privkey, sender);
      return nostrNip44.v2.decrypt(ciphertext, conversationKey);
    } catch (e) {
      return null;
    }
  };

  return {
    pubkey,
    nsec,
    secretKey: privkey,
    signer: {
      signEvent: async (event: EventTemplate) => {
        return finalizeEvent(event, privkey);
      },
      nip44: {
        encrypt: async (target: string, plaintext: string): Promise<string> => {
          const conversationKey = nostrNip44.v2.utils.getConversationKey(privkey, target);
          return nostrNip44.v2.encrypt(plaintext, conversationKey);
        },
        decrypt: async (sender: string, ciphertext: string): Promise<string> => {
          const conversationKey = nostrNip44.v2.utils.getConversationKey(privkey, sender);
          return nostrNip44.v2.decrypt(ciphertext, conversationKey);
        },
      },
    },
    nip44Encrypt,
    nip44Decrypt,
  };
}
