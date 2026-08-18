/**
 * nip46 — NIP-46 (Nostr Connect) remote signer client for bao-signer.
 *
 * Decoupled port of bao.markets' Nip46Client: same hardening (response
 * signature verification, expected-pubkey pinning, JSON/shape validation,
 * per-relay publish timeout, pending-before-publish race fix), with
 * app-specific dependencies removed:
 *   - shared pool   → nostr-tools SimplePool (or inject your own)
 *   - NIP44 service → nostr-tools nip44.v2 directly (spec)
 *   - timestamp fn  → injectable, defaults to now
 *
 * NIP-44 ONLY (NIP-04 leaks metadata and is not supported).
 */

import {
  generateSecretKey,
  getPublicKey,
  getEventHash,
  finalizeEvent,
  verifyEvent,
  nip19,
  SimplePool,
  type Event,
  type UnsignedEvent,
} from "nostr-tools";
import * as nostrNip44 from "nostr-tools/nip44";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import type { SubCloser } from "nostr-tools/pool";

/* ── Bunker URL parsing ────────────────────────────────────── */

export interface BunkerUrlData {
  pubkey: string;
  relays: string[];
  secret?: string;
}

export interface BunkerUrlValidation {
  valid: boolean;
  data?: BunkerUrlData;
  error?: string;
}

/** Parse bunker://<pubkey|npub>?relay=<wss://…>&secret=<secret> */
export function parseBunkerUrl(url: string): BunkerUrlValidation {
  try {
    const trimmed = url.trim();

    if (!trimmed.startsWith("bunker://")) {
      return { valid: false, error: "URL must start with bunker://" };
    }

    const withoutProtocol = trimmed.slice(9);
    const [pubkeyPart, queryString] = withoutProtocol.split("?");

    if (!pubkeyPart) {
      return { valid: false, error: "Missing pubkey" };
    }

    let pubkey: string;
    if (pubkeyPart.startsWith("npub1")) {
      try {
        const decoded = nip19.decode(pubkeyPart);
        if (decoded.type !== "npub") {
          return { valid: false, error: "Invalid npub" };
        }
        pubkey = decoded.data as string;
      } catch {
        return { valid: false, error: "Invalid npub format" };
      }
    } else if (/^[0-9a-f]{64}$/i.test(pubkeyPart)) {
      pubkey = pubkeyPart.toLowerCase();
    } else {
      return { valid: false, error: "Invalid pubkey format" };
    }

    const relays: string[] = [];
    let secret: string | undefined;

    if (queryString) {
      const params = new URLSearchParams(queryString);
      params.getAll("relay").forEach((r) => {
        // Full URL validation: rejects embedded credentials
        // (wss://user:pass@host) and malformed URLs (SSRF/network scanning).
        try {
          const parsed = new URL(r);
          if (parsed.protocol !== "wss:" && parsed.protocol !== "ws:") return;
          if (parsed.username || parsed.password) return;
          relays.push(r);
        } catch {
          /* invalid URL — skip */
        }
      });
      secret = params.get("secret") || undefined;
    }

    if (relays.length === 0) {
      return { valid: false, error: "At least one relay required" };
    }

    return { valid: true, data: { pubkey, relays, secret } };
  } catch (e) {
    return { valid: false, error: e instanceof Error ? e.message : String(e) };
  }
}

/* ── Client ────────────────────────────────────────────────── */

export type Nip46Status = "disconnected" | "connecting" | "connected" | "error";

export interface Nip46Config {
  bunkerUrl: string;
  timeout?: number;
  /** Inject a shared pool; defaults to a private SimplePool. */
  pool?: SimplePool;
  /** Timestamp source for published events (privacy jitter hook). */
  now?: () => number;
}

interface Nip46Request {
  id: string;
  method: string;
  params: string[];
}

interface Nip46Response {
  id: string;
  result?: string;
  error?: string;
}

function normalizePubkey(pk: string): string {
  return pk.toLowerCase();
}

export class Nip46Client {
  private pool: SimplePool;
  private ownPool: boolean;
  private clientSecretKey: Uint8Array;
  private clientPubkey: string;
  private bunkerData: BunkerUrlData | null = null;
  private remotePubkey: string | null = null;
  private timeout: number;
  private now: () => number;
  private pendingRequests = new Map<
    string,
    {
      resolve: (result: string) => void;
      reject: (error: Error) => void;
      timer: ReturnType<typeof setTimeout>;
    }
  >();
  private subCloser: (() => void) | null = null;
  public status: Nip46Status = "disconnected";

  constructor(config: Nip46Config) {
    this.pool = config.pool ?? new SimplePool();
    this.ownPool = !config.pool;
    this.clientSecretKey = generateSecretKey();
    this.clientPubkey = getPublicKey(this.clientSecretKey);
    this.timeout = config.timeout ?? 30000;
    this.now = config.now ?? (() => Math.floor(Date.now() / 1000));

    const parsed = parseBunkerUrl(config.bunkerUrl);
    if (!parsed.valid || !parsed.data) {
      throw new Error(parsed.error || "Invalid bunker URL");
    }
    this.bunkerData = parsed.data;
    this.remotePubkey = parsed.data.pubkey;
  }

  async connect(): Promise<{ publicKey: string }> {
    if (!this.bunkerData || !this.remotePubkey) {
      throw new Error("Invalid bunker configuration");
    }

    this.status = "connecting";

    try {
      this.subscribeToResponses();

      const params = [this.clientPubkey];
      if (this.bunkerData.secret) {
        params.push(this.bunkerData.secret);
      }

      const result = await this.sendRequest("connect", params);
      if (result !== "ack") {
        throw new Error(`Connect failed: ${result}`);
      }

      const pubkey = await this.sendRequest("get_public_key", []);

      this.status = "connected";
      return { publicKey: pubkey };
    } catch (e) {
      this.status = "error";
      const errorMsg = e instanceof Error ? e.message : String(e);
      throw new Error(`NIP-46 connection failed: ${errorMsg}`);
    }
  }

  private nip44EncryptLocal(pubkey: string, plaintext: string): string {
    const ck = nostrNip44.v2.utils.getConversationKey(this.clientSecretKey, pubkey);
    return nostrNip44.v2.encrypt(plaintext, ck);
  }

  private nip44DecryptLocal(pubkey: string, ciphertext: string): string {
    const ck = nostrNip44.v2.utils.getConversationKey(this.clientSecretKey, pubkey);
    return nostrNip44.v2.decrypt(ciphertext, ck);
  }

  private subscribeToResponses() {
    if (!this.bunkerData) return;

    const sub: SubCloser = this.pool.subscribeMany(
      this.bunkerData.relays,
      { kinds: [24133], "#p": [this.clientPubkey] },
      {
        onevent: async (event: Event) => {
          // Verify signature before trusting relay-sourced content.
          let sigOk = false;
          try {
            sigOk = verifyEvent(event);
          } catch {
            /* malformed */
          }
          if (!sigOk) return;

          // Only process responses from the expected bunker pubkey.
          if (normalizePubkey(event.pubkey ?? "") !== normalizePubkey(this.remotePubkey ?? "")) {
            return;
          }
          try {
            const decrypted = this.nip44DecryptLocal(event.pubkey ?? "", event.content);
            const response: Nip46Response = JSON.parse(decrypted);

            const pending = this.pendingRequests.get(response.id);
            if (pending) {
              clearTimeout(pending.timer);
              this.pendingRequests.delete(response.id);

              if (response.error) {
                pending.reject(new Error(response.error));
              } else {
                pending.resolve(response.result || "");
              }
            }
          } catch {
            // Decryption/parse failure — not meant for us; ignore.
          }
        },
      },
    );

    this.subCloser = () => sub.close();
  }

  private async sendRequest(method: string, params: string[]): Promise<string> {
    if (!this.bunkerData || !this.remotePubkey) {
      throw new Error("Not configured");
    }

    // 32 bytes of entropy for request IDs (collision-proof).
    const id = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));
    const request: Nip46Request = { id, method, params };

    const encrypted = this.nip44EncryptLocal(this.remotePubkey, JSON.stringify(request));

    const unsignedEvent: UnsignedEvent = {
      kind: 24133,
      created_at: this.now(),
      tags: [["p", this.remotePubkey]],
      content: encrypted,
      pubkey: this.clientPubkey,
    };

    const event: Event = {
      ...unsignedEvent,
      id: getEventHash(unsignedEvent),
      sig: finalizeEvent(unsignedEvent, this.clientSecretKey).sig,
    };

    // Register the pending handler BEFORE publishing (response-race fix).
    const responsePromise = new Promise<string>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pendingRequests.delete(id);
        reject(new Error("Request timeout"));
      }, this.timeout);

      this.pendingRequests.set(id, { resolve, reject, timer });
    });

    // Per-relay 5s publish timeout (unresponsive relays must not hang the flow).
    await Promise.allSettled(
      this.bunkerData.relays.map((relay) =>
        Promise.race([
          this.pool.publish([relay], event),
          new Promise<string>((_, reject) =>
            setTimeout(() => reject(new Error("relay timeout")), 5000),
          ),
        ]),
      ),
    );

    return responsePromise;
  }

  async getPublicKeyRemote(): Promise<string> {
    return this.sendRequest("get_public_key", []);
  }

  /** Ask the remote signer to sign an event template. Validates shape,
   * Schnorr signature, AND that the signing pubkey is the bunker's. */
  async finalizeEventRemote(template: UnsignedEvent): Promise<Event> {
    const result = await this.sendRequest("sign_event", [JSON.stringify(template)]);
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(result) as Record<string, unknown>;
    } catch (e) {
      throw new Error(
        `Remote signer returned invalid JSON: ${e instanceof Error ? e.message : String(e)}`,
      );
    }
    if (
      !parsed ||
      typeof parsed.id !== "string" ||
      typeof parsed.pubkey !== "string" ||
      typeof parsed.sig !== "string" ||
      typeof parsed.kind !== "number" ||
      typeof parsed.created_at !== "number" ||
      !Array.isArray(parsed.tags)
    ) {
      throw new Error("Remote signer returned invalid event: missing required fields");
    }
    if (!/^[0-9a-f]{128}$/.test(parsed.sig as string)) {
      throw new Error("Remote signer returned invalid signature format (expected 128 hex chars)");
    }
    try {
      if (!verifyEvent(parsed as unknown as Event)) {
        throw new Error("Remote signer returned event with invalid Schnorr signature");
      }
    } catch (e) {
      if (e instanceof Error && e.message.includes("invalid Schnorr")) throw e;
      throw new Error(
        `Remote signer signature verification failed: ${e instanceof Error ? e.message : String(e)}`,
      );
    }
    if (this.remotePubkey && normalizePubkey(parsed.pubkey as string) !== normalizePubkey(this.remotePubkey)) {
      throw new Error("Remote signer returned event signed with unexpected pubkey");
    }
    return parsed as unknown as Event;
  }

  /** Request NIP-44 encryption from the remote signer. */
  async encryptRemote(pubkey: string, plaintext: string): Promise<string> {
    return this.sendRequest("nip44_encrypt", [pubkey, plaintext]);
  }

  /** Request NIP-44 decryption from the remote signer. */
  async decryptRemote(pubkey: string, ciphertext: string): Promise<string> {
    return this.sendRequest("nip44_decrypt", [pubkey, ciphertext]);
  }

  disconnect(): void {
    this.subCloser?.();
    this.subCloser = null;
    this.pendingRequests.forEach((p) => {
      clearTimeout(p.timer);
      p.reject(new Error("Disconnected"));
    });
    this.pendingRequests.clear();
    try {
      if (this.ownPool) this.pool.close(this.bunkerData?.relays || []);
    } catch {
      /* pool already closed / relays unreachable */
    }
    this.status = "disconnected";
  }
}

/* ── Convenience: one-call connect → signer shape ──────────── */

export interface Nip46SignerSession {
  pubkey: string;
  client: Nip46Client;
  signer: {
    pubkey: string;
    signEvent: (template: {
      kind: number;
      created_at: number;
      tags: string[][];
      content: string;
    }) => Promise<Event>;
    nip44Encrypt: (pubkey: string, plaintext: string) => Promise<string | null>;
    nip44Decrypt: (pubkey: string, ciphertext: string) => Promise<string | null>;
  };
}

/**
 * Connect to a remote signer (bunker:// URL) and return a signer in the
 * same shape as the other bao-signer identity signers — so apps can swap
 * extension / passkey / remote without code changes.
 */
export async function connectNip46Signer(
  bunkerUrl: string,
  options?: { timeout?: number; pool?: SimplePool; now?: () => number },
): Promise<Nip46SignerSession> {
  const client = new Nip46Client({ bunkerUrl, ...options });
  const { publicKey } = await client.connect();
  return {
    pubkey: publicKey,
    client,
    signer: {
      pubkey: publicKey,
      signEvent: (template) =>
        client.finalizeEventRemote({ ...template, pubkey: publicKey } as UnsignedEvent),
      nip44Encrypt: async (pk, pt) => {
        try {
          return await client.encryptRemote(pk, pt);
        } catch {
          return null;
        }
      },
      nip44Decrypt: async (pk, ct) => {
        try {
          return await client.decryptRemote(pk, ct);
        } catch {
          return null;
        }
      },
    },
  };
}
