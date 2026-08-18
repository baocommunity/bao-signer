/**
 * nip07 — NIP-07 browser-extension connect for bao-signer.
 *
 * Ported from bao.markets' battle-tested extension flow (UnifiedLoginModal
 * EXT-SYNC-001 / EXT-CACHE-001 lessons):
 *
 *  - SYNCHRONOUS shape check: extensions (Alby, nos2x) need an active user
 *    gesture to open their approval popup. Any async delay between the click
 *    and getPublicKey() lets the gesture expire and the extension silently
 *    hangs — callers must invoke connectNip07Signer() directly from the
 *    click handler (it does the shape check synchronously).
 *  - Cached pubkey: repeated callers (hooks re-running on storage/auth
 *    events) must not re-open the approval popup every time. Denials are
 *    cached too — one denial is respected until an explicit retry
 *    ({ force: true }) from a real user action.
 *  - Honest timeout: "check the extension popup" instead of hanging forever.
 */

export interface Nip07Extension {
  getPublicKey: () => Promise<string>;
  signEvent?: (event: {
    kind: number;
    created_at: number;
    tags: string[][];
    content: string;
  }) => Promise<{
    id: string;
    pubkey: string;
    sig: string;
    kind: number;
    created_at: number;
    tags: string[][];
    content: string;
  }>;
  nip44?: {
    encrypt: (pubkey: string, plaintext: string) => Promise<string>;
    decrypt: (pubkey: string, ciphertext: string) => Promise<string>;
  };
}

/** Read the injected extension, or null when absent / wrong shape. */
export function getNip07Extension(): Nip07Extension | null {
  if (typeof window === "undefined") return null;
  const n = (window as unknown as { nostr?: Nip07Extension }).nostr;
  if (!n || typeof n.getPublicKey !== "function") return null;
  return n;
}

export function isNip07Available(): boolean {
  return getNip07Extension() !== null;
}

/* ── Cached pubkey (EXT-CACHE-001) ─────────────────────────── */

let _pubkeyCache: string | null = null;
let _pubkeyPromise: Promise<string> | null = null;
let _denialError: Error | null = null;

/** Clear the cached pubkey/denial (explicit logout or account switch). */
export function clearNip07PublicKeyCache(): void {
  _pubkeyCache = null;
  _pubkeyPromise = null;
  _denialError = null;
}

/**
 * Get the extension pubkey, prompting at most once per session.
 * Denials are cached and re-thrown unless `{ force: true }` (explicit
 * user action retrying after a denial).
 */
export async function getNip07PublicKey(options?: { force?: boolean }): Promise<string> {
  const force = options?.force === true;

  if (!force && _denialError) throw _denialError;
  if (force && _denialError) {
    _denialError = null;
    _pubkeyPromise = null;
  }
  if (_pubkeyCache) return _pubkeyCache;
  if (_pubkeyPromise) return _pubkeyPromise;

  const n = getNip07Extension();
  if (!n) {
    throw new Error(
      "No Nostr extension detected. If you just enabled it, refresh the page and try again.",
    );
  }

  _pubkeyPromise = n.getPublicKey().then(
    (key) => {
      if (typeof key !== "string" || key.length === 0) {
        throw new Error("Extension returned an empty public key. Try refreshing the page.");
      }
      _pubkeyCache = key;
      _denialError = null;
      return key;
    },
    (err) => {
      _pubkeyPromise = null;
      _denialError = err instanceof Error ? err : new Error(String(err));
      throw _denialError;
    },
  );
  return _pubkeyPromise;
}

/* ── Full connect: pubkey + signer shape ───────────────────── */

export interface Nip07SignerSession {
  pubkey: string;
  signer: {
    pubkey: string;
    signEvent: (event: {
      kind: number;
      created_at: number;
      tags: string[][];
      content: string;
    }) => Promise<never>;
    nip44Encrypt: ((pubkey: string, plaintext: string) => Promise<string | null>) | null;
    nip44Decrypt: ((pubkey: string, ciphertext: string) => Promise<string | null>) | null;
  };
  /** True when the extension exposes NIP-44 (wallet/config encryption works). */
  hasNip44: boolean;
}

export const DEFAULT_NIP07_TIMEOUT_MS = 15_000;

/**
 * Connect to the NIP-07 extension. MUST be called synchronously from a user
 * gesture (click handler) — see module docs. The shape check is synchronous;
 * the pubkey prompt races a timeout so a missed extension popup produces an
 * actionable error instead of a silent hang.
 */
export async function connectNip07Signer(options?: {
  timeoutMs?: number;
}): Promise<Nip07SignerSession> {
  const timeoutMs = options?.timeoutMs ?? DEFAULT_NIP07_TIMEOUT_MS;

  // Synchronous shape check (preserves the user gesture for the popup).
  const n = getNip07Extension();
  if (!n) {
    throw new Error(
      "No Nostr extension detected. If you just enabled it, refresh the page and try again.",
    );
  }

  let timeoutId: ReturnType<typeof setTimeout> | null = null;
  try {
    const pubkey = await Promise.race([
      getNip07PublicKey({ force: true }),
      new Promise<never>((_, rej) => {
        timeoutId = setTimeout(
          () =>
            rej(
              new Error(
                "Extension timed out. Check the extension popup and approve the request.",
              ),
            ),
          timeoutMs,
        );
      }),
    ]);

    const hasNip44 = typeof n.nip44?.encrypt === "function" && typeof n.nip44?.decrypt === "function";

    return {
      pubkey,
      hasNip44,
      signer: {
        pubkey,
        signEvent: (event) => {
          if (typeof n.signEvent !== "function") {
            return Promise.reject(
              new Error("This extension cannot sign events (missing signEvent)."),
            ) as Promise<never>;
          }
          return n.signEvent(event) as Promise<never>;
        },
        nip44Encrypt: hasNip44
          ? (pk: string, pt: string) => n.nip44!.encrypt(pk, pt).catch(() => null)
          : null,
        nip44Decrypt: hasNip44
          ? (pk: string, ct: string) => n.nip44!.decrypt(pk, ct).catch(() => null)
          : null,
      },
    };
  } finally {
    if (timeoutId !== null) clearTimeout(timeoutId);
  }
}
