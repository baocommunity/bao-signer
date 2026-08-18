import {
  startRegistration,
  startAuthentication,
  bufferToBase64URLString,
} from "@simplewebauthn/browser";
import type {
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  AuthenticationExtensionsClientInputs,
  AuthenticationExtensionsClientOutputs,
} from "@simplewebauthn/browser";
import { getPublicKey, nip19 } from "nostr-tools";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { getSignerApiBase } from "./config.ts";
import { ensureValidSecp256k1Scalar } from "./derivedKeys.ts";
import {
  BAO_PRF_CONTEXT,
  BreezPasskeyError,
  BrowserPasskeyPrfProvider,
  base64URLStringToBuffer,
  extractPrfFromAuthenticationResponse,
} from "./prf.ts";

/**
 * Default PRF salt for the BAO auth path (registration + login).
 *
 * @note This salt is intentionally simple (just the context string) because the
 * auth path derives Nostr keys from the PRF output. The Breez SDK provider path
 * in `prf.ts` uses a compound salt `${BAO_PRF_CONTEXT}:${credentialId}:${userSalt}`
 * because Breez requires a per-credential, per-user salt for deterministic wallet
 * seed derivation. Keep the two salt strategies distinct.
 */
const DEFAULT_PRF_SALT = BAO_PRF_CONTEXT;

interface NostrKeyPair {
  pubkeyHex: string;
  npub: string;
  nsec: string;
  privKeyBytes: Uint8Array;
}

export function deriveNostrKeysFromPrfSeed(prfSeed: Uint8Array): NostrKeyPair {
  const seedHex = bytesToHex(prfSeed);
  // Domain-separated derivation, then scalar validation. sha256 output is
  // overwhelmingly likely to be a valid secp256k1 scalar, but an invalid one
  // (0 or >= curve order N) would break getPublicKey — guard against it.
  const privKeyBytes = ensureValidSecp256k1Scalar(
    sha256(new TextEncoder().encode(`bao:nostr:v1:${seedHex}`)),
  );
  const pubkeyHex = getPublicKey(privKeyBytes);
  const npub = nip19.npubEncode(pubkeyHex);
  const nsec = nip19.nsecEncode(privKeyBytes);
  return { pubkeyHex, npub, nsec, privKeyBytes };
}

export function extractPrfSeedFromResponse(
  response: RegistrationResponseJSON | AuthenticationResponseJSON,
): Uint8Array | null {
  const extResults = response.clientExtensionResults as AuthenticationExtensionsClientOutputs & {
    prf?: { results?: { first?: ArrayBuffer } };
  };

  if (!extResults.prf?.results?.first) {
    return null;
  }

  return new Uint8Array(extResults.prf.results.first);
}

/**
 * Check whether the browser supports WebAuthn PRF (via Breez provider).
 */
export async function isBreezPrfAvailable(): Promise<boolean> {
  const provider = new BrowserPasskeyPrfProvider();
  return provider.isPrfAvailable();
}

/**
 * Shared PRF-seed extraction with the self-auth fallback: some authenticators
 * report `prf.enabled` at creation but withhold the result until the first
 * assertion. Used by both the (legacy) direct register flow and the
 * authenticated account-link flow.
 */
async function extractPrfSeedWithFallback(
  credential: RegistrationResponseJSON,
  rpId?: string,
): Promise<Uint8Array> {
  let prfSeed = extractPrfSeedFromResponse(credential);

  if (!prfSeed) {
    const extResults = credential.clientExtensionResults as AuthenticationExtensionsClientOutputs & {
      prf?: { enabled?: boolean };
    };
    if (extResults?.prf?.enabled) {
      const authOptionsJSON: PublicKeyCredentialRequestOptionsJSON = {
        challenge: bufferToBase64URLString(crypto.getRandomValues(new Uint8Array(32)).buffer),
        rpId: rpId || window.location.hostname,
        allowCredentials: [
          {
            id: credential.rawId || credential.id,
            type: "public-key",
          },
        ],
        userVerification: "required",
        extensions: {
          prf: {
            eval: {
              first: new TextEncoder().encode(DEFAULT_PRF_SALT),
            },
          },
        } as AuthenticationExtensionsClientInputs,
      };
      try {
        const authResponse = await startAuthentication({
          optionsJSON: authOptionsJSON,
        });
        const authPrfSeed = extractPrfSeedFromResponse(authResponse);
        if (authPrfSeed) {
          prfSeed = authPrfSeed;
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : "Unknown error";
        throw new Error(
          `${BreezPasskeyError.PRF_RESULT_NOT_AVAILABLE}: PRF result not available after self-authentication: ${message}`,
        );
      }
    }
  }

  if (!prfSeed) {
    throw new Error(
      `${BreezPasskeyError.PRF_NOT_SUPPORTED}: PRF extension not supported or returned no result. Ensure your browser supports WebAuthn PRF.`,
    );
  }
  return prfSeed;
}

/**
 * Register a new Breez PRF passkey, derive a deterministic Nostr identity from the
 * PRF seed, and link the passkey to the backend with the client-generated pubkey.
 *
 * @returns The registration response, PRF seed (raw bytes), derived Nostr
 *          keys, and credential ID.
 *
 * SECURITY NOTE: `prfSeedHex` is the raw authenticator PRF output, NOT the
 * Nostr private key. The Nostr secret key is derived from it via
 * domain-separated SHA-256 (see `deriveNostrKeysFromPrfSeed`). Treat
 * `prfSeedHex` with the same care as a private key — anyone holding it can
 * re-derive the identity — but never encode it as an nsec: doing so would
 * produce a DIFFERENT identity than `pubkeyHex`/`npub` returned here.
 *
 * SERVER POLICY NOTE: the reference server (`bao-signer/server`) rejects
 * anonymous registration with a client-supplied pubkey
 * (`PRF_ACCOUNT_LINK_REQUIRES_AUTH`). A WebAuthn attestation proves control of
 * the new credential, not of the claimed Nostr pubkey, so PRF identities are
 * linked through the authenticated account-link flow instead. Against the
 * reference server, use `linkBreezPasskey({ sessionToken })` after
 * establishing a session (see loginFlows.ts) — this function targets
 * non-reference servers that accept direct PRF registration.
 */
export async function registerBreezPasskey(options: {
  username?: string;
  displayName?: string;
  /** Per-call API base override; otherwise configureBaoSignerClient() is used. */
  apiBaseUrl?: string;
} = {}): Promise<{
  credential: RegistrationResponseJSON;
  /** Raw 32-byte PRF seed. NOT the Nostr private key — see security note above. */
  prfSeed: Uint8Array;
  /** Hex encoding of `prfSeed`. NOT the Nostr private key — see security note above. */
  prfSeedHex: string;
  pubkeyHex: string;
  npub: string;
  nsec: string;
  credentialId: string;
  session?: {
    sessionToken: string;
    expires_at: number;
    firstLogin?: boolean;
    relayBackupKey?: string;
    username?: string;
  };
}> {
  const API_BASE = getSignerApiBase(options.apiBaseUrl);

  const optRes = await fetch(
    `${API_BASE}/v1/auth/passkey/register-options`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: options.username,
        displayName: options.displayName,
      }),
    },
  );

  if (!optRes.ok) {
    throw new Error(
      `${BreezPasskeyError.SERVER_ERROR}: Failed to get registration options`,
    );
  }

  const { challengeId, options: webAuthnOptions } = await optRes.json() as {
    challengeId: string;
    options: PublicKeyCredentialCreationOptionsJSON;
  };

  // Inject the PRF extension so the seed is derived in the same prompt.
  // We use DEFAULT_PRF_SALT ("bao:prf:v1") for the auth path; this is
  // distinct from the compound salt used in prf.ts for Breez SDK.
  webAuthnOptions.extensions = {
    ...(webAuthnOptions.extensions || {}),
    prf: {
      eval: {
        first: new TextEncoder().encode(DEFAULT_PRF_SALT),
      },
    },
  } as AuthenticationExtensionsClientInputs;

  const credential = await startRegistration({
    optionsJSON: webAuthnOptions,
  });

  const prfSeed = await extractPrfSeedWithFallback(credential, webAuthnOptions.rp.id);
  const { pubkeyHex, npub, nsec } = deriveNostrKeysFromPrfSeed(prfSeed);
  const credentialId = credential.id;
  const prfSeedHex = bytesToHex(prfSeed);

  const regRes = await fetch(`${API_BASE}/v1/auth/passkey/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      challengeId,
      credential,
      pubkey: pubkeyHex,
    }),
  });

  if (!regRes.ok) {
    throw new Error(
      `${BreezPasskeyError.REGISTRATION_FAILED}: Passkey registration failed on server`,
    );
  }

  const data = await regRes.json();

  // TODO: For full self-custody PRF, the relay backup key should ideally be
  // derived from the PRF output instead of server-side HMAC of credentialId.
  // Consider deriving it locally from prfSeed + a fixed context string.

  return {
    credential,
    prfSeed,
    prfSeedHex,
    pubkeyHex,
    npub,
    nsec,
    credentialId,
    session: data.session
      ? {
          sessionToken: data.session.sessionToken,
          expires_at: data.session.expires_at,
          firstLogin: data.session.firstLogin,
          relayBackupKey: data.session.relayBackupKey,
          username: data.session.username,
        }
      : undefined,
  };
}

/**
 * Authenticate with an existing Breez PRF passkey, re-derive the same Nostr identity,
 * and establish a session with the backend.
 *
 * @returns The authentication response, PRF seed (raw bytes), derived Nostr
 *          keys, credential ID, and server session payload.
 *          See the security note on `registerBreezPasskey` for why
 *          `prfSeedHex` is NOT the Nostr private key.
 */
export async function loginBreezPasskey(options: {
  /** Per-call API base override; otherwise configureBaoSignerClient() is used. */
  apiBaseUrl?: string;
} = {}): Promise<{
  assertion: AuthenticationResponseJSON;
  /** Raw 32-byte PRF seed. NOT the Nostr private key — see registerBreezPasskey. */
  prfSeed: Uint8Array;
  /** Hex encoding of `prfSeed`. NOT the Nostr private key — see registerBreezPasskey. */
  prfSeedHex: string;
  pubkeyHex: string;
  npub: string;
  nsec: string;
  credentialId: string;
  session: any;
}> {
  const API_BASE = getSignerApiBase(options.apiBaseUrl);

  const optRes = await fetch(`${API_BASE}/v1/auth/passkey/login-options`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
  });

  if (!optRes.ok) {
    throw new Error(
      `${BreezPasskeyError.SERVER_ERROR}: Failed to get login options`,
    );
  }

  const { challengeId, options: webAuthnOptions } = await optRes.json() as {
    challengeId: string;
    options: PublicKeyCredentialRequestOptionsJSON;
  };

  // Inject the PRF extension to re-derive the same seed deterministically.
  // We use DEFAULT_PRF_SALT ("bao:prf:v1") for the auth path.
  webAuthnOptions.extensions = {
    ...(webAuthnOptions.extensions || {}),
    prf: {
      eval: {
        first: new TextEncoder().encode(DEFAULT_PRF_SALT),
      },
    },
  } as AuthenticationExtensionsClientInputs;

  const assertion = await startAuthentication({
    optionsJSON: webAuthnOptions,
  });

  const prfSeed = extractPrfSeedFromResponse(assertion);
  if (!prfSeed) {
    throw new Error(
      `${BreezPasskeyError.PRF_NOT_SUPPORTED}: PRF extension not supported or returned no result. Ensure your browser supports WebAuthn PRF.`,
    );
  }

  const { pubkeyHex, npub, nsec } = deriveNostrKeysFromPrfSeed(prfSeed);
  const credentialId = assertion.id;
  const prfSeedHex = bytesToHex(prfSeed);

  const loginRes = await fetch(`${API_BASE}/v1/auth/passkey/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      challengeId,
      credential: assertion,
      pubkey: pubkeyHex,
    }),
  });

  if (!loginRes.ok) {
    throw new Error(
      `${BreezPasskeyError.LOGIN_FAILED}: Passkey login failed on server`,
    );
  }

  const data = await loginRes.json();

  // TODO: For full self-custody PRF, the relay backup key should ideally be
  // derived from the PRF output instead of server-side HMAC of credentialId.
  // Consider deriving it locally from prfSeed + a fixed context string.

  return {
    assertion,
    prfSeed,
    prfSeedHex,
    pubkeyHex,
    npub,
    nsec,
    credentialId,
    session: data.session ?? data,
  };
}


/* ═══ Authenticated account-link flow (the supported server path) ═════════
 *
 * The reference server REJECTS anonymous PRF registration
 * (PRF_ACCOUNT_LINK_REQUIRES_AUTH): an attestation proves control of the new
 * credential, not of a claimed Nostr pubkey. The supported flow is therefore:
 *
 *   1. establish a session first (guest/NIP-98/email/… — see loginFlows.ts)
 *   2. linkBreezPasskey({ sessionToken }) — binds a NEW passkey whose PRF
 *      derives the SAME deterministic identity to the session's account
 *
 * All three functions send `Authorization: Bearer <sessionToken>`.
 */

function bearerHeaders(sessionToken: string): Record<string, string> {
  return {
    "Content-Type": "application/json",
    Authorization: `Bearer ${sessionToken}`,
  };
}

/**
 * POST /auth/link/passkey/options — registration options for linking a new
 * passkey to the session's account. The returned options already carry a
 * challenge bound to the session pubkey server-side.
 */
export async function linkPasskeyOptions(opts: {
  sessionToken: string;
  apiBaseUrl?: string;
}): Promise<{ challengeId: string; options: PublicKeyCredentialCreationOptionsJSON }> {
  const API_BASE = getSignerApiBase(opts.apiBaseUrl);
  const res = await fetch(`${API_BASE}/v1/auth/link/passkey/options`, {
    method: "POST",
    headers: bearerHeaders(opts.sessionToken),
  });
  if (!res.ok) {
    throw new Error(
      `${BreezPasskeyError.SERVER_ERROR}: Failed to get link options (${res.status})`,
    );
  }
  return (await res.json()) as {
    challengeId: string;
    options: PublicKeyCredentialCreationOptionsJSON;
  };
}

/**
 * POST /auth/link/passkey/register — complete the link with the created
 * credential. The server verifies the attestation against the session-bound
 * challenge and binds the credential to the session's account.
 */
export async function linkPasskeyRegister(opts: {
  sessionToken: string;
  challengeId: string;
  credential: RegistrationResponseJSON;
  apiBaseUrl?: string;
}): Promise<{ linked: boolean; credentialId?: string }> {
  const API_BASE = getSignerApiBase(opts.apiBaseUrl);
  const res = await fetch(`${API_BASE}/v1/auth/link/passkey/register`, {
    method: "POST",
    headers: bearerHeaders(opts.sessionToken),
    body: JSON.stringify({
      challengeId: opts.challengeId,
      credential: opts.credential,
    }),
  });
  if (!res.ok) {
    const body = (await res.json().catch(() => ({}))) as { error?: { code?: string; message?: string } };
    const detail = body?.error?.message ?? body?.error?.code ?? `HTTP ${res.status}`;
    throw new Error(`${BreezPasskeyError.REGISTRATION_FAILED}: Passkey link failed: ${detail}`);
  }
  return (await res.json()) as { linked: boolean; credentialId?: string };
}

/**
 * Full PRF link flow: options → WebAuthn create (PRF-injected) → derive the
 * deterministic Nostr identity from the PRF seed → register the link.
 *
 * Requires an existing session (any login method). Returns the derived
 * identity; on subsequent logins use loginBreezPasskey() which re-derives
 * the same identity from the same passkey.
 */
export async function linkBreezPasskey(opts: {
  sessionToken: string;
  apiBaseUrl?: string;
}): Promise<{
  credential: RegistrationResponseJSON;
  prfSeed: Uint8Array;
  prfSeedHex: string;
  pubkeyHex: string;
  npub: string;
  nsec: string;
  credentialId: string;
}> {
  const { challengeId, options } = await linkPasskeyOptions(opts);

  // Inject the PRF extension so the seed is derived in the same prompt.
  options.extensions = {
    ...(options.extensions || {}),
    prf: {
      eval: {
        first: new TextEncoder().encode(DEFAULT_PRF_SALT),
      },
    },
  } as AuthenticationExtensionsClientInputs;

  const credential = await startRegistration({ optionsJSON: options });
  const prfSeed = await extractPrfSeedWithFallback(credential, options.rp.id);
  const { pubkeyHex, npub, nsec } = deriveNostrKeysFromPrfSeed(prfSeed);

  await linkPasskeyRegister({ ...opts, challengeId, credential });

  return {
    credential,
    prfSeed,
    prfSeedHex: bytesToHex(prfSeed),
    pubkeyHex,
    npub,
    nsec,
    credentialId: credential.id,
  };
}

/** Re-export error codes for backward compatibility. */
export { BreezPasskeyError };

/** Alias for {@link isBreezPrfAvailable} to match consumer naming convention. */
export const checkPrfAvailability = isBreezPrfAvailable;
