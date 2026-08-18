/**
 * loginFlows — thin client helpers for every bao-signer server login method.
 *
 * All helpers use the configured API base (configureBaoSignerClient) or a
 * per-call `apiBaseUrl` override. No secrets ever cross the wire:
 * - guest/nostr: only a signed kind-27235 event is sent
 * - lnurl: the wallet signs the k1 locally; only the signature is sent
 * - email/telegram: the server derives the account; the nsec is shown once
 */

import { finalizeEvent, type EventTemplate, type NostrEvent, nip19 } from "nostr-tools";
import { getSignerApiBase } from "./config.ts";
import { newSeedPhrase, createSeedIdentitySigner } from "./seedIdentity.ts";

export interface AuthSession {
  pubkey: string;
  npub?: string;
  nsec?: string | null;
  username?: string;
  firstLogin?: boolean;
  isNewAccount?: boolean;
  authMethod?: string;
  linkedMethods?: string[];
  relayBackupKey?: string;
  sessionToken: string;
  expires_at?: number;
}

/** GET /auth/challenge — server nonce for NIP-98 auth events. */
export async function fetchAuthChallenge(apiBaseUrl?: string): Promise<string> {
  const base = getSignerApiBase(apiBaseUrl);
  const res = await fetch(`${base}/v1/auth/challenge`);
  if (!res.ok) throw new Error(`Failed to get auth challenge (${res.status})`);
  const data = (await res.json()) as { challenge: string };
  return data.challenge;
}

/**
 * Build and sign a NIP-98 (kind 27235) auth event bound to an endpoint,
 * method, and server challenge.
 */
export function signAuthEvent(
  secretKey: Uint8Array,
  opts: { url: string; method: string; challenge: string },
): NostrEvent {
  const template: EventTemplate = {
    kind: 27235,
    created_at: Math.floor(Date.now() / 1000),
    tags: [
      ["u", opts.url],
      ["method", opts.method.toUpperCase()],
      ["challenge", opts.challenge],
    ],
    content: "",
  };
  return finalizeEvent(template, secretKey);
}

async function postSignedAuthEvent(
  path: "/v1/auth/guest" | "/v1/auth/nostr",
  secretKey: Uint8Array,
  apiBaseUrl?: string,
): Promise<AuthSession> {
  const base = getSignerApiBase(apiBaseUrl);
  const url = `${base}${path}`;
  const challenge = await fetchAuthChallenge(base);
  const event = signAuthEvent(secretKey, { url, method: "POST", challenge });
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ event }),
  });
  if (!res.ok) {
    const err = (await res.json().catch(() => ({}))) as { error?: { message?: string } };
    throw new Error(err.error?.message ?? `Auth failed (${res.status})`);
  }
  return (await res.json()) as AuthSession;
}

/** Guest login (Quick Start): any fresh Nostr keypair → short-lived session. */
export function guestLogin(secretKey: Uint8Array, apiBaseUrl?: string): Promise<AuthSession> {
  return postSignedAuthEvent("/v1/auth/guest", secretKey, apiBaseUrl);
}

/** Nostr login: existing keypair → long-lived session. */
export function nostrLogin(secretKey: Uint8Array, apiBaseUrl?: string): Promise<AuthSession> {
  return postSignedAuthEvent("/v1/auth/nostr", secretKey, apiBaseUrl);
}

/* ── LNURL-auth (Lightning wallet login) ─────────────────────── */

export interface LnurlChallenge {
  lnurl: string;
  k1: string;
  expiresAt: number;
}

export async function lnurlStart(apiBaseUrl?: string): Promise<LnurlChallenge> {
  const base = getSignerApiBase(apiBaseUrl);
  const res = await fetch(`${base}/v1/auth/lnurl`);
  if (!res.ok) throw new Error(`Failed to start LNURL auth (${res.status})`);
  return (await res.json()) as LnurlChallenge;
}

export interface LnurlPollResult {
  authenticated: boolean;
  expiresAt?: number;
  session?: AuthSession;
}

export async function lnurlPoll(k1: string, apiBaseUrl?: string): Promise<LnurlPollResult> {
  const base = getSignerApiBase(apiBaseUrl);
  const res = await fetch(`${base}/v1/auth/lnurl/poll?k1=${encodeURIComponent(k1)}`);
  if (res.status === 410) return { authenticated: false };
  if (!res.ok) throw new Error(`LNURL poll failed (${res.status})`);
  return (await res.json()) as LnurlPollResult;
}

/* ── Email OTP ───────────────────────────────────────────────── */

export async function emailRequestOtp(email: string, apiBaseUrl?: string): Promise<void> {
  const base = getSignerApiBase(apiBaseUrl);
  const res = await fetch(`${base}/v1/auth/email/request`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
  });
  if (!res.ok) {
    const err = (await res.json().catch(() => ({}))) as { error?: string };
    throw new Error(err.error ?? `OTP request failed (${res.status})`);
  }
}

export async function emailVerifyOtp(
  email: string,
  code: string,
  apiBaseUrl?: string,
): Promise<{ session: AuthSession }> {
  const base = getSignerApiBase(apiBaseUrl);
  const res = await fetch(`${base}/v1/auth/email/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, code }),
  });
  if (!res.ok) {
    const err = (await res.json().catch(() => ({}))) as { error?: string };
    throw new Error(err.error ?? `OTP verify failed (${res.status})`);
  }
  return (await res.json()) as { session: AuthSession };
}

/* ── Telegram ────────────────────────────────────────────────── */

export async function telegramGetConfig(
  apiBaseUrl?: string,
): Promise<{ botUsername?: string; configured: boolean }> {
  const base = getSignerApiBase(apiBaseUrl);
  const res = await fetch(`${base}/v1/auth/telegram/config`);
  if (!res.ok) throw new Error(`Telegram config failed (${res.status})`);
  return (await res.json()) as { botUsername?: string; configured: boolean };
}

export interface TelegramQrChallenge {
  state: string;
  authUrl: string;
  expiresAt: number;
}

export async function telegramQrStart(apiBaseUrl?: string): Promise<TelegramQrChallenge> {
  const base = getSignerApiBase(apiBaseUrl);
  const res = await fetch(`${base}/v1/auth/telegram/qr`);
  if (!res.ok) throw new Error(`Telegram QR start failed (${res.status})`);
  return (await res.json()) as TelegramQrChallenge;
}

export interface TelegramQrPollResult {
  authenticated: boolean;
  expiresAt?: number;
  session?: AuthSession;
}

export async function telegramQrPoll(
  state: string,
  apiBaseUrl?: string,
): Promise<TelegramQrPollResult> {
  const base = getSignerApiBase(apiBaseUrl);
  const res = await fetch(`${base}/v1/auth/telegram/qr/poll?state=${encodeURIComponent(state)}`);
  if (res.status === 410) return { authenticated: false };
  if (!res.ok) throw new Error(`Telegram QR poll failed (${res.status})`);
  return (await res.json()) as TelegramQrPollResult;
}

/** Data returned by the Telegram Login Widget. */
export interface TelegramWidgetData {
  id: number;
  first_name?: string;
  last_name?: string;
  username?: string;
  photo_url?: string;
  auth_date: number;
  hash: string;
}

export async function telegramWidgetVerify(
  data: TelegramWidgetData,
  apiBaseUrl?: string,
): Promise<{ session: AuthSession }> {
  const base = getSignerApiBase(apiBaseUrl);
  const res = await fetch(`${base}/v1/auth/telegram/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    const err = (await res.json().catch(() => ({}))) as { error?: string };
    throw new Error(err.error ?? `Telegram verify failed (${res.status})`);
  }
  return (await res.json()) as { session: AuthSession };
}

/* ── Self-custody onboarding ─────────────────────────────────── */

/**
 * Create a fully self-custodial identity: a fresh 24-word BIP-39 seed phrase
 * derives the Nostr key entirely on the client — the server never sees or
 * generates the key. The returned `nsec` + `phrase` are the user's recovery
 * material (save once, then bind email/passkey via the register/link flows).
 */
export function createSelfCustodyAccount(): {
  phrase: string;
  pubkey: string;
  npub: string;
  nsec: string;
  signer: ReturnType<typeof createSeedIdentitySigner>;
} {
  const phrase = newSeedPhrase(256);
  const identity = createSeedIdentitySigner(phrase);
  return {
    phrase,
    pubkey: identity.pubkey,
    npub: nip19.npubEncode(identity.pubkey),
    nsec: identity.nsec,
    signer: identity,
  };
}

/**
 * Bind a client-generated key to an email (the self-custody onboarding path).
 * Requires an OTP from {@link emailRequestOtp}. Use with a server configured
 * with `allowServerKeyGeneration: false`: it stores only `email → pubkey` and
 * never mints or retains a copy of the nsec.
 */
export async function emailRegisterKey(opts: {
  email: string;
  nsec: string;
  username: string;
  code: string;
  apiBaseUrl?: string;
}): Promise<{ registered: boolean; pubkey: string }> {
  const base = getSignerApiBase(opts.apiBaseUrl);
  const res = await fetch(`${base}/v1/auth/email/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: opts.email, nsec: opts.nsec, username: opts.username, code: opts.code }),
  });
  if (!res.ok) {
    const err = (await res.json().catch(() => ({}))) as { error?: string };
    throw new Error(err.error ?? `Email register failed (${res.status})`);
  }
  return (await res.json()) as { registered: boolean; pubkey: string };
}
