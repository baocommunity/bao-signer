/**
 * Telegram Auth — Login Widget verification + OIDC QR login.
 *
 * Endpoints:
 * - GET  /auth/telegram/config   — Public bot config (username + configured flag)
 * - POST /auth/telegram/verify   — Verify Telegram Login Widget data
 * - GET  /auth/telegram/qr       — Generate OIDC PKCE challenge → QR auth URL
 * - GET  /auth/telegram/callback — OIDC redirect: exchange code, mark challenge
 * - GET  /auth/telegram/qr/poll  — Poll QR status, receive session
 *
 * Privacy model:
 * - auth_id = HMAC-SHA256(botToken, telegram_id) — non-reversible without the secret
 * - No PII stored: Telegram identity is discarded after auth_id derivation
 * - Username is random, never derived from Telegram identity
 *
 * Secrets policy: bot token / OIDC client secret are injected via options —
 * nothing is read from env or hardcoded here.
 */

import type { FastifyInstance } from 'fastify';
import { createHash, createHmac, timingSafeEqual, randomBytes } from 'crypto';
import { generateSecretKey, getPublicKey, nip19 } from 'nostr-tools';
import { bytesToHex } from '@noble/hashes/utils.js';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { holdNsec, consumeNsec, computeNsecHash } from './nsecManager.ts';
import type { SignerStorage } from './storage.ts';

const MAX_AUTH_AGE_SECONDS = 5 * 60;
const OIDC_CHALLENGE_TTL = 10 * 60;
const ERR_ACCOUNT_CREATION_DISABLED = 'ACCOUNT_CREATION_DISABLED';
const TELEGRAM_ISSUER = 'https://oauth.telegram.org';
const TELEGRAM_JWKS = createRemoteJWKSet(
  new URL('https://oauth.telegram.org/.well-known/jwks.json'),
);

/** Verify Telegram Login Widget data. https://core.telegram.org/widgets/login#checking-authorization */
function verifyTelegramAuth(data: Record<string, string>, botToken: string): boolean {
  const { hash, ...fields } = data;
  if (!hash) return false;

  const checkString = Object.keys(fields)
    .sort()
    .map((k) => `${k}=${fields[k]}`)
    .join('\n');

  const secretKey = createHash('sha256').update(botToken).digest();
  const expectedHash = createHmac('sha256', secretKey).update(checkString).digest('hex');

  try {
    return timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(expectedHash, 'hex'));
  } catch {
    return false;
  }
}

export interface TelegramAuthOptions {
  storage: SignerStorage;
  /** Bot token — required for the Login Widget flow + auth_id derivation. */
  botToken?: string;
  /** Public bot username (returned by /config so the frontend needn't hardcode it). */
  botUsername?: string;
  /** OIDC client credentials — required for the QR flow. */
  clientId?: string;
  clientSecret?: string;
  redirectUri?: string;
  /** Where to redirect after the OIDC callback. Default "/". */
  frontendBase?: string;
  /** HMAC secret for relay backup keys. REQUIRED (fail closed). */
  backupSecret: string;
  sessionTtlSeconds?: number;
  rateLimit?: { max: number; timeWindow: string };
  /**
   * When false, Telegram can only sign in an already-known user — it will
   * NEVER generate a Nostr key. Unknown users get a 403 (widget) or an
   * `account_creation_disabled` redirect (QR). Default true.
   */
  allowServerKeyGeneration?: boolean;
}

export async function telegramAuthRoutes(app: FastifyInstance, opts: TelegramAuthOptions): Promise<void> {
  if (!opts.backupSecret) throw new Error('telegramAuthRoutes: backupSecret is required (fail closed)');

  const storage = opts.storage;
  const rateLimit = opts.rateLimit ?? { max: 50, timeWindow: '1 minute' };
  const ttl = Math.max(opts.sessionTtlSeconds ?? 86400, 3600);
  const frontendBase = opts.frontendBase ?? '/';
  const allowMint = opts.allowServerKeyGeneration ?? true;

  /** Stable non-reversible auth id from a Telegram user id. */
  const deriveAuthId = (telegramId: string): string => {
    if (!opts.botToken) throw new Error('Telegram bot token not configured');
    return createHmac('sha256', opts.botToken).update(telegramId).digest('hex');
  };

  const relayBackupKeyFor = (authId: string): string =>
    createHmac('sha256', opts.backupSecret).update(`telegram:${authId}`).digest('hex').slice(0, 32);

  /** Shared find-or-create-account logic. Returns session payload pieces. */
  async function resolveAccount(authId: string, holdKey: string): Promise<{ pubkey: string; isNewAccount: boolean }> {
    const existing = await storage.findAuthMethod('telegram', authId);
    if (existing) return { pubkey: existing.pubkey, isNewAccount: false };
    if (!allowMint) throw new Error(ERR_ACCOUNT_CREATION_DISABLED);

    const nsecBytes = generateSecretKey();
    const nsecHex = bytesToHex(nsecBytes);
    const pubkey = getPublicKey(nsecBytes);
    const username = 'user_' + randomBytes(4).toString('hex');
    const now = Math.floor(Date.now() / 1000);

    // Create the account first (the auth-method row references it via FK in
    // the reference schema), then claim the auth id atomically. Exactly one
    // caller of concurrent first logins wins the claim; losers adopt the
    // winner's pubkey instead of minting a second identity whose held nsec
    // would no longer match the account.
    await storage.insertAccount({ pubkey, nsec_hash: computeNsecHash(nsecHex), username, now });

    const claimed = await storage.insertAuthMethodIfAbsent({ method: 'telegram', authId, pubkey, now });
    if (!claimed) {
      const canonical = await storage.findAuthMethod('telegram', authId);
      return { pubkey: canonical?.pubkey ?? pubkey, isNewAccount: false };
    }

    holdNsec(holdKey, nsecHex, nip19.nsecEncode(nsecBytes));
    return { pubkey, isNewAccount: true };
  }

  // ── GET /auth/telegram/config ──────────────────────────────────
  app.get('/auth/telegram/config', {
    config: { rateLimit },
  }, async (_request, reply) => {
    return reply.send({
      botUsername: opts.botUsername,
      configured: !!opts.botToken,
    });
  });

  // ── GET /auth/telegram/qr ──────────────────────────────────────
  app.get('/auth/telegram/qr', {
    config: { rateLimit },
  }, async (_request, reply) => {
    if (!opts.clientId || !opts.clientSecret || !opts.redirectUri) {
      return reply.status(503).send({ error: 'Telegram OIDC not configured' });
    }

    const state = randomBytes(32).toString('hex');
    const codeVerifier = randomBytes(32).toString('base64url');
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + OIDC_CHALLENGE_TTL;

    await storage.tgInsertChallenge(state, codeVerifier, now, expiresAt);

    const params = new URLSearchParams({
      client_id: opts.clientId,
      redirect_uri: opts.redirectUri,
      response_type: 'code',
      scope: 'openid',
      state,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    });
    const authUrl = `https://oauth.telegram.org/auth?${params.toString()}`;

    return reply.send({ state, authUrl, expiresAt });
  });

  // ── GET /auth/telegram/callback ────────────────────────────────
  app.get('/auth/telegram/callback', {
    config: { rateLimit },
    schema: {
      querystring: {
        type: 'object',
        properties: {
          code: { type: 'string' },
          state: { type: 'string' },
          error: { type: 'string' },
        },
      },
    },
  }, async (request, reply) => {
    const { code, state, error } = request.query as Record<string, string | undefined>;

    if (error || !code || !state) return reply.redirect(`${frontendBase}?tg_error=cancelled`);
    if (!/^[0-9a-f]{64}$/.test(state)) return reply.redirect(`${frontendBase}?tg_error=cancelled`);
    if (!opts.clientId || !opts.clientSecret || !opts.redirectUri) {
      return reply.redirect(`${frontendBase}?tg_error=not_configured`);
    }

    const now = Math.floor(Date.now() / 1000);
    const challenge = await storage.tgGetChallenge(state);
    if (!challenge || challenge.expires_at < now || challenge.authenticated) {
      return reply.redirect(`${frontendBase}?tg_error=expired`);
    }

    // Exchange authorization code for tokens
    let idToken: string;
    try {
      const tokenRes = await fetch('https://oauth.telegram.org/token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Basic ${Buffer.from(`${opts.clientId}:${opts.clientSecret}`).toString('base64')}`,
        },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code,
          redirect_uri: opts.redirectUri,
          client_id: opts.clientId,
          code_verifier: challenge.code_verifier,
        }).toString(),
        signal: AbortSignal.timeout(10_000),
      });
      if (!tokenRes.ok) {
        request.log.warn({ status: tokenRes.status }, 'Telegram token exchange failed');
        return reply.redirect(`${frontendBase}?tg_error=token_exchange`);
      }
      const tokens = (await tokenRes.json()) as { id_token?: string };
      if (!tokens.id_token) return reply.redirect(`${frontendBase}?tg_error=no_id_token`);
      idToken = tokens.id_token;
    } catch (err) {
      request.log.error({ err: err instanceof Error ? err.message : String(err) }, 'Telegram token exchange error');
      return reply.redirect(`${frontendBase}?tg_error=network`);
    }

    // Validate the OIDC JWT
    let telegramId: string;
    try {
      const { payload } = await jwtVerify(idToken, TELEGRAM_JWKS, {
        issuer: TELEGRAM_ISSUER,
        audience: opts.clientId,
      });
      if (!payload.sub) throw new Error('Missing sub claim');
      telegramId = String(payload.sub);
    } catch (err) {
      request.log.warn({ err: err instanceof Error ? err.message : String(err) }, 'Telegram JWT validation failed');
      return reply.redirect(`${frontendBase}?tg_error=invalid_token`);
    }

    const authId = deriveAuthId(telegramId);
    let pubkey: string;
    let isNewAccount: boolean;
    try {
      ({ pubkey, isNewAccount } = await resolveAccount(authId, state));
    } catch (err) {
      if (err instanceof Error && err.message === ERR_ACCOUNT_CREATION_DISABLED) {
        return reply.redirect(`${frontendBase}?tg_error=account_creation_disabled`);
      }
      throw err;
    }
    await storage.tgMarkAuthenticated(state, { authId, pubkey, isNewAccount });

    return reply.redirect(`${frontendBase}?tg_done=${state}`);
  });

  // ── GET /auth/telegram/qr/poll ─────────────────────────────────
  app.get('/auth/telegram/qr/poll', {
    config: { rateLimit },
    schema: {
      querystring: {
        type: 'object',
        required: ['state'],
        properties: { state: { type: 'string' } },
      },
    },
  }, async (request, reply) => {
    const { state } = request.query as { state: string };
    if (!/^[0-9a-f]{64}$/.test(state)) {
      return reply.status(400).send({ error: { code: 'INVALID_STATE', message: 'state must be 64 hex characters' } });
    }

    const now = Math.floor(Date.now() / 1000);

    // Atomic consume — concurrent polls cannot mint duplicate sessions
    const consumed = await storage.tgConsumeAuthenticated(state);
    if (!consumed) {
      const pending = await storage.tgGetChallenge(state);
      if (!pending) {
        return reply.status(404).send({ error: { code: 'NOT_FOUND', message: 'Challenge not found' } });
      }
      if (pending.expires_at < now) {
        await storage.tgDeleteChallenge(state);
        return reply.status(410).send({ error: { code: 'EXPIRED', message: 'Challenge expired. Request a new one.' } });
      }
      return reply.send({ authenticated: false, expiresAt: pending.expires_at });
    }

    const pubkey = consumed.resolved_pubkey!;
    const account = await storage.getAccount(pubkey);
    if (!account) {
      return reply.status(500).send({ error: { code: 'ACCOUNT_NOT_FOUND', message: 'Account not found' } });
    }

    const nsecData = consumeNsec(state);
    const sessionToken = `bao_sess_${randomBytes(32).toString('hex')}`;
    await storage.storeSession(sessionToken, pubkey, {
      userAgent: request.headers['user-agent'] || '',
      ipAddress: request.ip,
      expiresAt: now + ttl,
    });
    const methods = await storage.getAuthMethodsForPubkey(pubkey);

    return reply.send({
      authenticated: true,
      session: {
        pubkey: account.pubkey,
        npub: nip19.npubEncode(account.pubkey),
        nsec: nsecData?.nsec_bech32 ?? null,
        username: account.username,
        firstLogin: nsecData !== null,
        isNewAccount: consumed.is_new_account === 1,
        authMethod: 'telegram',
        linkedMethods: methods.map((m) => m.method),
        relayBackupKey: consumed.auth_id ? relayBackupKeyFor(consumed.auth_id) : '',
        sessionToken,
        expires_at: now + ttl,
      },
    });
  });

  // Periodic cleanup of expired OIDC challenges
  const cleanupTimer = setInterval(() => {
    storage.tgDeleteExpired(Math.floor(Date.now() / 1000)).catch((err) => {
      app.log.warn({ err: err instanceof Error ? err.message : String(err) }, '[telegramAuth] challenge cleanup failed (non-fatal)');
    });
  }, 15 * 60 * 1000);
  if (cleanupTimer.unref) cleanupTimer.unref();

  // ── POST /auth/telegram/verify (Login Widget) ──────────────────
  app.post('/auth/telegram/verify', {
    config: { rateLimit },
    schema: {
      body: {
        type: 'object',
        required: ['id', 'auth_date', 'hash'],
        properties: {
          id: { type: 'number' },
          first_name: { type: 'string' },
          last_name: { type: 'string' },
          username: { type: 'string' },
          photo_url: { type: 'string' },
          auth_date: { type: 'number' },
          hash: { type: 'string' },
        },
      },
    },
  }, async (request, reply) => {
    if (!opts.botToken) {
      return reply.status(503).send({ error: 'Telegram login not configured' });
    }

    const body = request.body as {
      id: number;
      first_name?: string;
      last_name?: string;
      username?: string;
      photo_url?: string;
      auth_date: number;
      hash: string;
    };

    // Cap user-controlled fields before HMAC; they are discarded after verification.
    const MAX_FIELD_LEN = 256;
    const capField = (v?: string) => v?.slice(0, MAX_FIELD_LEN);

    const dataForVerification: Record<string, string> = {
      id: String(body.id),
      auth_date: String(body.auth_date),
      hash: body.hash,
    };
    if (body.first_name) dataForVerification.first_name = capField(body.first_name)!;
    if (body.last_name) dataForVerification.last_name = capField(body.last_name)!;
    if (body.username) dataForVerification.username = capField(body.username)!;
    if (body.photo_url) dataForVerification.photo_url = capField(body.photo_url)!;

    if (!verifyTelegramAuth(dataForVerification, opts.botToken)) {
      return reply.status(401).send({ error: 'Invalid Telegram auth data' });
    }

    const now = Math.floor(Date.now() / 1000);
    // Absolute window: a far-future auth_date must not live forever either.
    if (Math.abs(now - body.auth_date) > MAX_AUTH_AGE_SECONDS) {
      return reply.status(401).send({ error: 'Telegram auth data expired' });
    }

    // PII discarded after this point — only the opaque auth_id is used
    const authId = deriveAuthId(String(body.id));
    let pubkey: string;
    let isNewAccount: boolean;
    try {
      ({ pubkey, isNewAccount } = await resolveAccount(authId, authId));
    } catch (err) {
      if (err instanceof Error && err.message === ERR_ACCOUNT_CREATION_DISABLED) {
        return reply.status(403).send({ error: 'Account creation is disabled. Create a self-custodial identity first, then link Telegram.' });
      }
      throw err;
    }

    const account = await storage.getAccount(pubkey);
    if (!account) {
      return reply.status(500).send({ error: 'Account not found after creation' });
    }

    const nsecData = consumeNsec(authId);
    const sessionToken = `bao_sess_${randomBytes(32).toString('hex')}`;
    await storage.storeSession(sessionToken, pubkey, {
      userAgent: request.headers['user-agent'] || '',
      ipAddress: request.ip,
      expiresAt: now + ttl,
    });
    const methods = await storage.getAuthMethodsForPubkey(pubkey);

    return reply.send({
      session: {
        pubkey: account.pubkey,
        npub: nip19.npubEncode(account.pubkey),
        nsec: nsecData?.nsec_bech32 ?? null,
        username: account.username,
        firstLogin: nsecData !== null,
        isNewAccount,
        authMethod: 'telegram',
        linkedMethods: methods.map((m) => m.method),
        relayBackupKey: relayBackupKeyFor(authId),
        sessionToken,
        expires_at: now + ttl,
      },
    });
  });
}
