/**
 * LNURL-auth — Lightning wallet login (LUD-04 style).
 *
 * Endpoints:
 * - GET /auth/lnurl          — Generate k1 challenge, return LNURL bech32
 * - GET /auth/lnurl/callback — Wallet calls with signature
 * - GET /auth/lnurl/poll     — Frontend polls for auth status + session token
 *
 * "Show once, hash irreversibly": new accounts get their nsec exactly once
 * via the poll response; the server stores only SHA-256(nsec).
 */

import type { FastifyInstance } from 'fastify';
import { randomBytes, createHash, createHmac } from 'crypto';
import { bech32 } from 'bech32';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { generateSecretKey, getPublicKey, nip19 } from 'nostr-tools';
import { holdNsec, consumeNsec, computeNsecHash } from './nsecManager.ts';
import { deriveRelayBackupKey } from './relayBackupKey.ts';
import type { SignerStorage } from './storage.ts';

const K1_BYTES = 32;
const CHALLENGE_TTL_SECONDS = 5 * 60;
const HEX64 = /^[0-9a-f]{64}$/i;
// secp256k1 pubkeys: compressed = 33 bytes (66 hex), uncompressed = 65 bytes (130 hex)
const HEX_PUBKEY = /^[0-9a-f]{66}$|^[0-9a-f]{130}$/i;

/** One-shot plaintext session tokens between callback and poll. */
const pendingSessionTokens = new Map<string, { token: string; created_at: number }>();
const PENDING_TOKEN_TTL_MS = CHALLENGE_TTL_SECONDS * 1000;

function holdSessionToken(k1: string, token: string): void {
  pendingSessionTokens.set(k1, { token, created_at: Date.now() });
}

function consumeSessionToken(k1: string): string | null {
  const entry = pendingSessionTokens.get(k1);
  if (!entry) return null;
  pendingSessionTokens.delete(k1);
  if (Date.now() - entry.created_at > PENDING_TOKEN_TTL_MS) return null;
  return entry.token;
}

/** Test hook: drop a held token, simulating the process-restart window where
 * the challenge survives (persistent store) but the in-memory token is gone. */
export function __dropHeldSessionTokenForTest(k1: string): void {
  pendingSessionTokens.delete(k1);
}

function hashSessionToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

function generateK1(): string {
  return randomBytes(K1_BYTES).toString('hex');
}

function encodeLnurl(callbackUrl: string): string {
  const words = bech32.toWords(Buffer.from(callbackUrl, 'utf8'));
  return bech32.encode('lnurl', words, 2000);
}

function verifyLnurlSignature(sigHex: string, k1Hex: string, keyHex: string): boolean {
  try {
    // lowS: false — some Lightning wallets emit high-S DER signatures;
    // rejecting them is an availability failure, not a security control
    // (the message hash binds the signature either way).
    return secp256k1.verify(
      Buffer.from(sigHex, 'hex'),
      Buffer.from(k1Hex, 'hex'),
      Buffer.from(keyHex, 'hex'),
      { lowS: false },
    );
  } catch {
    return false;
  }
}

export interface LnurlAuthOptions {
  storage: SignerStorage;
  /**
   * Public base URL of this API (including any path prefix, no trailing
   * slash) — used to build the LNURL callback. Example:
   * "https://api.example.com/bao-api/v1"
   */
  publicBaseUrl: string;
  /**
   * HMAC secret for linking keys + relay backup keys. REQUIRED (fail closed):
   * without it, linking keys would be stored as raw wallet pubkeys and backup
   * keys would be publicly derivable.
   */
  secret: string;
  sessionTtlSeconds?: number;
  rateLimit?: { max: number; timeWindow: string };
}

export async function lnurlAuthRoutes(app: FastifyInstance, opts: LnurlAuthOptions): Promise<void> {
  if (!opts.publicBaseUrl) throw new Error('lnurlAuthRoutes: publicBaseUrl is required');
  if (!opts.secret) throw new Error('lnurlAuthRoutes: secret is required (fail closed)');

  const storage = opts.storage;
  const rateLimit = opts.rateLimit ?? { max: 50, timeWindow: '1 minute' };
  const ttl = Math.max(opts.sessionTtlSeconds ?? 86400, 3600);
  const callbackBase = opts.publicBaseUrl.replace(/\/+$/, '');

  /** Non-reversible auth id for a wallet linking key. */
  const hmacLinkingKey = (linkingKey: string): string =>
    createHmac('sha256', opts.secret).update(linkingKey).digest('hex');

  app.get('/auth/lnurl', {
    config: { rateLimit },
  }, async (_request, reply) => {
    const k1 = generateK1();
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + CHALLENGE_TTL_SECONDS;
    await storage.lnurlInsertChallenge(k1, now, expiresAt);
    const callbackUrl = `${callbackBase}/auth/lnurl/callback?tag=login&k1=${k1}`;
    const lnurl = encodeLnurl(callbackUrl);
    return reply.send({ lnurl, k1, expiresAt });
  });

  app.get('/auth/lnurl/callback', {
    config: { rateLimit },
    schema: {
      querystring: {
        type: 'object',
        required: ['tag', 'k1', 'sig', 'key'],
        properties: {
          tag: { type: 'string' },
          k1: { type: 'string' },
          sig: { type: 'string' },
          key: { type: 'string' },
        },
      },
    },
  }, async (request, reply) => {
    const { tag, k1, sig, key } = request.query as Record<string, string>;
    const sendError = (reason: string) => reply.send({ status: 'ERROR', reason });

    if (tag !== 'login') return sendError("Invalid tag: expected 'login'");
    if (!HEX64.test(k1)) return sendError('Invalid k1 format');
    if (!HEX_PUBKEY.test(key)) return sendError('Invalid key format');
    if (!sig || !/^[0-9a-f]+$/i.test(sig)) return sendError('Invalid signature format');

    const now = Math.floor(Date.now() / 1000);
    const challenge = await storage.lnurlGetChallenge(k1);
    if (!challenge) return sendError('Challenge not found');
    if (challenge.expires_at < now) return sendError('Challenge not found or expired');
    if (challenge.authenticated) return sendError('Challenge already used');
    if (!verifyLnurlSignature(sig, k1, key)) return sendError('Invalid signature');

    const linkingKey = key.toLowerCase();
    const authId = hmacLinkingKey(linkingKey);
    const existingMethod = await storage.findAuthMethod('lightning', authId);

    let pubkey: string;
    let isNewAccount = false;
    if (existingMethod) {
      pubkey = existingMethod.pubkey;
    } else {
      const nsecBytes = generateSecretKey();
      const nsecHex = bytesToHex(nsecBytes);
      pubkey = getPublicKey(nsecBytes);
      const username = 'user_' + randomBytes(4).toString('hex');
      await storage.insertAccount({ pubkey, nsec_hash: computeNsecHash(nsecHex), username, now });
      await storage.insertAuthMethod({ method: 'lightning', authId, pubkey, now });
      holdNsec(k1, nsecHex, nip19.nsecEncode(nsecBytes));
      isNewAccount = true;
    }

    // Mint the session up front so its hash lands on the challenge row; the
    // plaintext is held in memory for one-shot delivery at poll time.
    const sessionToken = `bao_sess_${randomBytes(32).toString('hex')}`;
    const sessionTokenHash = hashSessionToken(sessionToken);
    await storage.storeSession(sessionToken, pubkey, {
      userAgent: request.headers['user-agent'] || '',
      ipAddress: request.ip,
      expiresAt: now + ttl,
    });
    holdSessionToken(k1, sessionToken);
    await storage.lnurlMarkAuthenticated(k1, {
      linkingKey,
      pubkey,
      isNewAccount,
      sessionTokenHash,
    });

    return reply.send({ status: 'OK' });
  });

  app.get('/auth/lnurl/poll', {
    config: { rateLimit },
    schema: {
      querystring: {
        type: 'object',
        required: ['k1'],
        properties: { k1: { type: 'string' } },
      },
    },
  }, async (request, reply) => {
    const { k1 } = request.query as { k1: string };
    const meta = { request_id: request.id, timestamp: Math.floor(Date.now() / 1000) };
    if (!HEX64.test(k1)) {
      return reply.status(400).send({ error: { code: 'INVALID_K1', message: 'k1 must be 64 hex characters' }, meta });
    }

    const now = Math.floor(Date.now() / 1000);
    const challenge = await storage.lnurlGetChallenge(k1);
    if (!challenge) {
      return reply.status(404).send({ error: { code: 'LNURL_CHALLENGE_NOT_FOUND', message: 'Challenge not found' }, meta });
    }
    if (challenge.expires_at < now && !challenge.authenticated) {
      await storage.lnurlDeleteChallenge(k1);
      return reply.status(410).send({ error: { code: 'LNURL_CHALLENGE_EXPIRED', message: 'Challenge has expired. Request a new one.' }, meta });
    }
    if (!challenge.authenticated) {
      return reply.send({ authenticated: false, expiresAt: challenge.expires_at });
    }

    const pubkey = challenge.resolved_pubkey!;
    const isNewAccount = challenge.is_new_account === 1;
    const account = await storage.getAccount(pubkey);
    if (!account) {
      return reply.status(500).send({ error: { code: 'ACCOUNT_NOT_FOUND', message: 'Account created but not found' }, meta });
    }

    const nsecData = consumeNsec(k1);
    // MED-1 FIX: the held token is strictly one-shot. If it is gone (a
    // concurrent poll already consumed it, or the process restarted), we
    // must NOT mint a fresh session — that would hand out a second valid
    // session for the same challenge. Fail honestly instead.
    const sessionToken = consumeSessionToken(k1);
    if (!sessionToken) {
      await storage.lnurlDeleteChallenge(k1);
      return reply.status(410).send({
        error: {
          code: 'LNURL_SESSION_CONSUMED',
          message: 'Login session was already consumed (or the server restarted). Request a new challenge.',
        },
        meta,
      });
    }
    await storage.lnurlDeleteChallenge(k1);

    const methods = await storage.getAuthMethodsForPubkey(pubkey);
    const relayBackupKey = challenge.linking_key
      ? deriveRelayBackupKey(challenge.linking_key, opts.secret)
      : '';

    return reply.send({
      authenticated: true,
      session: {
        pubkey: account.pubkey,
        npub: nip19.npubEncode(account.pubkey),
        nsec: nsecData?.nsec_bech32 ?? null,
        username: account.username,
        firstLogin: nsecData !== null,
        isNewAccount,
        authMethod: 'lightning',
        linkedMethods: methods.map((m) => m.method),
        relayBackupKey,
        sessionToken,
      },
    });
  });
}
