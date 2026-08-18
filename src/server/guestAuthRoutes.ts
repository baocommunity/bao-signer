/**
 * Guest Auth — issues a short-lived session for Quick Start (guest) users.
 *
 * Flow:
 *   1. Client generates a fresh Nostr keypair (Quick Start)
 *   2. Client signs a kind-27235 event bound to this endpoint + server challenge
 *   3. POST /auth/guest with { event }
 *   4. Server verifies freshness, binding, challenge, and signature
 *   5. Server issues a session token
 *
 * No prior registration needed — any valid Nostr keypair works.
 */

import type { FastifyInstance } from 'fastify';
import { verifyEvent, nip19 } from 'nostr-tools';
import { createHash, randomBytes } from 'crypto';
import { verifyNip98Binding, validateNip98Challenge } from './nip98.ts';
import type { SignerStorage } from './storage.ts';

const GUEST_SESSION_TTL_SECONDS = 24 * 60 * 60; // guests are ephemeral
const MAX_EVENT_AGE_SECONDS = 5 * 60;

const nip98EventSchema = {
  type: 'object',
  required: ['event'],
  properties: {
    event: {
      type: 'object',
      required: ['id', 'pubkey', 'sig', 'kind', 'created_at', 'tags', 'content'],
      properties: {
        id: { type: 'string', maxLength: 128 },
        pubkey: { type: 'string', minLength: 64, maxLength: 64 },
        sig: { type: 'string', maxLength: 256 },
        kind: { type: 'number' },
        created_at: { type: 'number' },
        tags: { type: 'array', maxItems: 100 },
        content: { type: 'string', maxLength: 10_000 },
      },
    },
  },
} as const;

export interface GuestAuthOptions {
  storage: SignerStorage;
  rateLimit?: { max: number; timeWindow: string };
}

export async function guestAuthRoutes(app: FastifyInstance, opts: GuestAuthOptions): Promise<void> {
  const storage = opts.storage;
  const rateLimit = opts.rateLimit ?? { max: 50, timeWindow: '1 minute' };

  app.post('/auth/guest', {
    config: { rateLimit },
    schema: { body: nip98EventSchema },
  }, async (request, reply) => {
    const { event } = request.body as { event: Record<string, unknown> };

    // 1. Freshness — replay window
    const now = Math.floor(Date.now() / 1000);
    const eventAge = now - ((event.created_at as number) ?? 0);
    if (eventAge > MAX_EVENT_AGE_SECONDS || eventAge < -60) {
      return reply.status(400).send({
        error: { code: 'EVENT_TOO_OLD', message: `Event must be within ${MAX_EVENT_AGE_SECONDS}s of server time` },
      });
    }

    // 2. Kind 27235 (NIP-98) only — kind 1 is replayable social content
    if ((event.kind as number) !== 27235) {
      return reply.status(400).send({
        error: { code: 'INVALID_KIND', message: 'Event must be kind 27235 (NIP-98)' },
      });
    }

    // 3. u/method binding — prevents cross-endpoint replay
    if (!verifyNip98Binding(event as { tags: unknown[]; kind: number }, request.url.split('?')[0], 'POST')) {
      return reply.status(401).send({
        error: { code: 'INVALID_NIP98_BINDING', message: 'NIP-98 u/method tags do not match this endpoint' },
      });
    }

    // 4. Signature — proves key ownership. Verified BEFORE the single-use
    // challenge is consumed: an invalid event must not burn a valid challenge,
    // otherwise an attacker could DoS a victim's in-flight login by racing
    // with a garbage event that reuses the same challenge.
    let valid = false;
    try {
      valid = verifyEvent(event as Parameters<typeof verifyEvent>[0]);
    } catch {
      valid = false;
    }
    if (!valid) {
      return reply.status(401).send({
        error: { code: 'INVALID_SIGNATURE', message: 'Event signature verification failed' },
      });
    }

    // 5. Server challenge — prevents pre-signed replay (single use)
    const challengeResult = validateNip98Challenge(event as { tags?: unknown[] });
    if (!challengeResult.valid) {
      return reply.status(401).send({ error: { code: 'INVALID_CHALLENGE', message: challengeResult.error || 'Challenge validation failed' } });
    }

    const pubkey = event.pubkey as string;
    const token = `bao_sess_${randomBytes(32).toString('hex')}`;

    try {
      await storage.upsertAccount({
        pubkey,
        nsec_hash: createHash('sha256').update(`guest:${pubkey}`).digest('hex'),
        npub: nip19.npubEncode(pubkey),
        username: `Guest ${pubkey.slice(0, 8)}`,
        nostr_only_mode: 0,
        now,
      });
    } catch (err) {
      request.log.error({ err: err instanceof Error ? err.message : String(err) }, 'Guest auth: account init failed');
      return reply.status(500).send({ error: { code: 'ACCOUNT_ERROR', message: 'Failed to initialize guest account' } });
    }

    await storage.storeSession(token, pubkey, {
      userAgent: request.headers['user-agent'] || 'unknown',
      ipAddress: request.ip,
      expiresAt: now + GUEST_SESSION_TTL_SECONDS,
    });

    request.log.info({ pubkey: pubkey.slice(0, 16) }, 'Guest session issued');

    return reply.status(201).send({
      sessionToken: token,
      pubkey,
      expires_at: now + GUEST_SESSION_TTL_SECONDS,
      authMethod: 'guest',
    });
  });
}
