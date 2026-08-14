/**
 * Nostr Auth — NIP-98 (kind 27235) signed-event login for existing keypairs.
 *
 * Same verification pipeline as guest auth, but issues a long-lived session
 * (30 days) and marks the account nostr-only.
 */

import type { FastifyInstance } from 'fastify';
import { verifyEvent, nip19 } from 'nostr-tools';
import { createHash, randomBytes } from 'crypto';
import { verifyNip98Binding, validateNip98Challenge } from './nip98.ts';
import type { SignerStorage } from './storage.ts';

const NOSTR_SESSION_TTL_SECONDS = 30 * 24 * 60 * 60; // 30 days
const MAX_EVENT_AGE_SECONDS = 5 * 60;

export interface NostrAuthOptions {
  storage: SignerStorage;
  rateLimit?: { max: number; timeWindow: string };
}

export async function nostrAuthRoutes(app: FastifyInstance, opts: NostrAuthOptions): Promise<void> {
  const storage = opts.storage;

  app.post('/auth/nostr', {
    config: { rateLimit: opts.rateLimit ?? { max: 50, timeWindow: '1 minute' } },
    schema: {
      body: {
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
      },
    },
  }, async (request, reply) => {
    const { event } = request.body as { event: Record<string, unknown> };

    const now = Math.floor(Date.now() / 1000);
    const eventAge = now - ((event.created_at as number) ?? 0);
    if (eventAge > MAX_EVENT_AGE_SECONDS || eventAge < -60) {
      return reply.status(400).send({ error: { code: 'EVENT_TOO_OLD', message: 'Event too old' } });
    }

    if ((event.kind as number) !== 27235) {
      return reply.status(400).send({ error: { code: 'INVALID_KIND', message: 'Event must be kind 27235 (NIP-98)' } });
    }

    if (!verifyNip98Binding(event as { tags: unknown[]; kind: number }, request.url.split('?')[0], 'POST')) {
      return reply.status(401).send({ error: { code: 'INVALID_NIP98_BINDING', message: 'NIP-98 u/method tags do not match this endpoint' } });
    }

    const challengeResult = validateNip98Challenge(event as { tags?: unknown[] });
    if (!challengeResult.valid) {
      return reply.status(401).send({ error: { code: 'INVALID_CHALLENGE', message: challengeResult.error || 'Challenge validation failed' } });
    }

    let valid = false;
    try {
      valid = verifyEvent(event as Parameters<typeof verifyEvent>[0]);
    } catch {
      valid = false;
    }
    if (!valid) {
      return reply.status(401).send({ error: { code: 'INVALID_SIGNATURE', message: 'Signature verification failed' } });
    }

    const pubkey = event.pubkey as string;
    const token = `bao_sess_${randomBytes(32).toString('hex')}`;

    try {
      const existing = await storage.getAccount(pubkey);
      if (!existing) {
        await storage.upsertAccount({
          pubkey,
          nsec_hash: createHash('sha256').update(`nostr:${pubkey}`).digest('hex'),
          npub: nip19.npubEncode(pubkey),
          username: `Nostr ${pubkey.slice(0, 8)}`,
          nostr_only_mode: 1,
          now,
        });
      }

      await storage.storeSession(token, pubkey, {
        userAgent: request.headers['user-agent'] || 'unknown',
        ipAddress: request.ip,
        expiresAt: now + NOSTR_SESSION_TTL_SECONDS,
      });

      return reply.status(201).send({
        sessionToken: token,
        pubkey,
        expires_at: now + NOSTR_SESSION_TTL_SECONDS,
      });
    } catch (err) {
      request.log.error({ err: err instanceof Error ? err.message : String(err) }, 'Nostr auth failed');
      return reply.status(500).send({ error: { code: 'AUTH_ERROR', message: 'Internal error' } });
    }
  });
}
