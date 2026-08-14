/**
 * NIP-98 auth machinery — server-side challenge store + event binding checks.
 *
 * - GET /auth/challenge issues a single-use, 5-minute server nonce.
 * - Auth events (kind 27235) must carry tags:
 *     ["u", <endpoint URL>], ["method", "POST"], ["challenge", <nonce>]
 * - `verifyNip98Binding` prevents replaying an event across endpoints.
 * - `validateNip98Challenge` prevents replaying an event across time.
 */

import type { FastifyInstance } from 'fastify';
import { randomBytes } from 'crypto';

const CHALLENGE_TTL_MS = 5 * 60 * 1000;

// challenge → expiry timestamp (ms)
const challenges = new Map<string, number>();

function cleanupExpiredChallenges(): void {
  const now = Date.now();
  for (const [challenge, expiry] of challenges) {
    if (expiry < now) challenges.delete(challenge);
  }
}

export function generateNip98Challenge(): string {
  cleanupExpiredChallenges();
  const challenge = randomBytes(32).toString('hex');
  challenges.set(challenge, Date.now() + CHALLENGE_TTL_MS);
  return challenge;
}

/** Single-use validation — consumes the challenge. */
export function validateNip98Challenge(event: { tags?: unknown[] }): { valid: boolean; error?: string } {
  cleanupExpiredChallenges();
  if (!Array.isArray(event.tags)) {
    return { valid: false, error: 'Missing tags' };
  }
  const challengeTag = event.tags.find((t: unknown) => Array.isArray(t) && t[0] === 'challenge');
  const challenge = (challengeTag as string[] | undefined)?.[1];
  if (!challenge || typeof challenge !== 'string') {
    return { valid: false, error: 'Missing challenge tag' };
  }
  if (!challenges.has(challenge)) {
    return { valid: false, error: 'Invalid or expired challenge' };
  }
  challenges.delete(challenge); // single use
  return { valid: true };
}

/**
 * Verify the event's u/method tags match the endpoint being called.
 * Compares paths only (host-agnostic), tolerating an optional API-prefix.
 */
export function verifyNip98Binding(
  event: { tags: unknown[]; kind: number },
  requestUrl: string,
  requestMethod: string,
): boolean {
  if (event.kind !== 27235) return false;

  const uTag = event.tags.find(
    (t: unknown) => Array.isArray(t) && t[0] === 'u',
  ) as string[] | undefined;
  const methodTag = event.tags.find(
    (t: unknown) => Array.isArray(t) && t[0] === 'method',
  ) as string[] | undefined;

  const normalizePath = (p: string): string => {
    return p.replace(/^\/bao-api/, '').replace(/\/$/, '') || '/';
  };

  let urlMatch = false;
  const uValue = uTag?.[1];
  if (uValue) {
    try {
      const uPath = normalizePath(new URL(uValue).pathname);
      const reqPath = normalizePath(requestUrl);
      urlMatch = reqPath === uPath;
    } catch {
      urlMatch = normalizePath(requestUrl) === normalizePath(uValue);
    }
  }

  const methodMatch =
    !!methodTag?.[1] && methodTag[1].toUpperCase() === requestMethod.toUpperCase();

  return urlMatch && methodMatch;
}

/** Register GET /auth/challenge. */
export async function nip98ChallengeRoutes(
  app: FastifyInstance,
  opts: { rateLimit?: { max: number; timeWindow: string } } = {},
): Promise<void> {
  app.get('/auth/challenge', {
    config: { rateLimit: opts.rateLimit ?? { max: 50, timeWindow: '1 minute' } },
  }, async (_request, reply) => {
    return reply.send({ challenge: generateNip98Challenge() });
  });
}
