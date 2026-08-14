/**
 * nsecManager — In-memory hold/consume pattern for v2 "Show Once, Hash Irreversibly"
 *
 * The server stores only SHA-256(nsec_hex) in the database.
 * This Map holds plaintext nsec temporarily between account creation
 * and first-login delivery. After consume(), the entry is deleted.
 *
 * Lifecycle:
 *   1. Account created → holdNsec(identifier, nsecHex, nsecBech32)
 *   2. First login → consumeNsec(identifier) → returns nsec, deletes from memory
 *   3. Subsequent logins → consumeNsec returns null
 *
 * Safety:
 *   - Entries auto-expire after 30 minutes (server restart = entries lost)
 *   - Relay backup is the safety net (user can recover from relay)
 *   - Cleanup runs every 60 seconds
 */

import { createHash } from 'crypto';

interface PendingNsec {
  nsec_hex: string;
  nsec_bech32: string;
  created_at: number;
}

const NSEC_TTL_MS = 30 * 60 * 1000; // 30 minutes
const CLEANUP_INTERVAL_MS = 60 * 1000;  // 1 minute

const pendingNsecs = new Map<string, PendingNsec>();

/** Hold nsec in memory for first-login delivery. Key is method-specific identifier. */
export function holdNsec(identifier: string, nsecHex: string, nsecBech32: string): void {
  pendingNsecs.set(identifier, {
    nsec_hex: nsecHex,
    nsec_bech32: nsecBech32,
    created_at: Date.now(),
  });
}

/** Consume nsec from memory (one-shot). Returns null if not found or expired. */
export function consumeNsec(identifier: string): { nsec_hex: string; nsec_bech32: string } | null {
  const entry = pendingNsecs.get(identifier);
  if (!entry) return null;

  // Check TTL
  if (Date.now() - entry.created_at > NSEC_TTL_MS) {
    pendingNsecs.delete(identifier);
    return null;
  }

  pendingNsecs.delete(identifier);
  return entry;
}

/** Check if nsec is held for identifier (without consuming). */
export function hasNsec(identifier: string): boolean {
  return pendingNsecs.has(identifier);
}

/** Compute irreversible SHA-256 hash of nsec hex. */
export function computeNsecHash(nsecHex: string): string {
  return createHash('sha256').update(nsecHex).digest('hex');
}

// Periodic cleanup of stale entries
const cleanupTimer = setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of pendingNsecs) {
    if (now - entry.created_at > NSEC_TTL_MS) {
      pendingNsecs.delete(key);
    }
  }
}, CLEANUP_INTERVAL_MS);

// Prevent the timer from keeping the process alive
if (cleanupTimer.unref) {
  cleanupTimer.unref();
}
