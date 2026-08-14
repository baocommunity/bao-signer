/**
 * WebAuthn challenge store — in-memory with TTL
 *
 * Stores registration and login challenges between the options and verify steps.
 * Challenges are short-lived (5 min) and auto-cleaned.
 */

interface StoredChallenge {
  challenge: string;
  userHandle?: string;
  username?: string;
  linkingPubkey?: string;
  created_at: number;
}

const CHALLENGE_TTL_MS = 5 * 60 * 1000;
const CLEANUP_INTERVAL_MS = 60 * 1000;

const challenges = new Map<string, StoredChallenge>();

export function storeChallenge(
  challengeId: string,
  challenge: string,
  extra?: { userHandle?: string; username?: string; linkingPubkey?: string },
): void {
  challenges.set(challengeId, {
    challenge,
    userHandle: extra?.userHandle,
    username: extra?.username,
    linkingPubkey: extra?.linkingPubkey,
    created_at: Date.now(),
  });
}

export function consumeChallenge(challengeId: string): StoredChallenge | null {
  const entry = challenges.get(challengeId);
  if (!entry) return null;
  if (Date.now() - entry.created_at > CHALLENGE_TTL_MS) {
    challenges.delete(challengeId);
    return null;
  }
  challenges.delete(challengeId);
  return entry;
}
const timer = setInterval(() => {
  try {
    const now = Date.now();
    for (const [key, entry] of challenges) {
      if (now - entry.created_at > CHALLENGE_TTL_MS) {
        challenges.delete(key);
      }
    }
  } catch {
    /* ignore cleanup errors */
  }
}, CLEANUP_INTERVAL_MS);
if (timer.unref) timer.unref();
