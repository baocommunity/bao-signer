/**
 * Email Auth — OTP code login + account registration.
 *
 * Endpoints:
 * - POST /auth/email/request  — Send a 6-digit OTP code (always { sent: true })
 * - POST /auth/email/verify   — Verify OTP, return session (+ nsec once for new accounts)
 * - POST /auth/email/register — Link an existing Nostr key to an email
 *
 * Secrets policy: NO credentials live here. The email sender and the
 * at-rest nsec encryption key are injected by the host app.
 */

import type { FastifyInstance } from 'fastify';
import { createHash, createHmac, randomBytes, randomInt, pbkdf2Sync, createCipheriv } from 'crypto';
import { generateSecretKey, getPublicKey, nip19 } from 'nostr-tools';
import { bytesToHex } from '@noble/hashes/utils.js';
import { holdNsec, consumeNsec, computeNsecHash } from './nsecManager.ts';
import type { SignerStorage } from './storage.ts';

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const OTP_TTL_SECONDS = 10 * 60;
const RATE_LIMIT_PER_HOUR = 5;
const MIN_SESSION_TTL_SECONDS = 3600;

function hashEmail(email: string): string {
  return createHash('sha256').update(email).digest('hex');
}

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

function generateOtp(): string {
  return randomInt(0, 1_000_000).toString().padStart(6, '0');
}

/** Encrypt an nsec for at-rest backup. PBKDF2(host key, salt) → AES-256-GCM. */
function encryptNsec(nsec: string, encryptionKey: string): { ciphertext: string; salt: string; iv: string } {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = pbkdf2Sync(encryptionKey, salt, 100_000, 32, 'sha256');
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(nsec, 'utf8'), cipher.final(), cipher.getAuthTag()]);
  return {
    ciphertext: ciphertext.toString('base64'),
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
  };
}

export interface EmailAuthOptions {
  storage: SignerStorage;
  /**
   * Deliver the OTP to the user. REQUIRED — this is where your SMTP/API
   * credentials live (injected by the host, never stored in this module).
   * Throwing is safe: the OTP is already stored hashed, so the user can
   * still enter it when the email eventually arrives.
   */
  sendEmail: (to: string, code: string) => Promise<void>;
  /** HMAC secret for relay backup keys. REQUIRED (fail closed). */
  backupSecret: string;
  /** Optional key for at-rest encrypted nsec backup. Omit to disable backup storage. */
  nsecEncryptionKey?: string;
  /** Optional hook after a new account is created (e.g. publish a relay backup). */
  onNewAccount?: (info: { pubkey: string; nsecHex: string; emailHash: string }) => Promise<void>;
  sessionTtlSeconds?: number;
  rateLimit?: { max: number; timeWindow: string };
  /** Dev only: log OTP codes (masked) so flows can be tested without email. */
  logOtpCodes?: boolean;
}

export async function emailAuthRoutes(app: FastifyInstance, opts: EmailAuthOptions): Promise<void> {
  if (!opts.sendEmail) throw new Error('emailAuthRoutes: sendEmail hook is required');
  if (!opts.backupSecret) throw new Error('emailAuthRoutes: backupSecret is required (fail closed)');

  const storage = opts.storage;
  const rateLimit = opts.rateLimit ?? { max: 50, timeWindow: '1 minute' };
  const ttl = Math.max(opts.sessionTtlSeconds ?? 86400, MIN_SESSION_TTL_SECONDS);

  const relayBackupKeyFor = (email: string): string =>
    createHmac('sha256', opts.backupSecret).update(`email:${email}`).digest('hex').slice(0, 32);

  // ---------------------------------------------------------------
  // POST /auth/email/request
  // ---------------------------------------------------------------
  app.post('/auth/email/request', {
    config: { rateLimit },
    schema: {
      body: {
        type: 'object',
        required: ['email'],
        properties: { email: { type: 'string', maxLength: 254 } },
      },
    },
  }, async (request, reply) => {
    const { email: rawEmail } = request.body as { email?: string };
    if (!rawEmail) return reply.status(400).send({ error: 'email required' });

    const email = rawEmail.toLowerCase().trim();
    if (!EMAIL_RE.test(email)) return reply.status(400).send({ error: 'Invalid email address' });

    const now = Math.floor(Date.now() / 1000);
    const emailHash = hashEmail(email);

    const recentCount = await storage.emailCountRecentOtps(emailHash, now - 3600);
    if (recentCount >= RATE_LIMIT_PER_HOUR) {
      return reply.status(429).send({ error: 'Too many login attempts. Please try again later.' });
    }

    // Auto-create account if the email is new
    const existing = await storage.emailGetAccount(emailHash);
    if (!existing) {
      const secretKeyBytes = generateSecretKey();
      const pubkey = getPublicKey(secretKeyBytes);
      const nsecHex = bytesToHex(secretKeyBytes);
      const nsec = nip19.nsecEncode(secretKeyBytes);
      const username = 'user_' + randomBytes(4).toString('hex');

      const inserted = await storage.emailInsertAccount({ email_hash: emailHash, pubkey, username });
      if (inserted) {
        await storage.insertAccount({ pubkey, nsec_hash: computeNsecHash(nsecHex), username, now });
        await storage.insertAuthMethod({ method: 'email', authId: emailHash, pubkey, now });
        holdNsec(emailHash, nsecHex, nsec);

        // At-rest encrypted backup (optional; only when a key is configured)
        if (opts.nsecEncryptionKey) {
          try {
            const { ciphertext, salt, iv } = encryptNsec(nsec, opts.nsecEncryptionKey);
            await storage.emailUpdateEncryptedNsec(emailHash, ciphertext, salt, iv);
          } catch (err) {
            request.log.warn({ err: err instanceof Error ? err.message : String(err) }, 'nsec backup encryption failed');
          }
        }

        if (opts.onNewAccount) {
          opts.onNewAccount({ pubkey, nsecHex, emailHash }).catch((err) => {
            request.log.warn({ err: err instanceof Error ? err.message : String(err) }, 'onNewAccount hook failed (non-blocking)');
          });
        }

        request.log.info({ email_hash: emailHash, pubkey: pubkey.slice(0, 8) }, 'New email account auto-created');
      }
    }

    const code = generateOtp();
    await storage.emailInsertOtp(hashToken(code), emailHash, now + OTP_TTL_SECONDS);

    if (opts.logOtpCodes) {
      request.log.info({ email_hash: emailHash, otp_masked: code.slice(0, 3) + '***' }, 'OTP code generated (masked)');
    }

    // Fire-and-forget: respond immediately; the hashed OTP is already stored.
    opts.sendEmail(email, code).catch((err) => {
      request.log.error({ err: err instanceof Error ? err.message : String(err), email_hash: emailHash }, 'Failed to send OTP email');
    });

    // Always { sent: true } — prevents email enumeration
    return reply.send({ sent: true });
  });

  // ---------------------------------------------------------------
  // POST /auth/email/verify
  // ---------------------------------------------------------------
  app.post('/auth/email/verify', {
    config: { rateLimit },
    schema: {
      body: {
        type: 'object',
        required: ['email', 'code'],
        properties: {
          email: { type: 'string', maxLength: 254 },
          code: { type: 'string', maxLength: 32 },
        },
      },
    },
  }, async (request, reply) => {
    const { email: rawEmail, code } = request.body as { email?: string; code?: string };
    if (!rawEmail || !code) return reply.status(400).send({ error: 'email and code are required' });

    const email = rawEmail.toLowerCase().trim();
    if (!/^\d{6}$/.test(code)) return reply.status(400).send({ error: 'Invalid code format' });

    const now = Math.floor(Date.now() / 1000);
    const emailHash = hashEmail(email);

    const tokenRow = await storage.emailGetValidOtp(hashToken(code), emailHash, now);
    if (!tokenRow) return reply.status(401).send({ error: 'Invalid or expired code' });

    await storage.emailMarkOtpUsed(hashToken(code));

    const account = await storage.emailGetAccount(tokenRow.email_hash);
    if (!account) {
      request.log.error({ email_hash: tokenRow.email_hash }, 'Account not found for valid OTP');
      return reply.status(500).send({ error: { code: 'ACCOUNT_NOT_FOUND', message: 'Account not found' } });
    }

    const nsecData = consumeNsec(emailHash);
    const sessionToken = `bao_sess_${randomBytes(32).toString('hex')}`;
    await storage.storeSession(sessionToken, account.pubkey, {
      userAgent: request.headers['user-agent'] || '',
      ipAddress: request.ip,
      expiresAt: now + ttl,
    });

    const methods = await storage.getAuthMethodsForPubkey(account.pubkey);

    return reply.send({
      session: {
        pubkey: account.pubkey,
        npub: nip19.npubEncode(account.pubkey),
        nsec: nsecData?.nsec_bech32 ?? null,
        username: account.username,
        firstLogin: nsecData !== null,
        isNewAccount: false,
        authMethod: 'email',
        linkedMethods: methods.map((m) => m.method),
        relayBackupKey: relayBackupKeyFor(email),
        sessionToken,
        expires_at: now + ttl,
      },
    });
  });

  // ---------------------------------------------------------------
  // POST /auth/email/register — link an existing key to an email
  // ---------------------------------------------------------------
  app.post('/auth/email/register', {
    config: { rateLimit },
    schema: {
      body: {
        type: 'object',
        required: ['email', 'nsec', 'username'],
        properties: {
          email: { type: 'string', maxLength: 254 },
          nsec: { type: 'string', maxLength: 128 },
          username: { type: 'string', maxLength: 64 },
        },
      },
    },
  }, async (request, reply) => {
    const { email: rawEmail, nsec, username } = request.body as {
      email?: string;
      nsec?: string;
      username?: string;
    };
    if (!rawEmail || !nsec || !username) {
      return reply.status(400).send({ error: 'email, nsec, and username are required' });
    }

    const email = rawEmail.toLowerCase().trim();
    if (!EMAIL_RE.test(email)) return reply.status(400).send({ error: 'Invalid email address' });

    let decoded: { type: string; data: Uint8Array };
    try {
      decoded = nip19.decode(nsec) as { type: string; data: Uint8Array };
    } catch {
      return reply.status(400).send({ error: 'Invalid nsec key' });
    }
    if (decoded.type !== 'nsec') return reply.status(400).send({ error: 'Expected nsec key' });

    const pubkey = getPublicKey(decoded.data);
    const emailHash = hashEmail(email);

    const existing = await storage.emailGetAccount(emailHash);
    if (existing) {
      if (existing.pubkey === pubkey) {
        return reply.send({ registered: true, pubkey }); // idempotent
      }
      return reply.status(409).send({ error: 'Email already registered with a different key' });
    }

    let encrypted: { ciphertext: string; salt: string; iv: string } | undefined;
    if (opts.nsecEncryptionKey) {
      encrypted = encryptNsec(nsec, opts.nsecEncryptionKey);
    }

    await storage.emailInsertAccount({
      email_hash: emailHash,
      pubkey,
      username,
      encrypted_nsec: encrypted?.ciphertext,
      nsec_salt: encrypted?.salt,
      nsec_iv: encrypted?.iv,
    });

    request.log.info({ email_hash: emailHash, pubkey: pubkey.slice(0, 8) }, 'Email account registered with existing key');
    return reply.send({ registered: true, pubkey });
  });
}
