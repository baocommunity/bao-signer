/**
 * bao-signer server — WebAuthn passkey registration + login routes.
 *
 * Endpoints (relative to the registered prefix):
 * - POST /auth/passkey/register-options — Generate registration challenge
 * - POST /auth/passkey/register          — Verify attestation, create account
 * - POST /auth/passkey/login-options     — Generate login challenge
 * - POST /auth/passkey/login             — Verify assertion, return session
 * - POST /auth/link/passkey/options      — Registration options for linking (authed)
 * - POST /auth/link/passkey/register     — Complete passkey linking (authed)
 *
 * Architecture: v2 "Show Once, Hash Irreversibly"
 * - Server-generated accounts: the nsec is shown once at registration and only
 *   its SHA-256 hash is stored.
 * - PRF-derived accounts: the server never sees the nsec at all.
 *
 * SECURITY POLICY — anonymous PRF registration is REJECTED
 * (`PRF_ACCOUNT_LINK_REQUIRES_AUTH`): a WebAuthn attestation proves control of
 * the new credential, NOT control of a caller-supplied Nostr pubkey. Allowing
 * anonymous registration with a client-chosen pubkey lets anyone attach their
 * passkey to an existing public identity. PRF-backed identities are added via
 * the authenticated link endpoints, where the challenge is bound to the
 * current session pubkey.
 */

import type { FastifyInstance, FastifyRequest } from 'fastify';
import { randomBytes, createHash } from 'crypto';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import type {
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
} from '@simplewebauthn/server';
import { generateSecretKey, getPublicKey, nip19 } from 'nostr-tools';
import { bytesToHex } from '@noble/hashes/utils.js';
import { holdNsec, consumeNsec, computeNsecHash } from './nsecManager.ts';
import { storeChallenge, consumeChallenge } from './webauthnChallenges.ts';
import { deriveRelayBackupKey } from './relayBackupKey.ts';
import type { SignerStorage } from './storage.ts';

export interface BaoSignerServerOptions {
  /** Persistence implementation (see storage.ts). */
  storage: SignerStorage;
  /** WebAuthn relying party ID, e.g. "example.com" (no protocol/port). */
  rpId: string;
  /** Allowed origins, e.g. ["https://example.com"]. */
  expectedOrigins: string[];
  /**
   * HMAC secret for relay backup keys. REQUIRED — the server fails closed
   * without it. Load from your secret manager (Vault, KMS, env-injected at
   * boot), never hardcode.
   */
  backupSecret: string;
  /** RP display name. Default "BAO Signer". */
  rpName?: string;
  /** Session TTL in seconds. Default 86400 (24h). */
  sessionTtlSeconds?: number;
  /** Rate limit applied to all auth endpoints. Default 50/min. */
  rateLimit?: { max: number; timeWindow: string };
  /**
   * Required to enable the /auth/link/passkey/* endpoints: resolve the
   * request's session to an account pubkey (return null when unauthenticated).
   * Typically: read the Bearer token, look it up in your session store.
   */
  authenticate?: (request: FastifyRequest) => Promise<string | null>;
  /**
   * When false, the server will NEVER generate a Nostr key on a user's
   * behalf. Anonymous `/auth/passkey/register` (the only server-key-minting
   * path here) is rejected; passkeys can only be attached to an existing
   * self-custodial account via the authenticated link endpoints. Default true
   * for backward compatibility.
   */
  allowServerKeyGeneration?: boolean;
}

function generateChallengeId(): string {
  return randomBytes(32).toString('hex');
}

function generateSessionToken(): string {
  return randomBytes(32).toString('base64url');
}

/**
 * A client-supplied pubkey at anonymous registration is a claim, not proof.
 * PRF identities must be linked via the authenticated flow.
 */
export function untrustedPasskeyRegistrationError(clientPubkey?: string): string | null {
  return clientPubkey ? 'PRF_ACCOUNT_LINK_REQUIRES_AUTH' : null;
}

export async function baoSignerAuthRoutes(
  app: FastifyInstance,
  opts: BaoSignerServerOptions,
): Promise<void> {
  if (!opts.rpId) throw new Error('baoSignerAuthRoutes: rpId is required');
  if (!opts.expectedOrigins?.length) throw new Error('baoSignerAuthRoutes: expectedOrigins is required');
  if (!opts.backupSecret) {
    throw new Error('baoSignerAuthRoutes: backupSecret is required (fail closed)');
  }

  const storage = opts.storage;
  const RP_NAME = opts.rpName ?? 'BAO Signer';
  const RP_ID = opts.rpId;
  const EXPECTED_ORIGINS = opts.expectedOrigins;
  const rateLimit = opts.rateLimit ?? { max: 50, timeWindow: '1 minute' };
  const ttl = opts.sessionTtlSeconds ?? 86400;
  const allowMint = opts.allowServerKeyGeneration ?? true;

  const errorMeta = (request: FastifyRequest) => ({
    request_id: request.id,
    timestamp: Math.floor(Date.now() / 1000),
  });

  // ------------------------------------------------------------------
  // POST /auth/passkey/register-options
  // ------------------------------------------------------------------
  app.post('/auth/passkey/register-options', {
    config: { rateLimit },
    schema: {
      body: {
        type: 'object',
        properties: {
          username: { type: 'string', maxLength: 64 },
        },
      },
    },
  }, async (request, reply) => {
    const { username } = (request.body as { username?: string }) || {};
    const displayName = username?.trim() || 'bao_user';

    const challengeId = generateChallengeId();
    const userHandle = randomBytes(16);

    const options = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: RP_ID,
      userName: displayName,
      userDisplayName: displayName,
      userID: userHandle,
      attestationType: 'none',
      authenticatorSelection: {
        // UV=required ensures ownership proof (PIN/biometric), not just
        // possession (tap). Critical for real-money auth.
        userVerification: 'required',
        residentKey: 'required',
      },
    });
    storeChallenge(challengeId, options.challenge, {
      userHandle: Buffer.from(userHandle).toString('base64url'),
      username: displayName,
    });

    return reply.send({ challengeId, options });
  });

  // ------------------------------------------------------------------
  // POST /auth/passkey/register
  // ------------------------------------------------------------------
  app.post('/auth/passkey/register', {
    config: { rateLimit },
    schema: {
      body: {
        type: 'object',
        required: ['challengeId', 'credential'],
        properties: {
          challengeId: { type: 'string', maxLength: 128 },
          credential: {
            type: 'object',
            maxProperties: 10,
            properties: {
              id: { type: 'string', maxLength: 1024 },
              rawId: { type: 'string', maxLength: 2048 },
              type: { type: 'string', maxLength: 32 },
              response: { type: 'object', maxProperties: 10 },
              clientExtensionResults: { type: 'object', maxProperties: 10 },
            },
          },
          username: { type: 'string', maxLength: 64 },
          pubkey: { type: 'string', pattern: '^[0-9a-f]{64}$' },
        },
      },
    },
  }, async (request, reply) => {
    const { challengeId, credential, username, pubkey: clientPubkey } = request.body as {
      challengeId: string;
      credential: RegistrationResponseJSON;
      username?: string;
      pubkey?: string;
    };

    const challenge = consumeChallenge(challengeId);
    if (!challenge) {
      return reply.status(400).send({
        error: { code: 'PASSKEY_CHALLENGE_NOT_FOUND', message: 'Challenge not found or expired' },
        meta: errorMeta(request),
      });
    }

    let verification;
    try {
      verification = await verifyRegistrationResponse({
        response: credential,
        expectedChallenge: challenge.challenge,
        expectedOrigin: EXPECTED_ORIGINS,
        expectedRPID: RP_ID,
      });
    } catch (err) {
      request.log.warn({ err: err instanceof Error ? err.message : String(err), credentialId: credential.id }, 'Passkey registration verification failed');
      return reply.status(400).send({
        error: { code: 'PASSKEY_REGISTRATION_FAILED', message: 'Attestation verification failed' },
        meta: errorMeta(request),
      });
    }

    if (!verification.verified || !verification.registrationInfo) {
      return reply.status(400).send({
        error: { code: 'PASSKEY_REGISTRATION_FAILED', message: 'Verification failed' },
        meta: errorMeta(request),
      });
    }

    const { credential: webauthnCred } = verification.registrationInfo;
    const credentialId = webauthnCred.id;
    const publicKeyB64 = Buffer.from(webauthnCred.publicKey).toString('base64url');
    const counter = webauthnCred.counter;

    const now = Math.floor(Date.now() / 1000);
    const existing = await storage.getCredentialById(credentialId);
    if (existing) {
      return reply.status(400).send({
        error: { code: 'PASSKEY_ALREADY_REGISTERED', message: 'This passkey is already registered' },
        meta: errorMeta(request),
      });
    }

    // A WebAuthn attestation proves control of the new credential, not control
    // of a caller-supplied Nostr pubkey. Binding the two here allowed anyone to
    // attach their passkey to an existing user's public identity. PRF-backed
    // identities must be added through the authenticated account-link flow,
    // where the challenge is bound to the current session pubkey.
    const registrationError = untrustedPasskeyRegistrationError(clientPubkey);
    if (registrationError) {
      return reply.status(400).send({
        error: {
          code: registrationError,
          message: 'A client-derived Nostr identity can only be linked from an authenticated account.',
        },
        meta: errorMeta(request),
      });
    }

    // Self-custody mode: anonymous registration can only produce a
    // server-generated key, which is exactly what we must not do. Direct users
    // to a seed/passkey-derived identity and the authenticated link flow.
    if (!allowMint) {
      return reply.status(403).send({
        error: {
          code: 'ACCOUNT_CREATION_DISABLED',
          message: 'Server-side key generation is disabled. Create a self-custodial identity (seed phrase) and link this passkey from the authenticated account.',
        },
        meta: errorMeta(request),
      });
    }

    // Server-generated identity ("show once, hash irreversibly").
    const nsecBytes = generateSecretKey();
    const nsecHex = bytesToHex(nsecBytes);
    const pubkeyHex = getPublicKey(nsecBytes);
    const nsecHash = computeNsecHash(nsecHex);
    const nsecBech32 = nip19.nsecEncode(nsecBytes);

    const displayName = username?.trim() || challenge.username || 'bao_user';

    await storage.withTransaction(async () => {
      await storage.insertAccount({ pubkey: pubkeyHex, nsec_hash: nsecHash, username: displayName, now });
      await storage.insertAuthMethod({ method: 'passkey', authId: credentialId, pubkey: pubkeyHex, now });
      await storage.insertCredential({
        credential_id: credentialId,
        pubkey: pubkeyHex,
        public_key: publicKeyB64,
        counter,
        transports: JSON.stringify(webauthnCred.transports ?? []),
        name: displayName,
        now,
        is_prf: 0,
      });
      await storage.touchAuthMethod('passkey', credentialId, now);
    });

    // holdNsec is in-memory; multi-server deployments need a shared store for durability.
    holdNsec(credentialId, nsecHex, nsecBech32);

    const sessionToken = generateSessionToken();
    await storage.storeSession(sessionToken, pubkeyHex, {
      userAgent: request.headers['user-agent'] || '',
      ipAddress: request.ip,
      expiresAt: now + ttl,
    });
    const relayBackupKey = deriveRelayBackupKey(credentialId, opts.backupSecret);
    const nsecData = consumeNsec(credentialId);

    return reply.send({
      session: {
        pubkey: pubkeyHex,
        npub: nip19.npubEncode(pubkeyHex),
        nsec: nsecData?.nsec_bech32 ?? null,
        username: displayName,
        firstLogin: true,
        isNewAccount: true,
        authMethod: 'passkey',
        linkedMethods: ['passkey'],
        relayBackupKey,
        sessionToken,
        expires_at: now + ttl,
      },
    });
  });

  // ------------------------------------------------------------------
  // POST /auth/passkey/login-options
  // ------------------------------------------------------------------
  app.post('/auth/passkey/login-options', {
    config: { rateLimit },
    schema: {
    },
  }, async (_request, reply) => {
    // All passkey logins demand user verification (PIN/biometric).
    const challengeId = generateChallengeId();
    const options = await generateAuthenticationOptions({
      rpID: RP_ID,
      userVerification: 'required',
    });
    storeChallenge(challengeId, options.challenge);

    return reply.send({ challengeId, options });
  });

  // ------------------------------------------------------------------
  // POST /auth/passkey/login
  // ------------------------------------------------------------------
  app.post('/auth/passkey/login', {
    config: { rateLimit },
    schema: {
      body: {
        type: 'object',
        required: ['challengeId', 'credential'],
        properties: {
          challengeId: { type: 'string', maxLength: 128 },
          credential: {
            type: 'object',
            maxProperties: 10,
            properties: {
              id: { type: 'string', maxLength: 1024 },
              rawId: { type: 'string', maxLength: 2048 },
              type: { type: 'string', maxLength: 32 },
              response: { type: 'object', maxProperties: 10 },
              clientExtensionResults: { type: 'object', maxProperties: 10 },
            },
          },
          pubkey: { type: 'string', pattern: '^[0-9a-f]{64}$' },
        },
      },
    },
  }, async (request, reply) => {
    const { challengeId, credential, pubkey: clientPubkey } = request.body as {
      challengeId: string;
      credential: AuthenticationResponseJSON;
      pubkey?: string;
    };

    const challenge = consumeChallenge(challengeId);
    if (!challenge) {
      return reply.status(400).send({
        error: { code: 'PASSKEY_CHALLENGE_NOT_FOUND', message: 'Challenge not found or expired' },
        meta: errorMeta(request),
      });
    }

    const cred = await storage.getCredentialById(credential.id);
    if (!cred) {
      return reply.status(400).send({
        error: { code: 'PASSKEY_NOT_FOUND', message: 'Passkey not registered' },
        meta: errorMeta(request),
      });
    }
    if (!clientPubkey || clientPubkey !== cred.pubkey) {
      return reply.status(400).send({
        error: { code: 'PUBKEY_MISMATCH', message: 'Provided pubkey does not match credential' },
        meta: errorMeta(request),
      });
    }
    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response: credential,
        expectedChallenge: challenge.challenge,
        expectedOrigin: EXPECTED_ORIGINS,
        expectedRPID: RP_ID,
        credential: {
          id: cred.credential_id,
          publicKey: Buffer.from(cred.public_key, 'base64url'),
          counter: cred.counter,
          transports: JSON.parse(cred.transports || '[]'),
        },
      });
    } catch (err) {
      request.log.warn({ err: err instanceof Error ? err.message : String(err), credentialId: credential.id }, 'Passkey verification failed');
      return reply.status(400).send({
        error: { code: 'PASSKEY_LOGIN_FAILED', message: 'Assertion verification failed' },
        meta: errorMeta(request),
      });
    }
    if (!verification.verified) {
      return reply.status(400).send({
        error: { code: 'PASSKEY_LOGIN_FAILED', message: 'Verification failed' },
        meta: errorMeta(request),
      });
    }
    const newCounter = verification.authenticationInfo.newCounter;
    const now = Math.floor(Date.now() / 1000);

    const account = await storage.getAccount(cred.pubkey);
    if (!account) {
      return reply.status(400).send({
        error: { code: 'ACCOUNT_NOT_FOUND', message: 'Account not found' },
        meta: errorMeta(request),
      });
    }

    if (newCounter < cred.counter) {
      request.log.warn({
        credential_id: cred.credential_id,
        stored_counter: cred.counter,
        new_counter: newCounter,
      }, 'WebAuthn counter regression (likely synced passkey) -- tolerating');
      // Keep the higher counter; do NOT update to lower value
    } else {
      await storage.updateCredentialCounter(cred.credential_id, newCounter, now);
    }
    await storage.touchAuthMethod('passkey', cred.credential_id, now);
    await storage.updateAccountLastLogin(cred.pubkey, now);

    const sessionToken = generateSessionToken();
    const expiresAt = now + ttl;
    await storage.storeSession(sessionToken, cred.pubkey, {
      userAgent: request.headers['user-agent'] || '',
      ipAddress: request.ip,
      expiresAt,
    });
    const methods = await storage.getAuthMethodsForPubkey(cred.pubkey);
    const isPrf = cred.is_prf === 1;
    // PRF credentials: the client already holds the nsec derived from the
    // authenticator's PRF output, so the server has nothing to deliver.
    const nsecData = isPrf ? null : consumeNsec(cred.credential_id);
    const relayBackupKey = deriveRelayBackupKey(cred.credential_id, opts.backupSecret);
    return reply.send({
      session: {
        pubkey: account.pubkey,
        npub: nip19.npubEncode(account.pubkey),
        ...(isPrf ? {} : { nsec: nsecData?.nsec_bech32 ?? null }),
        username: account.username,
        firstLogin: !isPrf && nsecData !== null,
        isNewAccount: false,
        authMethod: 'passkey',
        linkedMethods: methods.map((m) => m.method),
        relayBackupKey,
        sessionToken,
        expires_at: expiresAt,
      },
    });
  });

  // ------------------------------------------------------------------
  // POST /auth/link/passkey/options — registration options for linking
  // ------------------------------------------------------------------
  if (opts.authenticate) {
    const authenticate = opts.authenticate;

    app.post('/auth/link/passkey/options', {
      config: { rateLimit },
      schema: {
      },
    }, async (request, reply) => {
      const pubkey = await authenticate(request);
      if (!pubkey) {
        return reply.status(401).send({
          error: { code: 'UNAUTHORIZED', message: 'Valid session token required' },
          meta: errorMeta(request),
        });
      }

      const challengeId = generateChallengeId();
      const userHandle = randomBytes(16);
      const username = `linked_${pubkey.slice(0, 8)}`;

      const options = await generateRegistrationOptions({
        rpName: RP_NAME,
        rpID: RP_ID,
        userName: username,
        userDisplayName: username,
        userID: userHandle,
        attestationType: 'none',
        authenticatorSelection: {
          userVerification: 'required',
          residentKey: 'preferred',
        },
      });

      storeChallenge(challengeId, options.challenge, {
        userHandle: Buffer.from(userHandle).toString('base64url'),
        username,
        linkingPubkey: pubkey,
      });

      return reply.send({ challengeId, options });
    });

    // ----------------------------------------------------------------
    // POST /auth/link/passkey/register — complete passkey linking
    // ----------------------------------------------------------------
    app.post('/auth/link/passkey/register', {
      config: { rateLimit },
      schema: {
        body: {
          type: 'object',
          required: ['challengeId', 'credential'],
          properties: {
            challengeId: { type: 'string', maxLength: 128 },
            credential: { type: 'object' },
          },
        },
      },
    }, async (request, reply) => {
      const { challengeId, credential } = request.body as {
        challengeId: string;
        credential: RegistrationResponseJSON;
      };

      const pubkey = await authenticate(request);
      if (!pubkey) {
        return reply.status(401).send({
          error: { code: 'UNAUTHORIZED', message: 'Valid session token required' },
          meta: errorMeta(request),
        });
      }

      const challenge = consumeChallenge(challengeId);
      if (!challenge) {
        return reply.status(400).send({
          error: { code: 'INVALID_CHALLENGE', message: 'Challenge not found or expired' },
          meta: errorMeta(request),
        });
      }

      if (challenge.linkingPubkey !== pubkey) {
        return reply.status(401).send({
          error: { code: 'CHALLENGE_MISMATCH', message: 'Challenge does not belong to current session' },
          meta: errorMeta(request),
        });
      }

      let verification;
      try {
        verification = await verifyRegistrationResponse({
          response: credential,
          expectedChallenge: challenge.challenge,
          expectedOrigin: EXPECTED_ORIGINS,
          expectedRPID: RP_ID,
        });
      } catch (err) {
        request.log.warn({ err: err instanceof Error ? err.message : String(err), action: 'passkey_link' }, 'Passkey link verification failed');
        return reply.status(400).send({
          error: { code: 'VERIFICATION_FAILED', message: 'Attestation verification failed' },
          meta: errorMeta(request),
        });
      }

      if (!verification.verified || !verification.registrationInfo) {
        return reply.status(400).send({
          error: { code: 'VERIFICATION_FAILED', message: 'Verification failed' },
          meta: errorMeta(request),
        });
      }

      const { credential: webauthnCred } = verification.registrationInfo;
      const credentialId = webauthnCred.id;
      const publicKeyB64 = Buffer.from(webauthnCred.publicKey).toString('base64url');
      const counter = webauthnCred.counter;
      const now = Math.floor(Date.now() / 1000);

      // Check if passkey already linked to another account
      const existing = await storage.getCredentialById(credentialId);

      if (existing) {
        if (existing.pubkey === pubkey) {
          return reply.send({ linked: true, method: 'passkey' });
        }
        return reply.status(400).send({
          error: { code: 'ALREADY_LINKED', message: 'This passkey is already linked to another account' },
          meta: errorMeta(request),
        });
      }

      await storage.insertCredential({
        credential_id: credentialId,
        pubkey,
        public_key: publicKeyB64,
        counter,
        transports: JSON.stringify(webauthnCred.transports ?? []),
        name: challenge.username || 'passkey',
        now,
        // The link flow binds a credential to an already-authenticated account.
        // is_prf stays 0: the server cannot distinguish a PRF-capable linked
        // credential, and the account's nsec (if server-generated) should
        // remain deliverable on first login with the new credential.
        is_prf: 0,
      });
      await storage.insertAuthMethod({ method: 'passkey', authId: credentialId, pubkey, now });
      await storage.touchAuthMethod('passkey', credentialId, now);

      return reply.send({ linked: true, method: 'passkey' });
    });
  }
}
