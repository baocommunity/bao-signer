import { createHmac } from 'crypto';

/**
 * Derive the relay backup key for a passkey credential.
 *
 * FAIL CLOSED: a server-side HMAC secret is REQUIRED. An earlier design fell
 * back to `sha256("bao:backup:" + credentialId)` when no secret was
 * configured — but the credentialId is not a secret (it is sent to the server
 * on every login), so that fallback produced backup keys anyone could
 * reproduce. This function refuses to derive without a real secret.
 *
 * Note: this is a server-custodial recovery aid. For full self-custody,
 * prefer client-side backup keys derived from the PRF output.
 */
export function deriveRelayBackupKey(credentialId: string, secret: string): string {
  if (!secret || typeof secret !== 'string') {
    throw new Error(
      'deriveRelayBackupKey: a non-empty HMAC secret is required. ' +
        'Refusing to derive a predictable backup key.',
    );
  }
  return createHmac('sha256', secret).update(credentialId).digest('hex').slice(0, 32);
}
