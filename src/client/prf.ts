import {
  startAuthentication,
  bufferToBase64URLString,
} from "@simplewebauthn/browser";
import type {
  AuthenticationExtensionsClientInputs,
  AuthenticationExtensionsClientOutputs,
  AuthenticationResponseJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/browser";

export const BAO_PRF_CONTEXT = "bao:prf:v1";

/** Exported error codes so the UI can handle them consistently. */
export const BreezPasskeyError = {
  PRF_NOT_SUPPORTED: "PRF_NOT_SUPPORTED",
  PRF_RESULT_NOT_AVAILABLE: "PRF_RESULT_NOT_AVAILABLE",
  REGISTRATION_FAILED: "REGISTRATION_FAILED",
  LOGIN_FAILED: "LOGIN_FAILED",
  TIMEOUT: "TIMEOUT",
  SERVER_ERROR: "SERVER_ERROR",
} as const;

/**
 * Build the BAO-specific PRF salt for the Breez SDK provider path.
 *
 * The salt is constructed as `${BAO_PRF_CONTEXT}:${credentialId}:${userSalt}`.
 * This format is used by the Breez SDK integration path (`BrowserPasskeyPrfProvider`)
 * to derive deterministic wallet seeds. The resulting string is UTF-8 encoded and
 * passed to the WebAuthn PRF extension. PRF salts can be arbitrary length, so
 * the variable length of credentialId and userSalt is not an issue.
 *
 * @note This is intentionally different from the auth salt used in
 * `breezPasskeyAuth.ts`, which uses only `BAO_PRF_CONTEXT` (e.g. `"bao:prf:v1"`).
 * The auth path derives Nostr keys, while the Breez provider path derives
 * Breez SDK wallet seeds.
 */
function buildBaoSalt(credentialId: string, userSalt: string): string {
  return `${BAO_PRF_CONTEXT}:${credentialId}:${userSalt}`;
}

/**
 * Browser-native implementation of PasskeyPrfProvider using the WebAuthn PRF extension.
 *
 * Wraps `@simplewebauthn/browser`'s `startAuthentication()` and extracts the
 * deterministic PRF seed for Breez SDK self-custodial wallet derivation.
 */
export class BrowserPasskeyPrfProvider {
  private credentialId: string | null = null;

  setCredentialId(id: string): void {
    this.credentialId = id;
  }

  async isPrfAvailable(): Promise<boolean> {
    // Test override: Playwright tests set this global to control PRF
    // availability without mocking native WebAuthn APIs.
    const testOverride =
      typeof window !== "undefined"
        ? (window as any).__bao_test_prf_available
        : undefined;
    if (typeof testOverride === "boolean") {
      return testOverride;
    }

    if (typeof window === "undefined" || !window.PublicKeyCredential) {
      return false;
    }

    try {
      if (
        typeof window.PublicKeyCredential.getClientCapabilities === "function"
      ) {
        const caps = await window.PublicKeyCredential.getClientCapabilities();
        if (caps && typeof caps === "object") {
          // Authoritative for PRF support: a platform authenticator existing
          // does NOT imply PRF, so trust the reported capability instead of
          // falling through to the weaker platform-authenticator heuristic.
          return caps.prf === true;
        }
      }
    } catch {
      // Fall through to the legacy heuristic below
    }

    try {
      if (
        typeof window.PublicKeyCredential
          .isUserVerifyingPlatformAuthenticatorAvailable === "function"
      ) {
        return await window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
      }
    } catch {
      // Ignore
    }

    return false;
  }

  async derivePrfSeed(userSalt: string): Promise<Uint8Array> {
    if (typeof window === "undefined" || !navigator.credentials) {
      throw new Error(
        `${BreezPasskeyError.PRF_NOT_SUPPORTED}: WebAuthn is not available in this environment`,
      );
    }

    if (!this.credentialId) {
      throw new Error(
        `${BreezPasskeyError.PRF_RESULT_NOT_AVAILABLE}: No credential ID set. Call setCredentialId() first.`,
      );
    }

    const salt = buildBaoSalt(this.credentialId, userSalt);

    const optionsJSON: PublicKeyCredentialRequestOptionsJSON = {
      challenge: bufferToBase64URLString(crypto.getRandomValues(new Uint8Array(32)).buffer),
      rpId: window.location.hostname,
      allowCredentials: [
        {
          id: this.credentialId,
          type: "public-key",
        },
      ],
      userVerification: "required",
      extensions: {
        prf: {
          eval: {
            first: new TextEncoder().encode(salt),
          },
        },
      } as AuthenticationExtensionsClientInputs,
    };

    let assertion: AuthenticationResponseJSON;
    try {
      assertion = await startAuthentication({ optionsJSON });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Unknown error";
      throw new Error(
        `${BreezPasskeyError.LOGIN_FAILED}: Passkey authentication failed: ${message}`,
      );
    }

    const prfSeed = extractPrfFromAuthenticationResponse(assertion);
    if (!prfSeed) {
      throw new Error(
        `${BreezPasskeyError.PRF_RESULT_NOT_AVAILABLE}: PRF extension not supported or returned no result`,
      );
    }

    return prfSeed;
  }
}

/**
 * Extract the PRF seed from a raw `navigator.credentials.create()` response.
 *
 * @param credential - The raw `PublicKeyCredential` returned by creation
 * @param _salt      - The salt used during creation (for API consistency)
 * @returns The 32-byte PRF seed, or `null` if PRF results are absent
 */
export function extractPrfFromRegistration(
  credential: PublicKeyCredential,
  _salt: string,
): Uint8Array | null {
  const extensions = credential.getClientExtensionResults() as AuthenticationExtensionsClientOutputs & {
    prf?: { results?: { first?: BufferSource } };
  };

  if (!extensions.prf?.results?.first) {
    return null;
  }

  return bufferSourceToUint8Array(extensions.prf.results.first);
}

/**
 * Extract the PRF seed from a raw `navigator.credentials.get()` response.
 *
 * @param assertion - The raw `PublicKeyCredential` returned by authentication
 * @param _salt     - The salt used during authentication (for API consistency)
 * @returns The 32-byte PRF seed, or `null` if PRF results are absent
 */
export function extractPrfFromAuthentication(
  assertion: PublicKeyCredential,
  _salt: string,
): Uint8Array | null {
  const extensions = assertion.getClientExtensionResults() as AuthenticationExtensionsClientOutputs & {
    prf?: { results?: { first?: BufferSource } };
  };

  if (!extensions.prf?.results?.first) {
    return null;
  }

  return bufferSourceToUint8Array(extensions.prf.results.first);
}

/**
 * Extract the PRF seed from a SimpleWebAuthn JSON authentication response.
 *
 * @param response - The `AuthenticationResponseJSON` returned by `startAuthentication()`
 * @returns The 32-byte PRF seed, or `null` if PRF results are absent
 */
export function extractPrfFromAuthenticationResponse(
  response: AuthenticationResponseJSON,
): Uint8Array | null {
  const extResults = response.clientExtensionResults as AuthenticationExtensionsClientOutputs & {
    prf?: { results?: { first?: ArrayBuffer } };
  };

  if (!extResults.prf?.results?.first) {
    return null;
  }

  return new Uint8Array(extResults.prf.results.first);
}

function bufferSourceToUint8Array(source: BufferSource): Uint8Array {
  if (ArrayBuffer.isView(source)) {
    return new Uint8Array(source.buffer, source.byteOffset, source.byteLength);
  }
  return new Uint8Array(source);
}

/**
 * Convert a base64url-encoded string to an `ArrayBuffer`.
 *
 * @param base64URLString - A base64url-encoded string (no padding, `-` and `_` instead of `+` and `/`)
 * @returns The decoded `ArrayBuffer`
 */
export function base64URLStringToBuffer(base64URLString: string): ArrayBuffer {
  const base64 = base64URLString.replace(/-/g, "+").replace(/_/g, "/");
  const padLength = (4 - (base64.length % 4)) % 4;
  const padded = base64.padEnd(base64.length + padLength, "=");
  const binary = atob(padded);
  const buffer = new ArrayBuffer(binary.length);
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return buffer;
}
