/**
 * Native Passkey module for bao-signer.
 *
 * Adapted from nostrified-mockup (Freedom ID) passkey.ts.
 * Zero-dependency, client-side only.
 *
 * Supports:
 *  - Platform authenticators with PRF (Touch ID, Face ID, Windows Hello, Android fingerprint)
 *  - YubiKey Bio series (PRF-capable)
 *  - YubiKey 5 series via largeBlob extension (fallback)
 *
 * No external libraries required. Uses native navigator.credentials + Web Crypto API.
 */

/* ── Constants ─────────────────────────────────────────────── */

const BAO_PRF_CONTEXT = "bao:prf:v1";
const BAO_NATIVE_PASSKEY_SALT = "bao:native_passkey:salt:v1";

/* ── Configuration ─────────────────────────────────────────── */

export interface NativePasskeyConfig {
  /** Relying Party display name shown in the authenticator prompt. */
  rpName?: string;
  /** localStorage key prefix for enrollment data. */
  storagePrefix?: string;
}

let nativePasskeyConfig: Required<NativePasskeyConfig> = {
  rpName: "BAO Signer",
  storagePrefix: "bao_native_passkey",
};

export function configureNativePasskey(config: NativePasskeyConfig): void {
  nativePasskeyConfig = { ...nativePasskeyConfig, ...config };
}

export function getNativePasskeyConfig(): Required<NativePasskeyConfig> {
  return nativePasskeyConfig;
}

/** Namespaced localStorage key. Exported so sibling modules
 * (nativePasskeyAuth) share the SAME configurable prefix — hardcoding a
 * second prefix splits enrollment state when consumers configure a custom one. */
export function nativePasskeyStorageKey(suffix: string): string {
  return `${nativePasskeyConfig.storagePrefix}_${suffix}`;
}

/* ── Types ─────────────────────────────────────────────────── */

export interface PasskeyEnrollment {
  credentialId: string;
  isYubiKey: boolean;
  /** 'prf' | 'largeBlob' — how the master key is wrapped */
  method: "prf" | "largeBlob";
}

export interface PasskeyUnlockResult {
  masterKey: CryptoKey;
  method: "prf" | "largeBlob";
}

/* ── Base64url helpers (no @simplewebauthn/browser dep) ────── */

function bufferToBase64URLString(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function base64URLStringToBuffer(base64URLString: string): ArrayBuffer {
  const base64 = base64URLString.replace(/-/g, "+").replace(/_/g, "/");
  const padLength = (4 - (base64.length % 4)) % 4;
  const padded = base64.padEnd(base64.length + padLength, "=");
  const binary = atob(padded);
  const buffer = new ArrayBuffer(binary.length);
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return buffer;
}

/* ── PRF Extension Helpers ─────────────────────────────────── */

interface PrfExtensionOutput {
  prf?: {
    results?: {
      first?: ArrayBuffer;
    };
  };
}

/** Extract the PRF seed from either a raw PublicKeyCredential (method) or a
 * SimpleWebAuthn JSON response (property). Exported for consumers that drive
 * navigator.credentials directly. */
export function extractPrfSeed(response: {
  clientExtensionResults?: unknown;
  getClientExtensionResults?: () => unknown;
}): Uint8Array | null {
  // Raw PublicKeyCredential exposes extension results ONLY via the
  // getClientExtensionResults() method — there is no clientExtensionResults
  // property, so reading it always yields undefined. JSON responses
  // (SimpleWebAuthn) carry the property instead. Support both.
  const ext = (
    typeof response.getClientExtensionResults === "function"
      ? response.getClientExtensionResults()
      : response.clientExtensionResults
  ) as PrfExtensionOutput | undefined;
  if (!ext?.prf?.results?.first) return null;
  return new Uint8Array(ext.prf.results.first);
}

/* ── Availability Detection ────────────────────────────────── */

/** Check if the browser supports WebAuthn PRF. */
export async function isPrfAvailable(): Promise<boolean> {
  if (typeof window === "undefined" || !window.PublicKeyCredential) return false;

  try {
    const caps = await (window.PublicKeyCredential as any).getClientCapabilities?.();
    if (caps?.prf === true) return true;
  } catch {
    /* fallback below */
  }

  try {
    const available = await (window.PublicKeyCredential as any)
      .isUserVerifyingPlatformAuthenticatorAvailable?.();
    if (available) return true;
  } catch {
    /* ignore */
  }

  return false;
}

/** Check if WebAuthn is available at all. */
export function isWebAuthnAvailable(): boolean {
  return typeof window !== "undefined" && !!window.PublicKeyCredential;
}

/** Check if largeBlob extension is available (for non-PRF YubiKeys). */
export async function isLargeBlobAvailable(): Promise<boolean> {
  if (!isWebAuthnAvailable()) return false;
  try {
    const caps = await (window.PublicKeyCredential as any).getClientCapabilities?.();
    return caps?.largeBlob === true;
  } catch {
    return false;
  }
}

/* ── Master Key Derivation from PRF Seed ───────────────────── */

/**
 * Derive a 256-bit AES-GCM key from a PRF seed.
 * The same passkey + same salt always produces the same key.
 */
async function deriveMasterKeyFromPrf(prfSeed: Uint8Array): Promise<CryptoKey> {
  const baseKey = await crypto.subtle.importKey("raw", buf(prfSeed), "HKDF", false, [
    "deriveKey",
  ]);
  const salt = new TextEncoder().encode(BAO_NATIVE_PASSKEY_SALT);
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      salt: buf(salt),
      info: new TextEncoder().encode("master"),
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/* ── Wrapping / Unwrapping ─────────────────────────────────── */

/** Cast Uint8Array to BufferSource for Web Crypto DOM types. */
function buf(src: Uint8Array): BufferSource {
  return src as unknown as BufferSource;
}

/** Wrap a master key with a passkey-derived key. */
async function wrapMasterKey(masterKey: CryptoKey, wrappingKey: CryptoKey): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wrapped = await crypto.subtle.wrapKey("raw", masterKey, wrappingKey, {
    name: "AES-GCM",
    iv: buf(iv),
  });
  const combined = new Uint8Array(iv.length + wrapped.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(wrapped), iv.length);
  return bufferToBase64URLString(combined.buffer);
}

/** Unwrap a master key with a passkey-derived key. */
async function unwrapMasterKey(wrappedB64: string, wrappingKey: CryptoKey): Promise<CryptoKey> {
  const combined = new Uint8Array(base64URLStringToBuffer(wrappedB64));
  const iv = combined.slice(0, 12);
  const wrapped = combined.slice(12);
  return crypto.subtle.unwrapKey(
    "raw",
    buf(wrapped),
    wrappingKey,
    { name: "AES-GCM", iv: buf(iv) },
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

/* ── Registration ──────────────────────────────────────────── */

/**
 * Register a platform passkey (Touch ID, Face ID, etc.) with PRF extension.
 * Returns the credential ID and wraps the provided master key.
 */
export async function registerPlatformPasskey(masterKey: CryptoKey): Promise<PasskeyEnrollment> {
  if (!isWebAuthnAvailable()) throw new Error("WebAuthn not available");

  const prfSalt = new TextEncoder().encode(BAO_PRF_CONTEXT);

  const createOptions: PublicKeyCredentialCreationOptions = {
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    rp: { name: getNativePasskeyConfig().rpName, id: window.location.hostname },
    user: {
      id: crypto.getRandomValues(new Uint8Array(16)),
      name: "bao-user",
      displayName: "BAO User",
    },
    pubKeyCredParams: [{ alg: -7, type: "public-key" }],
    authenticatorSelection: {
      authenticatorAttachment: "platform",
      userVerification: "required",
      residentKey: "preferred",
      requireResidentKey: false,
    },
    attestation: "none",
    extensions: {
      prf: { eval: { first: prfSalt.buffer } },
    } as any,
  };

  const credential = (await navigator.credentials.create({
    publicKey: createOptions,
  })) as PublicKeyCredential;
  if (!credential) throw new Error("Passkey creation was cancelled");

  const credentialId = bufferToBase64URLString(credential.rawId);

  // Try to extract PRF seed from registration response
  let prfSeed = extractPrfSeed(credential as any);

  // PRF sometimes isn't returned during creation — do a self-auth to get it
  if (!prfSeed) {
    const extResults = (credential as any).getClientExtensionResults?.() as
      | PrfExtensionOutput
      | undefined;
    if (extResults?.prf) {
      const authOptions: PublicKeyCredentialRequestOptions = {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rpId: window.location.hostname,
        allowCredentials: [{ id: credential.rawId, type: "public-key" }],
        userVerification: "required",
        extensions: { prf: { eval: { first: prfSalt.buffer } } } as any,
      };
      const assertion = (await navigator.credentials.get({
        publicKey: authOptions,
      })) as PublicKeyCredential;
      prfSeed = extractPrfSeed(assertion as any);
    }
  }

  if (!prfSeed) {
    // Platform authenticator doesn't support PRF — try largeBlob path for YubiKey
    throw new Error(
      "PRF_NOT_SUPPORTED: Your device does not support PRF. Try a YubiKey with largeBlob support or use PIN instead.",
    );
  }

  // Derive wrapping key from PRF seed and wrap master key
  const wrappingKey = await deriveMasterKeyFromPrf(prfSeed);
  const wrapped = await wrapMasterKey(masterKey, wrappingKey);

  // Store enrollment data
  localStorage.setItem(nativePasskeyStorageKey("credential_id"), credentialId);
  localStorage.setItem(nativePasskeyStorageKey("wrapped_master"), wrapped);
  localStorage.setItem(nativePasskeyStorageKey("is_yubikey"), "false");
  localStorage.setItem(nativePasskeyStorageKey("method"), "prf");

  return { credentialId, isYubiKey: false, method: "prf" };
}

/**
 * Register a YubiKey (or other cross-platform authenticator) with PRF extension.
 * For YubiKey 5.7+ and other FIDO2 keys that support the PRF extension.
 */
export async function registerYubiKeyWithPrf(masterKey: CryptoKey): Promise<PasskeyEnrollment> {
  if (!isWebAuthnAvailable()) throw new Error("WebAuthn not available");

  const prfSalt = new TextEncoder().encode(BAO_PRF_CONTEXT);

  const createOptions: PublicKeyCredentialCreationOptions = {
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    rp: { name: getNativePasskeyConfig().rpName, id: window.location.hostname },
    user: {
      id: crypto.getRandomValues(new Uint8Array(16)),
      name: "bao-yubikey",
      displayName: "BAO YubiKey",
    },
    pubKeyCredParams: [{ alg: -7, type: "public-key" }],
    authenticatorSelection: {
      authenticatorAttachment: "cross-platform",
      userVerification: "required",
      residentKey: "preferred",
      requireResidentKey: false,
    },
    attestation: "none",
    extensions: {
      prf: { eval: { first: prfSalt.buffer } },
    } as any,
  };

  const credential = (await navigator.credentials.create({
    publicKey: createOptions,
  })) as PublicKeyCredential;
  if (!credential) throw new Error("Passkey creation was cancelled");

  const credentialId = bufferToBase64URLString(credential.rawId);

  // Try to extract PRF seed from registration response
  let prfSeed = extractPrfSeed(credential as any);

  // PRF sometimes isn't returned during creation — do a self-auth to get it
  if (!prfSeed) {
    const extResults = (credential as any).getClientExtensionResults?.() as
      | PrfExtensionOutput
      | undefined;
    if (extResults?.prf) {
      const authOptions: PublicKeyCredentialRequestOptions = {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rpId: window.location.hostname,
        allowCredentials: [{ id: credential.rawId, type: "public-key" }],
        userVerification: "required",
        extensions: { prf: { eval: { first: prfSalt.buffer } } } as any,
      };
      const assertion = (await navigator.credentials.get({
        publicKey: authOptions,
      })) as PublicKeyCredential;
      prfSeed = extractPrfSeed(assertion as any);
    }
  }

  if (!prfSeed) {
    throw new Error(
      "PRF_NOT_SUPPORTED: Your YubiKey does not support PRF. Try largeBlob enrollment or use PIN instead.",
    );
  }

  // Derive wrapping key from PRF seed and wrap master key
  const wrappingKey = await deriveMasterKeyFromPrf(prfSeed);
  const wrapped = await wrapMasterKey(masterKey, wrappingKey);

  // Store enrollment data
  localStorage.setItem(nativePasskeyStorageKey("credential_id"), credentialId);
  localStorage.setItem(nativePasskeyStorageKey("wrapped_master"), wrapped);
  localStorage.setItem(nativePasskeyStorageKey("is_yubikey"), "true");
  localStorage.setItem(nativePasskeyStorageKey("method"), "prf");

  return { credentialId, isYubiKey: true, method: "prf" };
}

/**
 * Register a roaming authenticator (YubiKey) with largeBlob support.
 * Used when PRF is not available but largeBlob is.
 */
export async function registerYubiKeyPasskey(masterKey: CryptoKey): Promise<PasskeyEnrollment> {
  if (!isWebAuthnAvailable()) throw new Error("WebAuthn not available");

  const largeBlobData = crypto.getRandomValues(new Uint8Array(32));

  const createOptions: PublicKeyCredentialCreationOptions = {
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    rp: { name: getNativePasskeyConfig().rpName, id: window.location.hostname },
    user: {
      id: crypto.getRandomValues(new Uint8Array(16)),
      name: "bao-yubikey",
      displayName: "BAO YubiKey",
    },
    pubKeyCredParams: [{ alg: -7, type: "public-key" }],
    authenticatorSelection: {
      authenticatorAttachment: "cross-platform",
      userVerification: "required",
    },
    attestation: "none",
    extensions: {
      largeBlob: { support: "required" },
    } as any,
  };

  const credential = (await navigator.credentials.create({
    publicKey: createOptions,
  })) as PublicKeyCredential;
  if (!credential) throw new Error("Passkey creation was cancelled");

  const credentialId = bufferToBase64URLString(credential.rawId);

  // Derive a wrapping key from the largeBlob data (which we store ON the YubiKey)
  const wrappingKey = await crypto.subtle.importKey("raw", largeBlobData, "HKDF", false, [
    "deriveKey",
  ]);
  const derivedKey = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      salt: new TextEncoder().encode(BAO_NATIVE_PASSKEY_SALT),
      info: new Uint8Array(0),
      hash: "SHA-256",
    },
    wrappingKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );

  const wrapped = await wrapMasterKey(masterKey, derivedKey);

  // Store the largeBlob data back to the credential via an auth call
  const authOptions: PublicKeyCredentialRequestOptions = {
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    rpId: window.location.hostname,
    allowCredentials: [{ id: credential.rawId, type: "public-key" }],
    userVerification: "required",
    extensions: {
      largeBlob: { write: largeBlobData.buffer },
    } as any,
  };

  try {
    await navigator.credentials.get({ publicKey: authOptions });
  } catch {
    // largeBlob write failed — the YubiKey cannot store our secret.
    // Without the blob on the key, we have no secure way to derive the
    // wrapping key on unlock. Abort enrollment rather than create a
    // broken enrollment that can never unlock.
    throw new Error(
      "YubiKey largeBlob write failed. Your device may not support largeBlob. Try a YubiKey with PRF support (firmware 5.7+) or use a platform passkey / PIN instead.",
    );
  }

  // Verify the blob was actually written by reading it back
  const verifyAuthOptions: PublicKeyCredentialRequestOptions = {
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    rpId: window.location.hostname,
    allowCredentials: [{ id: credential.rawId, type: "public-key" }],
    userVerification: "required",
    extensions: { largeBlob: { read: true } } as any,
  };

  try {
    const verifyAssertion = (await navigator.credentials.get({
      publicKey: verifyAuthOptions,
    })) as PublicKeyCredential;
    const verifyExt = (verifyAssertion as any).getClientExtensionResults?.() as
      | { largeBlob?: { blob?: ArrayBuffer } }
      | undefined;
    const readBack = verifyExt?.largeBlob?.blob;
    if (!readBack || !timingSafeEqual(new Uint8Array(readBack), largeBlobData)) {
      throw new Error("YubiKey largeBlob verification failed — data did not persist. Enrollment aborted.");
    }
  } catch {
    throw new Error("YubiKey largeBlob read-back verification failed. Enrollment aborted.");
  }

  localStorage.setItem(nativePasskeyStorageKey("credential_id"), credentialId);
  localStorage.setItem(nativePasskeyStorageKey("wrapped_master"), wrapped);
  localStorage.setItem(nativePasskeyStorageKey("is_yubikey"), "true");
  localStorage.setItem(nativePasskeyStorageKey("method"), "largeBlob");

  return { credentialId, isYubiKey: true, method: "largeBlob" };
}

/** True when the authenticator ceremony was cancelled/timed out by the user
 * (or no authenticator responded) — NOT a genuine capability failure. */
/** Exported so consumers can distinguish user-cancel from capability failures. */
export function isCancelError(e: unknown): boolean {
  return (
    e instanceof DOMException &&
    (e.name === "NotAllowedError" || e.name === "AbortError")
  );
}

/* ── Authentication / Unlock ───────────────────────────────── */

/**
 * Unlock the master key using an enrolled passkey (PRF path).
 */
async function unlockWithPrf(credentialIdB64: string, wrappedB64: string): Promise<CryptoKey> {
  const credentialId = base64URLStringToBuffer(credentialIdB64);
  const prfSalt = new TextEncoder().encode(BAO_PRF_CONTEXT);

  const authOptions: PublicKeyCredentialRequestOptions = {
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    rpId: window.location.hostname,
    allowCredentials: [{ id: credentialId, type: "public-key" }],
    userVerification: "required",
    extensions: { prf: { eval: { first: prfSalt.buffer } } } as any,
  };

  const assertion = (await navigator.credentials.get({
    publicKey: authOptions,
  })) as PublicKeyCredential;
  if (!assertion) throw new Error("Passkey authentication was cancelled");

  const prfSeed = extractPrfSeed(assertion as any);
  if (!prfSeed) throw new Error("PRF result not available — your authenticator may not support PRF");

  const wrappingKey = await deriveMasterKeyFromPrf(prfSeed);
  return unwrapMasterKey(wrappedB64, wrappingKey);
}

/** Constant-time array comparison. */
function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export async function unlockWithPasskey(): Promise<PasskeyUnlockResult> {
  const credentialId = localStorage.getItem(nativePasskeyStorageKey("credential_id"));
  const wrappedB64 = localStorage.getItem(nativePasskeyStorageKey("wrapped_master"));
  const method = localStorage.getItem(nativePasskeyStorageKey("method")) as "prf" | "largeBlob" | null;
  const isYubiKeyLegacy = localStorage.getItem(nativePasskeyStorageKey("is_yubikey")) === "true";

  if (!credentialId || !wrappedB64) {
    throw new Error("No passkey enrolled");
  }

  // Legacy enrollments (before nativePasskeyStorageKey("method") existed)
  // isYubiKey='false' → PRF platform, isYubiKey='true' → largeBlob YubiKey
  const enrolledMethod: "prf" | "largeBlob" = method ?? (isYubiKeyLegacy ? "largeBlob" : "prf");

  // Try the enrolled method first
  if (enrolledMethod === "largeBlob") {
    const credentialIdBuf = base64URLStringToBuffer(credentialId);
    const authOptions: PublicKeyCredentialRequestOptions = {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rpId: window.location.hostname,
      allowCredentials: [{ id: credentialIdBuf, type: "public-key" }],
      userVerification: "required",
      extensions: { largeBlob: { read: true } } as any,
    };

    try {
      const assertion = (await navigator.credentials.get({
        publicKey: authOptions,
      })) as PublicKeyCredential;
      const ext = (assertion as any).getClientExtensionResults?.() as
        | { largeBlob?: { blob?: ArrayBuffer } }
        | undefined;
      const blob = ext?.largeBlob?.blob;

      if (blob) {
        const wrappingKey = await crypto.subtle.importKey("raw", new Uint8Array(blob), "HKDF", false, [
          "deriveKey",
        ]);
        const derivedKey = await crypto.subtle.deriveKey(
          {
            name: "HKDF",
            salt: new TextEncoder().encode(BAO_NATIVE_PASSKEY_SALT),
            info: new Uint8Array(0),
            hash: "SHA-256",
          },
          wrappingKey,
          { name: "AES-GCM", length: 256 },
          false,
          ["encrypt", "decrypt"],
        );
        const masterKey = await unwrapMasterKey(wrappedB64, derivedKey);
        return { masterKey, method: "largeBlob" };
      }
    } catch (e) {
      // User cancelled → report honestly, never mislabel as unavailable.
      if (isCancelError(e)) throw e;
      // largeBlob read failed — try PRF fallback (YubiKey may support both)
    }
  }

  // Try PRF (primary for platform, fallback for YubiKey)
  try {
    const masterKey = await unlockWithPrf(credentialId, wrappedB64);
    return { masterKey, method: "prf" };
  } catch (e) {
    if (isCancelError(e)) throw e;
    // PRF also failed
  }

  // Nothing worked. Give a clear error based on what was enrolled.
  if (enrolledMethod === "largeBlob") {
    throw new Error(
      "YubiKey unlock failed. largeBlob data is missing and PRF is not available. " +
        "Try re-inserting your YubiKey, or use PIN unlock instead.",
    );
  }
  throw new Error("Passkey unlock failed. PRF is not available on this authenticator. Use PIN unlock instead.");
}

/* ── Enrollment Status ─────────────────────────────────────── */

export function hasPasskeyEnrolled(): boolean {
  return !!localStorage.getItem(nativePasskeyStorageKey("credential_id")) && !!localStorage.getItem(nativePasskeyStorageKey("wrapped_master"));
}

export function getPasskeyEnrollment(): PasskeyEnrollment | null {
  const credentialId = localStorage.getItem(nativePasskeyStorageKey("credential_id"));
  const isYubiKey = localStorage.getItem(nativePasskeyStorageKey("is_yubikey")) === "true";
  const method = localStorage.getItem(nativePasskeyStorageKey("method")) as "prf" | "largeBlob" | null;
  if (!credentialId) return null;
  return { credentialId, isYubiKey, method: method ?? (isYubiKey ? "largeBlob" : "prf") };
}

/** Remove passkey enrollment. PIN remains as fallback. */
export function removePasskeyEnrollment(): void {
  try {
    localStorage.removeItem(nativePasskeyStorageKey("credential_id"));
  } catch {
    /* ignore */
  }
  try {
    localStorage.removeItem(nativePasskeyStorageKey("wrapped_master"));
  } catch {
    /* ignore */
  }
  try {
    localStorage.removeItem(nativePasskeyStorageKey("is_yubikey"));
  } catch {
    /* ignore */
  }
  try {
    localStorage.removeItem(nativePasskeyStorageKey("method"));
  } catch {
    /* ignore */
  }
}

/* ── Error Codes ───────────────────────────────────────────── */

export const PasskeyError = {
  NOT_AVAILABLE: "Passkeys are not available on this device",
  PRF_NOT_SUPPORTED:
    "Your authenticator does not support PRF. Use PIN or a PRF-capable device (YubiKey Bio, Touch ID, etc.)",
  CANCELLED: "Authentication was cancelled",
  NO_ENROLLMENT: "No passkey enrolled. Set up a passkey in settings first.",
  WRAP_FAILED: "Failed to wrap master key",
  UNWRAP_FAILED: "Failed to unlock — wrong authenticator or corrupted data",
} as const;
