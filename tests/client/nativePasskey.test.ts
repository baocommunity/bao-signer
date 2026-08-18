/**
 * Regression tests for the nativePasskey audit fixes:
 *
 *  1. extractPrfSeed must read extension results from RAW PublicKeyCredential
 *     objects via getClientExtensionResults() (method), not only from JSON
 *     responses via the clientExtensionResults property. Before the fix the
 *     raw-credential path always returned null, forcing a needless second
 *     authenticator prompt on every registration.
 *  2. isCancelError distinguishes user-cancel (NotAllowedError/AbortError)
 *     from genuine capability failures so unlock errors are reported honestly.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import { extractPrfSeed, isCancelError, isPrfAvailable } from "../../src/client/nativePasskey.ts";
import { BrowserPasskeyPrfProvider } from "../../src/client/prf.ts";

describe("extractPrfSeed", () => {
  const seed = new Uint8Array(32).fill(7);

  it("reads PRF results from a raw PublicKeyCredential (getClientExtensionResults method)", () => {
    const rawCredential = {
      getClientExtensionResults: () => ({
        prf: { results: { first: seed.buffer } },
      }),
    };
    const out = extractPrfSeed(rawCredential);
    expect(out).not.toBeNull();
    expect(out!.length).toBe(32);
    expect(out![0]).toBe(7);
  });

  it("reads PRF results from a SimpleWebAuthn JSON response (property)", () => {
    const jsonResponse = {
      clientExtensionResults: {
        prf: { results: { first: seed.buffer } },
      },
    };
    const out = extractPrfSeed(jsonResponse);
    expect(out).not.toBeNull();
    expect(out!.length).toBe(32);
  });

  it("prefers the method when both shapes are present (raw credential behavior)", () => {
    const other = new Uint8Array(32).fill(9);
    const mixed = {
      clientExtensionResults: { prf: { results: { first: other.buffer } } },
      getClientExtensionResults: () => ({
        prf: { results: { first: seed.buffer } },
      }),
    };
    const out = extractPrfSeed(mixed);
    expect(out![0]).toBe(7);
  });

  it("returns null when no PRF results exist", () => {
    expect(extractPrfSeed({ getClientExtensionResults: () => ({}) })).toBeNull();
    expect(extractPrfSeed({ clientExtensionResults: {} })).toBeNull();
    expect(extractPrfSeed({})).toBeNull();
  });

  it("returns null when prf is enabled but has no results yet", () => {
    const raw = { getClientExtensionResults: () => ({ prf: { enabled: true } }) };
    expect(extractPrfSeed(raw)).toBeNull();
  });
});

describe("isCancelError", () => {
  it("recognizes user-cancel and timeout as cancellation", () => {
    expect(isCancelError(new DOMException("cancelled", "NotAllowedError"))).toBe(true);
    expect(isCancelError(new DOMException("aborted", "AbortError"))).toBe(true);
  });

  it("rejects genuine capability/data failures", () => {
    expect(isCancelError(new DOMException("bad state", "InvalidStateError"))).toBe(false);
    expect(isCancelError(new Error("PRF result not available"))).toBe(false);
    expect(isCancelError("NotAllowedError")).toBe(false);
    expect(isCancelError(null)).toBe(false);
  });
});

describe("isPrfAvailable capability detection", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("reports true when getClientCapabilities says prf is supported", async () => {
    vi.stubGlobal("window", {
      PublicKeyCredential: {
        getClientCapabilities: async () => ({ prf: true }),
      },
    });
    expect(await isPrfAvailable()).toBe(true);
  });

  it("does NOT over-report: prf:false wins even when a platform authenticator exists", async () => {
    vi.stubGlobal("window", {
      PublicKeyCredential: {
        getClientCapabilities: async () => ({ prf: false }),
        isUserVerifyingPlatformAuthenticatorAvailable: async () => true,
      },
    });
    expect(await isPrfAvailable()).toBe(false);
  });

  it("falls back to the platform heuristic only when getClientCapabilities is unavailable", async () => {
    vi.stubGlobal("window", {
      PublicKeyCredential: {
        isUserVerifyingPlatformAuthenticatorAvailable: async () => true,
      },
    });
    expect(await isPrfAvailable()).toBe(true);
  });

  it("BrowserPasskeyPrfProvider applies the same honest capability check", async () => {
    vi.stubGlobal("window", {
      PublicKeyCredential: {
        getClientCapabilities: async () => ({ prf: false }),
        isUserVerifyingPlatformAuthenticatorAvailable: async () => true,
      },
    });
    const provider = new BrowserPasskeyPrfProvider();
    expect(await provider.isPrfAvailable()).toBe(false);
  });
});
