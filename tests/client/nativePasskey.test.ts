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
import { describe, expect, it } from "vitest";
import { extractPrfSeed, isCancelError } from "../../src/client/nativePasskey.ts";

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
