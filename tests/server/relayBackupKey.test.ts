import { describe, it, expect } from "vitest";
import { createHmac } from "crypto";
import { deriveRelayBackupKey } from "../../src/server/relayBackupKey.ts";

describe("deriveRelayBackupKey", () => {
  it("derives an HMAC of the credentialId", () => {
    const key = deriveRelayBackupKey("credential-1", "server-secret");
    const expected = createHmac("sha256", "server-secret")
      .update("credential-1")
      .digest("hex")
      .slice(0, 32);
    expect(key).toBe(expected);
  });

  it("is deterministic for the same inputs", () => {
    expect(deriveRelayBackupKey("cred", "secret")).toBe(
      deriveRelayBackupKey("cred", "secret"),
    );
  });

  it("fails closed without a secret", () => {
    expect(() => deriveRelayBackupKey("credential-1", "")).toThrow(/secret/i);
    // @ts-expect-error — runtime guard against undefined
    expect(() => deriveRelayBackupKey("credential-1", undefined)).toThrow(/secret/i);
  });

  it("different secrets produce different keys", () => {
    expect(deriveRelayBackupKey("cred", "a")).not.toBe(deriveRelayBackupKey("cred", "b"));
  });
});
