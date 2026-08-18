/**
 * storage.test.ts — regression tests for the find-or-create race guard and
 * upsert semantics in the in-memory reference storage.
 */
import { describe, it, expect } from "vitest";
import { MemorySignerStorage } from "../../src/server/storage.ts";

describe("MemorySignerStorage.insertAuthMethodIfAbsent", () => {
  it("claims once and returns false on subsequent inserts", async () => {
    const storage = new MemorySignerStorage();
    expect(
      await storage.insertAuthMethodIfAbsent({ method: "telegram", authId: "a1", pubkey: "pk1", now: 1 }),
    ).toBe(true);
    expect(
      await storage.insertAuthMethodIfAbsent({ method: "telegram", authId: "a1", pubkey: "pk2", now: 2 }),
    ).toBe(false);
    // The first caller's pubkey stays canonical.
    expect((await storage.findAuthMethod("telegram", "a1"))?.pubkey).toBe("pk1");
  });

  it("treats distinct auth ids as independent claims", async () => {
    const storage = new MemorySignerStorage();
    expect(
      await storage.insertAuthMethodIfAbsent({ method: "telegram", authId: "a1", pubkey: "pk1", now: 1 }),
    ).toBe(true);
    expect(
      await storage.insertAuthMethodIfAbsent({ method: "telegram", authId: "a2", pubkey: "pk2", now: 1 }),
    ).toBe(true);
  });
});

describe("MemorySignerStorage.upsertAccount", () => {
  it("refreshes npub + nostr_only_mode while preserving username and nsec_hash", async () => {
    const storage = new MemorySignerStorage();
    const pubkey = "a".repeat(64);
    await storage.insertAccount({ pubkey, nsec_hash: "real-hash", username: "Alice", now: 1 });

    const internal = (storage as unknown as { accounts: Map<string, Record<string, unknown>> }).accounts;
    const row = internal.get(pubkey)!;
    row.nostr_only_mode = 0;
    row.npub = "";

    await storage.upsertAccount({
      pubkey,
      nsec_hash: "marker-hash",
      npub: "npub1xxxx",
      username: "Nostr abcdefgh",
      nostr_only_mode: 1,
      now: 2,
    });

    expect(row.username).toBe("Alice"); // preserved, not clobbered by placeholder
    expect(row.nsec_hash).toBe("real-hash"); // preserved, not overwritten by marker
    expect(row.npub).toBe("npub1xxxx"); // deterministic field refreshed
    expect(row.nostr_only_mode).toBe(1); // monotonic upgrade
    expect(row.last_login_at).toBe(2);
  });

  it("never downgrades nostr_only_mode back to 0", async () => {
    const storage = new MemorySignerStorage();
    const pubkey = "b".repeat(64);
    await storage.insertAccount({ pubkey, nsec_hash: "h", username: "u", now: 1, nostr_only_mode: 1 });

    await storage.upsertAccount({
      pubkey,
      nsec_hash: "h2",
      username: "u2",
      nostr_only_mode: 0,
      now: 2,
    });

    const internal = (storage as unknown as { accounts: Map<string, Record<string, unknown>> }).accounts;
    expect(internal.get(pubkey)!.nostr_only_mode).toBe(1);
  });
});
