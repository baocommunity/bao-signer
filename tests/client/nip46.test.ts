/**
 * nip46 tests — bunker URL parsing (the Nip46Client relay flow is covered by
 * integration tests against a live bunker in bao.markets; unit-testing the
 * client here uses a stubbed pool).
 */
import { describe, it, expect } from "vitest";
import { nip19, generateSecretKey, getPublicKey, finalizeEvent, type UnsignedEvent } from "nostr-tools";
import { bytesToHex } from "@noble/hashes/utils.js";
import { parseBunkerUrl, Nip46Client } from "../../src/client/nip46.ts";

const PK_HEX = bytesToHex(generateSecretKey());
const NPUB = nip19.npubEncode(getPublicKey(generateSecretKey()));

describe("parseBunkerUrl", () => {
  it("parses a hex-pubkey bunker URL with relays and secret", () => {
    const r = parseBunkerUrl(`bunker://${PK_HEX}?relay=wss://relay.example.com&secret=abc123`);
    expect(r.valid).toBe(true);
    expect(r.data!.pubkey).toBe(PK_HEX.toLowerCase());
    expect(r.data!.relays).toEqual(["wss://relay.example.com"]);
    expect(r.data!.secret).toBe("abc123");
  });

  it("parses npub pubkeys and multiple relays", () => {
    const r = parseBunkerUrl(`bunker://${NPUB}?relay=wss://a.example.com&relay=wss://b.example.com`);
    expect(r.valid).toBe(true);
    expect(r.data!.relays).toHaveLength(2);
  });

  it("rejects non-bunker URLs, bad pubkeys, and missing relays", () => {
    expect(parseBunkerUrl("https://example.com").valid).toBe(false);
    expect(parseBunkerUrl("bunker://notakey?relay=wss://r.example.com").valid).toBe(false);
    expect(parseBunkerUrl(`bunker://${PK_HEX}`).valid).toBe(false);
  });

  it("rejects relay URLs with embedded credentials and non-ws protocols", () => {
    const r = parseBunkerUrl(
      `bunker://${PK_HEX}?relay=wss://user:pass@evil.example.com&relay=https://notws.example.com`,
    );
    expect(r.valid).toBe(false); // both relays filtered → none left
  });

  it("accepts ws:// for local development", () => {
    const r = parseBunkerUrl(`bunker://${PK_HEX}?relay=ws://localhost:7777`);
    expect(r.valid).toBe(true);
  });
});

describe("Nip46Client", () => {
  it("rejects invalid bunker URLs at construction", () => {
    expect(() => new Nip46Client({ bunkerUrl: "bunker://bad" })).toThrow();
  });

  it("constructs with a valid URL and starts disconnected", () => {
    const c = new Nip46Client({ bunkerUrl: `bunker://${PK_HEX}?relay=wss://r.example.com` });
    expect(c.status).toBe("disconnected");
    c.disconnect();
  });
});

describe("Nip46Client.finalizeEventRemote", () => {
  function makeClient(bunkerSk: Uint8Array): {
    client: Nip46Client;
    bunkerPk: string;
  } {
    const bunkerPk = getPublicKey(bunkerSk);
    const client = new Nip46Client({
      bunkerUrl: `bunker://${bunkerPk}?relay=wss://r.example.com`,
    });
    return { client, bunkerPk };
  }

  function stubResponse(client: Nip46Client, event: unknown): void {
    (client as unknown as { sendRequest: (m: string, p: string[]) => Promise<string> }).sendRequest =
      async () => JSON.stringify(event);
  }

  it("accepts the correctly-signed requested event", async () => {
    const bunkerSk = generateSecretKey();
    const { client, bunkerPk } = makeClient(bunkerSk);

    const requested: UnsignedEvent = {
      kind: 1,
      created_at: 1_700_000_000,
      tags: [],
      content: "hello",
      pubkey: bunkerPk,
    };
    const signed = finalizeEvent(requested, bunkerSk);
    stubResponse(client, signed);

    const out = await client.finalizeEventRemote(requested);
    expect(out.id).toBe(signed.id);
    expect(out.sig).toBe(signed.sig);
  });

  it("rejects a validly-signed event that does not match the requested template", async () => {
    const bunkerSk = generateSecretKey();
    const { client, bunkerPk } = makeClient(bunkerSk);

    const requested: UnsignedEvent = {
      kind: 1,
      created_at: 1_700_000_000,
      tags: [["t", "requested"]],
      content: "the real content",
      pubkey: bunkerPk,
    };

    // The "bunker" signs a DIFFERENT event than what was requested — the
    // signature is still valid, so only the template-match check can catch it.
    const forgedTemplate: UnsignedEvent = {
      kind: 999,
      created_at: 1_700_000_000,
      tags: [["t", "forged"]],
      content: "different content",
      pubkey: bunkerPk,
    };
    const forged = finalizeEvent(forgedTemplate, bunkerSk);
    stubResponse(client, forged);

    await expect(client.finalizeEventRemote(requested)).rejects.toThrow(
      /does not match the requested template/,
    );
  });
});
