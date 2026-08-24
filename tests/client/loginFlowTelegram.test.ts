/**
 * loginFlowMachine.telegram.test.ts — the Telegram QR login path:
 * start returns the challenge; poll ticks map server responses to
 * pending/expired/done and wrap the session as a LoginResult.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createLoginFlow } from "../../src/client/loginFlowMachine.ts";
import { configureBaoSignerClient } from "../../src/client/config.ts";

const fetchMock = vi.fn();

beforeEach(() => {
  vi.stubGlobal("fetch", fetchMock);
  configureBaoSignerClient({ apiBaseUrl: "https://signer.test" });
});

afterEach(() => {
  vi.unstubAllGlobals();
  fetchMock.mockReset();
});

function jsonRes(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("telegram QR flow via createLoginFlow", () => {
  it("start returns the challenge (state + authUrl + expiry)", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonRes({ state: "a".repeat(64), authUrl: "https://oauth.telegram.org/xyz", expiresAt: 1900000000 }),
    );
    const flow = createLoginFlow();
    const ch = await flow.telegramStart();
    expect(ch.state).toBe("a".repeat(64));
    expect(ch.authUrl).toContain("telegram");
    expect(ch.expiresAt).toBeGreaterThan(0);
    expect(fetchMock.mock.calls[0][0]).toContain("/auth/telegram/qr");
  });

  it("poll tick maps authenticated → done with a telegram LoginResult", async () => {
    fetchMock.mockResolvedValueOnce(
      jsonRes({
        authenticated: true,
        session: {
          pubkey: "f".repeat(64),
          npub: "npub1x",
          nsec: null,
          username: "user_a",
          firstLogin: false,
          isNewAccount: false,
          authMethod: "telegram",
          linkedMethods: ["email"],
          relayBackupKey: "",
          sessionToken: "bao_sess_x",
          expires_at: 1900000000,
        },
      }),
    );
    const flow = createLoginFlow();
    const res = await flow.telegramPollTick("b".repeat(64));
    expect(res.status).toBe("done");
    if (res.status === "done") {
      expect(res.result.method).toBe("telegram");
      expect(res.result.pubkey).toBe("f".repeat(64));
    }
  });

  it("poll tick maps unauthenticated → pending, and gone/expired challenges → expired", async () => {
    const flow = createLoginFlow();

    // still waiting
    fetchMock.mockResolvedValueOnce(jsonRes({ authenticated: false, expiresAt: 1900000000 }));
    const pending = await flow.telegramPollTick("c".repeat(64));
    expect(pending.status).toBe("pending");

    // 404 — challenge never existed / already consumed elsewhere
    fetchMock.mockResolvedValueOnce(jsonRes({ error: { code: "NOT_FOUND" } }, 404));
    expect((await flow.telegramPollTick("d".repeat(64))).status).toBe("expired");

    // 410 — explicit expiry
    fetchMock.mockResolvedValueOnce(jsonRes({ error: { code: "EXPIRED" } }, 410));
    expect((await flow.telegramPollTick("e".repeat(64))).status).toBe("expired");
  });
});
