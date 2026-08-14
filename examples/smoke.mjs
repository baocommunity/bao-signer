/**
 * Live smoke test — boots a real Fastify server with ALL login methods and
 * exercises the unauthenticated endpoints end-to-end.
 *
 * Run: node examples/smoke.mjs   (Node ≥ 22.18, native TS support)
 */
import Fastify from "fastify";
import {
  baoSignerAuthRoutes,
  nip98ChallengeRoutes,
  guestAuthRoutes,
  nostrAuthRoutes,
  lnurlAuthRoutes,
  emailAuthRoutes,
  telegramAuthRoutes,
  MemorySignerStorage,
} from "../src/server/index.ts";

const app = Fastify({ logger: false });
const storage = new MemorySignerStorage();
const SECRET = "smoke-secret";
const rateLimit = { max: 100, timeWindow: "1 minute" };

await app.register(baoSignerAuthRoutes, {
  storage,
  rpId: "localhost",
  expectedOrigins: ["http://localhost:3000"],
  backupSecret: SECRET,
  rateLimit,
  authenticate: async (req) => {
    const token = req.headers.authorization?.replace(/^Bearer /, "");
    const session = token ? await storage.getSession(token) : undefined;
    return session?.pubkey ?? null;
  },
});
await app.register(nip98ChallengeRoutes, { rateLimit });
await app.register(guestAuthRoutes, { storage, rateLimit });
await app.register(nostrAuthRoutes, { storage, rateLimit });
await app.register(lnurlAuthRoutes, {
  storage,
  publicBaseUrl: "http://localhost:3000/v1",
  secret: SECRET,
  rateLimit,
});
await app.register(emailAuthRoutes, {
  storage,
  backupSecret: SECRET,
  sendEmail: async (to, code) => console.log(`  [smtp stub] OTP for ${to}: ${code}`),
  rateLimit,
});
await app.register(telegramAuthRoutes, {
  storage,
  botToken: "smoke-bot-token",
  botUsername: "SmokeBot",
  backupSecret: SECRET,
  rateLimit,
});

await app.listen({ port: 0 });
const { port } = app.server.address();
const base = `http://127.0.0.1:${port}`;
const post = (path, body) =>
  fetch(`${base}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });

let pass = 0;
const check = (name, ok) => {
  console.log(`${ok ? "✅" : "❌"} ${name}`);
  if (ok) pass++;
};

// Passkey
const r1 = await post("/auth/passkey/register-options", { username: "smoke" });
const j1 = await r1.json();
check("passkey register-options", r1.status === 200 && !!j1.challengeId && j1.options?.authenticatorSelection?.userVerification === "required");

// NIP-98 challenge
const r2 = await fetch(`${base}/auth/challenge`);
check("nip98 challenge", r2.status === 200 && !!(await r2.json()).challenge);

// LNURL
const r3 = await fetch(`${base}/auth/lnurl`);
const j3 = await r3.json();
check("lnurl challenge", r3.status === 200 && j3.lnurl?.startsWith("lnurl1") && /^[0-9a-f]{64}$/.test(j3.k1));

// Email OTP (captured by the stub above)
const r4 = await post("/auth/email/request", { email: "smoke@example.com" });
check("email otp request", r4.status === 200 && (await r4.json()).sent === true);

// Telegram config
const r5 = await fetch(`${base}/auth/telegram/config`);
const j5 = await r5.json();
check("telegram config", r5.status === 200 && j5.configured === true && j5.botUsername === "SmokeBot");

await app.close();
console.log(pass === 5 ? "SMOKE OK (5/5)" : `SMOKE FAILED (${pass}/5)`);
process.exit(pass === 5 ? 0 : 1);
