/**
 * bao-signer — local preview/demo server.
 *
 * Boots a real Fastify server with every auth plugin registered (in-memory
 * storage + stub secrets) and serves a small index page describing the
 * library and the endpoints it exposes.
 *
 * Run: node examples/preview.mjs
 * Binds 0.0.0.0:PORT (default 8787) so it works inside a Freebuff preview.
 *
 * NOTE: this is a dev-only demo. Real deployments inject their own secrets,
 * storage backend, RP id/origins, and email sender via plugin options.
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

const PORT = Number(process.env.PORT || 8787);
const HOST = "0.0.0.0";

const app = Fastify({ logger: false });
const storage = new MemorySignerStorage();
const SECRET = "preview-dev-secret"; // dev only — never hardcode in production
const rateLimit = { max: 100, timeWindow: "1 minute" };

await app.register(baoSignerAuthRoutes, {
  storage,
  rpId: "localhost",
  expectedOrigins: [`http://localhost:${PORT}`, `http://127.0.0.1:${PORT}`],
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
  publicBaseUrl: `http://localhost:${PORT}`,
  secret: SECRET,
  rateLimit,
});
await app.register(emailAuthRoutes, {
  storage,
  backupSecret: SECRET,
  sendEmail: async (to, code) => console.log(`[email stub] OTP for ${to}: ${code}`),
  rateLimit,
});
await app.register(telegramAuthRoutes, {
  storage,
  botToken: "preview-bot-token",
  botUsername: "baoPreviewBot",
  backupSecret: SECRET,
  rateLimit,
});

const endpoints = [
  ["POST /auth/passkey/register-options", "Passkey registration challenge"],
  ["POST /auth/passkey/register", "Verify attestation, create account"],
  ["POST /auth/passkey/login-options", "Passkey login challenge"],
  ["POST /auth/passkey/login", "Verify assertion, return session"],
  ["GET /auth/challenge", "NIP-98 challenge (guest / nostr login)"],
  ["GET /auth/lnurl", "Lightning wallet login challenge"],
  ["GET /auth/lnurl/poll", "Poll Lightning login status"],
  ["POST /auth/email/request", "Email OTP request"],
  ["POST /auth/email/verify", "Email OTP verify"],
  ["GET /auth/telegram/config", "Telegram login configuration"],
  ["POST /auth/telegram/verify", "Telegram Login Widget verify"],
];

const rows = endpoints
  .map(
    ([path, desc]) =>
      `<tr><td><code>${path}</code></td><td>${desc}</td></tr>`,
  )
  .join("");

const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>bao-signer — preview server</title>
<style>
  :root { color-scheme: light dark; }
  body {
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    max-width: 880px; margin: 0 auto; padding: 3rem 1.5rem;
    line-height: 1.6;
  }
  h1 { font-size: 1.6rem; }
  .muted { opacity: 0.65; }
  code { background: rgba(127,127,127,0.15); padding: 0.1rem 0.35rem; border-radius: 4px; }
  table { width: 100%; border-collapse: collapse; margin-top: 1.5rem; font-size: 0.85rem; }
  th, td { text-align: left; padding: 0.5rem 0.6rem; border-bottom: 1px solid rgba(127,127,127,0.3); vertical-align: top; }
  th { opacity: 0.6; font-weight: 600; }
</style>
</head>
<body>
  <h1>bao-signer <span class="muted">— preview server</span></h1>
  <p>
    Passkey-first Nostr signing and authentication. This demo boots every
    auth plugin against an in-memory store with stub secrets, so the
    unauthenticated endpoints below are live and callable.
  </p>
  <table>
    <thead><tr><th>Endpoint</th><th>Purpose</th></tr></thead>
    <tbody>${rows}</tbody>
  </table>
  <p class="muted">
    Dev/demo only. In production, inject real secrets, a PostgreSQL
    <code>SignerStorage</code> (see <code>schema.sql</code>), your RP id/origins,
    and an email sender hook.
  </p>
</body>
</html>`;

app.get("/", async (_request, reply) => {
  reply.type("text/html").send(html);
});

await app.listen({ port: PORT, host: HOST });
console.log(`bao-signer preview listening on http://${HOST}:${PORT}`);
