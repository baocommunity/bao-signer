import Fastify from "fastify";
import { baoSignerAuthRoutes, MemorySignerStorage } from "../src/server/index.ts";

const app = Fastify({ logger: false });
const storage = new MemorySignerStorage();
await app.register(baoSignerAuthRoutes, {
  storage,
  rpId: "localhost",
  expectedOrigins: ["http://localhost:3000"],
  backupSecret: "smoke-secret",
});
await app.listen({ port: 0 });
const { port } = app.server.address();
const base = `http://127.0.0.1:${port}`;

const r1 = await fetch(`${base}/auth/passkey/register-options`, {
  method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ username: "smoke" }),
});
const j1 = await r1.json();
console.log("register-options:", r1.status, "challengeId?", !!j1.challengeId, "rp:", j1.options?.rp?.id, "uv:", j1.options?.authenticatorSelection?.userVerification);

const r2 = await fetch(`${base}/auth/passkey/login-options`, { method: "POST" });
const j2 = await r2.json();
console.log("login-options:", r2.status, "challengeId?", !!j2.challengeId, "uv:", j2.options?.userVerification);

// challenge must be single-use: unknown challengeId → 400
const r3 = await fetch(`${base}/auth/passkey/login`, {
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ challengeId: "unknown", credential: { id: "x", response: {} } }),
});
console.log("unknown challenge rejected:", r3.status === 400, (await r3.json()).error?.code);

await app.close();
console.log("SMOKE OK");
