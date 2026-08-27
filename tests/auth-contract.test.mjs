import test from "node:test";
import assert from "node:assert/strict";
import { createAuth } from "../src/index.js";

const env = {
  OIDC_DISCOVERY_URL: "https://issuer.example/.well-known/openid-configuration",
  OIDC_CLIENT_ID: "client-id",
  OIDC_CLIENT_SECRET: "client-secret",
  AUTH_SESSION_SECRET: "a-secret-at-least-32-bytes-long-123",
};

function request(path, init = {}) {
  return new Request(`https://site.example${path}`, init);
}

test("shared route contract exposes unauthenticated API behavior", async () => {
  const auth = createAuth({ publicPaths: ["/", "/health", "/api/public/"] });
  const me = await auth.handle(request("/api/me"), env);
  assert.equal(me.status, 200);
  assert.deepEqual(await me.json(), { user: null });

  const protectedResponse = await auth.handle(request("/api/private"), env);
  assert.equal(protectedResponse.status, 401);

  assert.equal(await auth.handle(request("/api/public/catalog"), env), null);
});

test("mutating requests require same-origin protection", async () => {
  const auth = createAuth({ publicPaths: ["/"], allowedOrigins: ["https://admin.example"] });
  assert.equal((await auth.handle(request("/api/private", { method: "POST" }), env)).status, 403);
  assert.equal((await auth.handle(request("/api/private", { method: "POST", headers: { Origin: "https://evil.example" } }), env)).status, 403);
  assert.equal(await auth.handle(request("/api/private", { method: "POST", headers: { Origin: "https://site.example" } }), env).then((response) => response.status), 401);
});

test("login uses provider discovery and PKCE", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input) => {
    assert.equal(String(input), "https://issuer.example/.well-known/openid-configuration");
    return Response.json({
      issuer: "https://issuer.example/",
      authorization_endpoint: "https://issuer.example/authorize",
      token_endpoint: "https://issuer.example/token",
      jwks_uri: "https://issuer.example/keys",
    });
  };
  try {
    const auth = createAuth({ publicPaths: ["/"] });
    const response = await auth.handle(request("/auth/login?return_to=https%3A%2F%2Fevil.example"), env);
    assert.equal(response.status, 302);
    const location = new URL(response.headers.get("Location"));
    assert.equal(location.origin, "https://issuer.example");
    assert.equal(location.searchParams.get("code_challenge_method"), "S256");
    assert.ok(location.searchParams.get("nonce"));
    assert.match(response.headers.get("Set-Cookie"), /__Host-cfgenai_state=/);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("rejects unsafe cookie prefixes", () => {
  assert.throws(() => createAuth({ cookiePrefix: "bad; Domain=evil.example" }), /cookiePrefix/);
});

test("authorize hook can restrict an authenticated route", async () => {
  const auth = createAuth({ publicPaths: ["/"], authorize: ({ user }) => user.email === "admin@example.com" });
  const response = await auth.handle(request("/admin"), env);
  assert.equal(response.status, 302);
});

test("valid signed sessions do not throw during authorization", async () => {
  const payload = btoa(JSON.stringify({ sub: "subject", exp: Math.floor(Date.now() / 1000) + 300 })).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(env.AUTH_SESSION_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload))))).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
  const auth = createAuth({ publicPaths: ["/"], authorize: () => false });
  const response = await auth.handle(request("/admin", { headers: { Cookie: `__Host-cfgenai_session=${payload}.${signature}` } }), env);
  assert.equal(response.status, 403);
});
