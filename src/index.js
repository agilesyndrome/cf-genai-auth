const encoder = new TextEncoder();
const decoder = new TextDecoder();
const configurationCache = new Map();
const configurationRequests = new Map();
const jwksCache = new Map();
const jwksRequests = new Map();
const OIDC_CACHE_MS = 15 * 60 * 1000;
const OIDC_TIMEOUT_MS = 10_000;

/**
 * Generic OIDC auth for Workers. It uses Authorization Code + PKCE and a
 * signed, host-only cookie, so a site needs no auth service of its own.
 * Site-specific roles can be derived from `claims` in `onLogin`.
 */
export function createAuth(options = {}) {
  const prefix = options.cookiePrefix || "__Host-cfgenai";
  if (!/^(?:__Host-)?[A-Za-z0-9_-]+$/.test(prefix)) throw new Error("cookiePrefix contains invalid characters");
  const names = { state: `${prefix}_state`, session: `${prefix}_session` };
  const publicPaths = options.publicPaths || ["/auth/", "/favicon.svg", "/robots.txt", "/health"];
  const protectedPath = options.protectedPath || (() => true);
  const envName = (key, fallback) => options.env?.[key] || fallback;

  return {
    async handle(request, env) {
      const url = new URL(request.url);
      if (url.pathname === "/auth/login") return login(request, env);
      if (url.pathname === "/auth/callback") return callback(request, env);
      if (url.pathname === "/auth/logout") return logout(request, env, names.session);
      if (url.pathname === "/api/me") return Response.json({ user: await getUser(request, env, envName("sessionSecret", "AUTH_SESSION_SECRET"), names.session) }, { headers: { "Cache-Control": "no-store" } });
      if (!protectedPath(url.pathname) || publicPaths.some((path) => path === "/" ? url.pathname === "/" : url.pathname.startsWith(path))) return null;
      if (isMutation(request)) { const originResponse = checkOrigin(request, options.allowedOrigins); if (originResponse) return originResponse; }
      const user = await getUser(request, env, envName("sessionSecret", "AUTH_SESSION_SECRET"), names.session);
      if (user) return null;
      if (url.pathname.startsWith("/api/")) return Response.json({ error: "Authentication is required." }, { status: 401, headers: { "Cache-Control": "no-store" } });
      return Response.redirect(`${url.origin}/auth/login?return_to=${encodeURIComponent(safeReturnTo(url.pathname + url.search))}`, 302);
    },
    getUser: (request, env) => getUser(request, env, envName("sessionSecret", "AUTH_SESSION_SECRET"), names.session),
  };

  async function login(request, env) {
    const config = await configuration(env, envName("issuer", "OIDC_ISSUER"));
    const state = random();
    const verifier = random();
    const nonce = random();
    const challenge = base64url(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(verifier))));
    const returnTo = safeReturnTo(new URL(request.url).searchParams.get("return_to") || "/");
    const stateValue = `${state}.${verifier}.${nonce}.${base64url(encoder.encode(returnTo))}`;
    const authorize = new URL(config.authorization_endpoint);
    authorize.search = new URLSearchParams({ client_id: required(env, envName("clientId", "OIDC_CLIENT_ID")), response_type: "code", redirect_uri: callbackUrl(request), scope: options.scope || "openid profile email", state, code_challenge: challenge, code_challenge_method: "S256", nonce }).toString();
    return redirect(authorize, [cookie(names.state, stateValue, 600)]);
  }

  async function callback(request, env) {
    const url = new URL(request.url);
    const value = cookies(request)[names.state] || "";
    const [state, verifier, nonce, encodedReturn] = value.split(".");
    if (!state || !constantTimeEqual(state, url.searchParams.get("state") || "") || !verifier) return authError("The sign-in state was invalid or expired.", 400);
    const config = await configuration(env, envName("issuer", "OIDC_ISSUER"));
    const clientId = required(env, envName("clientId", "OIDC_CLIENT_ID"));
    const token = await fetchWithTimeout(config.token_endpoint, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ client_id: clientId, client_secret: required(env, envName("clientSecret", "OIDC_CLIENT_SECRET")), grant_type: "authorization_code", code: url.searchParams.get("code") || "", redirect_uri: callbackUrl(request), code_verifier: verifier }) }).then((response) => response.ok ? response.json() : Promise.reject(new Error("OIDC token exchange failed")));
    const claims = await verify(token.id_token, config, clientId, nonce);
    if (!claims.sub) return authError("The identity provider returned no subject.", 502);
    const user = await (options.onLogin ? options.onLogin(claims, env) : normalizeUser(claims));
    const signed = await sign(JSON.stringify({ ...user, exp: Math.floor(Date.now() / 1000) + (options.sessionSeconds || 28800) }), env, envName("sessionSecret", "AUTH_SESSION_SECRET"));
    return redirect(`${url.origin}${decodeReturn(encodedReturn)}`, [cookie(names.session, signed, options.sessionSeconds || 28800), clearCookie(names.state)]);
  }
}

async function getUser(request, env, secretName = "AUTH_SESSION_SECRET", sessionName = "__Host-cfgenai_session") {
  const token = cookies(request)[sessionName];
  if (!token) return null;
  const [payload, signature] = token.split(".");
  if (!payload || !signature || !constantTimeEqual(signature, await sign(payload, env, secretName, false))) return null;
  if (typeof user.exp !== "number") return null;
  try { const user = JSON.parse(decoder.decode(decode(payload))); return user.exp > Date.now() / 1000 ? user : null; } catch { return null; }
}

async function configuration(env, key) {
  const issuer = required(env, key).replace(/\/+$/, "") + "/";
  const cached = configurationCache.get(issuer); if (cached && cached.exp > Date.now()) return cached.value;
  const existing = configurationRequests.get(issuer); if (existing) return existing;
  const request = fetchWithTimeout(issuer + ".well-known/openid-configuration").then(async (response) => {
    if (!response.ok) throw new Error("Unable to load OIDC configuration");
    const value = await response.json();
    if (normalizeIssuer(value.issuer || "") !== issuer) throw new Error("OIDC issuer mismatch");
    configurationCache.set(issuer, { value, exp: Date.now() + OIDC_CACHE_MS }); return value;
  }).finally(() => configurationRequests.delete(issuer));
  configurationRequests.set(issuer, request); return request;
}
async function verify(token, config, clientId, expectedNonce) {
  const [head, body, signature] = String(token || "").split("."); if (!head || !body || !signature) throw new Error("Malformed ID token");
  const header = JSON.parse(decoder.decode(decode(head))); if (header.alg !== "RS256" || !header.kid) throw new Error("Unsupported ID token signature"); const keys = await getJwks(config.jwks_uri); const jwk = keys.keys.find((key) => key.kid === header.kid); if (!jwk) throw new Error("ID token signing key was not found");
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  if (!await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, decode(signature), encoder.encode(`${head}.${body}`))) throw new Error("Invalid ID token");
  const claims = JSON.parse(decoder.decode(decode(body))); const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud]; const validAzp = !Array.isArray(claims.aud) || claims.aud.length < 2 || claims.azp === clientId;
  if (normalizeIssuer(claims.iss || "") !== normalizeIssuer(config.issuer || "") || !aud.includes(clientId) || !validAzp || claims.exp <= Date.now() / 1000 || claims.nonce !== expectedNonce || !claims.sub) throw new Error("Invalid ID token claims"); return claims;
}
async function getJwks(uri) {
  const cached = jwksCache.get(uri); if (cached && cached.exp > Date.now()) return cached.value;
  const existing = jwksRequests.get(uri); if (existing) return existing;
  const request = fetchWithTimeout(uri).then(async (response) => { if (!response.ok) throw new Error("Unable to load OIDC signing keys"); const value = await response.json(); jwksCache.set(uri, { value, exp: Date.now() + OIDC_CACHE_MS }); return value; }).finally(() => jwksRequests.delete(uri));
  jwksRequests.set(uri, request); return request;
}
async function fetchWithTimeout(input, init = {}) { return fetch(input, { ...init, signal: AbortSignal.timeout(OIDC_TIMEOUT_MS) }); }
function normalizeIssuer(value) { return String(value).replace(/\/+$/, "") + "/"; }
function isMutation(request) { return ["POST", "PUT", "PATCH", "DELETE"].includes(request.method); }
function checkOrigin(request, allowedOrigins = []) {
  const origin = request.headers.get("Origin"); if (!origin) return authError("A same-origin request is required.", 403);
  try { const requestOrigin = new URL(request.url).origin; const originUrl = new URL(origin); const allowed = originUrl.origin === requestOrigin || allowedOrigins.includes(originUrl.origin); return allowed ? null : authError("This request did not pass the same-origin check.", 403); } catch { return authError("This request did not pass the same-origin check.", 403); }
}
async function sign(value, env, name, encoded = true) { const secret = required(env, name); if (name === "AUTH_SESSION_SECRET" && secret.length < 32) throw new Error("AUTH_SESSION_SECRET must be at least 32 characters"); const data = encoded ? base64url(encoder.encode(value)) : value; const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]); const sig = base64url(new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(data)))); return encoded ? `${data}.${sig}` : sig; }
function normalizeUser(claims) { return { sub: claims.sub, email: String(claims.email || "").toLowerCase(), name: claims.name || claims.email || claims.sub }; }
function required(env, key) { if (!env[key] || String(env[key]).startsWith("replace-with-")) throw new Error(`${key} is not configured`); return String(env[key]); }
function random() { const bytes = new Uint8Array(32); crypto.getRandomValues(bytes); return base64url(bytes); }
function base64url(bytes) { let s = ""; for (const b of bytes) s += String.fromCharCode(b); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
function decode(value) { return Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4)), (c) => c.charCodeAt(0)); }
function cookies(request) { return Object.fromEntries((request.headers.get("Cookie") || "").split(";").flatMap((part) => { const i = part.indexOf("="); return i < 0 ? [] : [[part.slice(0, i).trim(), part.slice(i + 1).trim()]]; })); }
function cookie(name, value, age) { return `${name}=${value}; Max-Age=${age}; Path=/; HttpOnly; Secure; SameSite=Lax`; }
function clearCookie(name) { return `${name}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax`; }
function redirect(location, setCookies) { const response = new Response(null, { status: 302, headers: { Location: String(location), "Cache-Control": "no-store" } }); for (const value of setCookies) response.headers.append("Set-Cookie", value); return response; }
function logout(request, env, name) { const response = redirect(new URL(request.url).origin + "/", [clearCookie(name)]); return response; }
function authError(message, status) { return new Response(message, { status, headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" } }); }
function callbackUrl(request) { return `${new URL(request.url).origin}/auth/callback`; }
function safeReturnTo(value) { return value?.startsWith("/") && !value.startsWith("//") && !value.startsWith("/auth/") ? value : "/"; }
function decodeReturn(value) { try { return safeReturnTo(decoder.decode(decode(value))); } catch { return "/"; } }
function constantTimeEqual(a, b) { const aa = encoder.encode(a), bb = encoder.encode(b); let n = aa.length ^ bb.length; for (let i = 0; i < Math.max(aa.length, bb.length); i++) n |= (aa[i] || 0) ^ (bb[i] || 0); return n === 0; }
