# `@easleyowl/cf-genai-auth`

Shared Cloudflare Worker OIDC authentication. It provides `/auth/login`,
`/auth/callback`, `/auth/logout`, and `/api/me`, protects API/browser routes,
uses Authorization Code + PKCE, verifies RS256 ID tokens against the provider's
JWKS, and stores only a short-lived signed session cookie in the browser.

Required Worker vars/secrets are `OIDC_DISCOVERY_URL`, `OIDC_CLIENT_ID`,
`OIDC_CLIENT_SECRET`, and `AUTH_SESSION_SECRET`. The discovery document supplies
the issuer used for token validation. `OIDC_ISSUER` remains supported as a
backward-compatible fallback and is used to construct the standard discovery
URL. Override names with
`createAuth({ env: { issuer, clientId, clientSecret, sessionSecret } })`.

```js
const auth = createAuth({ publicPaths: ["/", "/api/public/"] });
export default createWorker({ auth: auth.handle, fetch: router });
```

The standard cookie is host-only and `Secure`; use a distinct `cookiePrefix`
when multiple environments share a browser. Authorization, admin roles, and
site-specific user records remain application concerns.

## Authorization

Pass `authorize({ request, url, user, env })` to `createAuth` when a site needs
role or route-level access control. Return `true` to continue or `false` for a
403 response. Keep the policy in the site initializer; the library does not
assume how roles are stored.
