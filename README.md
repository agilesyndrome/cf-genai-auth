# `@easleyowl/cf-genai-auth`

Shared Cloudflare Worker OIDC authentication. It provides `/auth/login`,
`/auth/callback`, `/auth/logout`, and `/api/me`, protects API/browser routes,
uses Authorization Code + PKCE, verifies RS256 ID tokens against the provider's
JWKS, and stores only a short-lived signed session cookie in the browser.

Required Worker vars/secrets are `OIDC_ISSUER`, `OIDC_CLIENT_ID`,
`OIDC_CLIENT_SECRET`, and `AUTH_SESSION_SECRET`. Override names with
`createAuth({ env: { issuer, clientId, clientSecret, sessionSecret } })`.

```js
const auth = createAuth({ publicPaths: ["/", "/api/public/"] });
export default createWorker({ auth: auth.handle, fetch: router });
```

The standard cookie is host-only and `Secure`; use a distinct `cookiePrefix`
when multiple environments share a browser. Authorization, admin roles, and
site-specific user records remain application concerns.
