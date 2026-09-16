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
export default createWorker({ features: [auth], fetch: router });
```

The standard cookie is host-only and `Secure`; use a distinct `cookiePrefix`
when multiple environments share a browser. Authorization policy remains an
application concern, while sites using cf-genai-base can opt into canonical
user persistence:

```js
const auth = createAuth({ persistUser: true });
```

With `persistUser`, `getUser` returns the normalized identity plus `authUser`,
the `auth_users` record maintained by cf-genai-base. This keeps site code from
reimplementing user lookups and lets base authorization reuse the hydrated row.

## Authorization

Pass `authorize({ request, url, user, env })` to `createAuth` when a site needs
role or route-level access control. Return `true` to continue or `false` for a
403 response. Keep the policy in the site initializer; the library does not
assume how roles are stored.

Use `loginAuthorize({ user, request, env })` for a policy that must run after a
new identity has been persisted. This is useful for application circuit
breakers or enrollment rules. Throw an auth error to reject the login or return
`false` to receive the standard 403 response.
