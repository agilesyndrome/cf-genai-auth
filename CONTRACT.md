# Auth contract

`createAuth(options)` returns a base v5 feature with `handle`, `getUser`,
`middleware`, and the canonical auth repositories. Register it through
`features: [auth]`.

`handle(request, env)` returns a `Response` when it owns the request and `null`
when the site router should continue. It owns the reserved auth routes and
`/api/me`, and returns 401 for protected API calls without a valid session.
Browser requests are redirected to login. `getUser` returns the normalized
session user or `null`. Authenticated identities require the base `DB` binding
and always include an `authUser` property containing the current canonical
`auth_users` record. Canonical rows are never serialized into the session
cookie. `/api/me` exposes only `{ id, email, name, isAdmin }`.

`loginAuthorize({ user, request, env })` runs after optional persistence during
OIDC callback handling. Return `false` for the standard forbidden response or
throw an error with a status to reject the login explicitly.

`sessionAuthorize({ user, request, env })` runs after optional persistence for
existing sessions. Returning `false` causes the request to be treated as
unauthenticated.

The default session is an HMAC-signed, host-only cookie. This is suitable for small sites and staging isolation. Base owns the admin boundary. Sites requiring revocation, multi-device
logout, or durable sessions can provide `createSession`, `getSession`, and
`revokeSession` adapters. The adapter receives the opaque cookie token and owns
its D1 or other binding-backed persistence.
