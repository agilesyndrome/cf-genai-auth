# Auth contract

`createAuth(options)` returns `{ handle, getUser, middleware }`. Use `features: [auth]` with cf-genai-base; the legacy `auth: auth.handle` form remains supported.

`handle(request, env)` returns a `Response` when it owns the request and `null`
when the site router should continue. It owns the reserved auth routes and
`/api/me`, and returns 401 for protected API calls without a valid session.
Browser requests are redirected to login. `getUser` returns the normalized
session user or `null`. With `persistUser: true`, the returned user also has an
`authUser` property containing the canonical `auth_users` record from
cf-genai-base.

`loginAuthorize({ user, request, env })` runs after optional persistence during
OIDC callback handling. Return `false` for the standard forbidden response or
throw an error with a status to reject the login explicitly.

The default session is an HMAC-signed, host-only cookie. This is suitable for small sites and staging isolation. Set `delegateAdmin: true` when the provider is composed with the base admin boundary. Sites requiring revocation, multi-device
logout, or durable sessions can provide `createSession`, `getSession`, and
`revokeSession` adapters. The adapter receives the opaque cookie token and owns
its D1 or other binding-backed persistence.
