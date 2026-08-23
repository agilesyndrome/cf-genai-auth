# Auth contract

`createAuth(options)` returns `{ handle, getUser }`.

`handle(request, env)` returns a `Response` when it owns the request and `null`
when the site router should continue. It owns the reserved auth routes and
`/api/me`, and returns 401 for protected API calls without a valid session.
Browser requests are redirected to login. `getUser` returns the normalized
session user or `null`.

The default session is an HMAC-signed, host-only cookie. This is suitable for
small sites and staging isolation. Sites requiring revocation, multi-device
logout, or durable sessions should add a session-store adapter before migration
rather than duplicating OAuth logic.
