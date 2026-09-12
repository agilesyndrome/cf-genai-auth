# Architecture

cf-genai-auth is the first reusable feature layered onto cf-genai-base. It owns
provider-neutral OIDC authorization-code + PKCE flow, cookie/state handling,
ID-token verification, provider-specific protected-route middleware, and the /api/me contract. With `delegateAdmin: true`, it leaves `/admin` and `/api/admin` to cf-genai-base.

## Runtime model

createAuth returns handle, getUser, and middleware. The middleware owns reserved auth routes, applies same-origin protection to mutations, loads the current session, and either short-circuits or calls the next site handler. `delegateAdmin` lets the base own the reserved admin namespaces.

The default session is an HMAC-signed host-only cookie. Applications that need
revocation or durable sessions may provide createSession, getSession, and
revokeSession adapters. GTA uses those hooks for opaque D1-backed sessions;
Cookbook uses the default signed session.

OIDC discovery and JWKS responses are cached at module scope because they are
provider metadata, not request state. Secrets remain in Worker environment
bindings. Cryptographic operations use Web Crypto.

## Repository layout

- src/index.js: auth feature and OIDC implementation.
- tests/: auth contract and security tests.
- CONTRACT.md: stable module integration contract.
- @agilesyndrome/cf-genai-cli: shared local project and release lifecycle.
- .github/workflows/publish.yml: tag-driven npm Trusted Publishing.

## Build and release

    npx --yes @agilesyndrome/cf-genai-cli@0.1.3 ci
    npx --yes @agilesyndrome/cf-genai-cli@0.1.3 release

Publish cf-genai-base before publishing auth when auth relies on a new base
contract. After auth is available on npm, consumers can regenerate lockfiles
and deploy.

The publish workflow uses GitHub OIDC/npm provenance. It validates tests and
package contents before publishing; no npm token is stored in the repository.
