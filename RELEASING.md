# Releasing

## One-time bootstrap

The package must exist on npm before npm allows a Trusted Publisher to be
configured. From this directory, run an interactive first publish:

```sh
npm publish --access public
```

Complete npm's account/2FA prompt. This publishes `0.1.0`.

## GitHub Actions releases

After the bootstrap publish, configure npm Trusted Publishing for this package:

- Provider: GitHub Actions
- Organization/user: `agilesyndrome`
- Repository: `cf-genai-auth`
- Workflow filename: `publish.yml`
- Environment: blank
- Allowed action: `npm publish`

For later releases, bump `version` in `package.json`, commit and push it to
`main`, then create and push a matching `v*` tag. The workflow runs tests and
publishes using GitHub OIDC; no npm token secret is required.
