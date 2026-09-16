# Changelog

## 5.0.0

- Require cf-genai-base 5 and compose authentication as a feature.
- Persist every authenticated identity as a canonical base user.
- Stop serializing canonical authorization rows into session cookies.
- Return a minimal canonical identity from `/api/me`.
- Register the users and groups repositories by default.
- Use base's shared same-origin and secure response helpers.
- Remove the `persistUser` and `delegateAdmin` compatibility options.
