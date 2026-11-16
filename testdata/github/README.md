# Recorded GitHub responses

JSON bodies in GitHub's REST response shapes (API version 2022-11-28), modelled
on the test organization from spec section 7.1 (`plumbline-demo-org`):

- `api-service` has a protected `main`; `legacy-scripts` has no protection and
  secret scanning off.
- One webhook to `http://example.com/hook` with SSL verification disabled and no
  secret; one HTTPS webhook with a (masked) secret.
- 2FA not required; default repository permission `write`.

Used by `internal/connector/github` tests. Trimmed to the fields we read plus a
few neighbours for realism. No real tokens, IDs or URLs.
