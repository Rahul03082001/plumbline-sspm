# GitHub permissions (least privilege)

Plumbline's live connector uses a **fine-grained personal access token** with
**read-only** permissions, scoped to one organization. It only ever sends `GET`
requests (a test fails if it sends anything else).

Checked against GitHub's REST docs ("Permissions required for fine-grained
personal access tokens" and "Endpoints available for fine-grained personal
access tokens", API version `2022-11-28`) on 2026-11-15.

| Endpoint | Fine-grained permission | Supported for fine-grained PAT | Used for |
|---|---|---|---|
| `GET /orgs/{org}` | None listed. Full details are returned only to org owners | yes | org: `two_factor_required`, `default_repo_permission`, `members_can_create_public_repos` |
| `GET /orgs/{org}/members` | Organization › Members: **Read** | yes | user list (members) |
| `GET /orgs/{org}/members?role=admin` | Organization › Members: **Read** | yes | user: `is_admin` |
| `GET /orgs/{org}/members?filter=2fa_disabled` | Organization › Members: **Read** (the filter is owner-only) | yes | user: `mfa_enabled` (members) |
| `GET /orgs/{org}/outside_collaborators` | Organization › Members: **Read** | yes | user list (outside collaborators) |
| `GET /orgs/{org}/outside_collaborators?filter=2fa_disabled` | Organization › Members: **Read** | yes | user: `mfa_enabled` (outside collaborators) |
| `GET /orgs/{org}/repos` | Repository › Metadata: **Read** | yes | repo list, `visibility`, `default_branch`; `secret_scanning` (only returned to repo admins / org owners) |
| `GET /repos/{owner}/{repo}/branches/{branch}/protection` | Repository › Administration: **Read** | yes | repo: `default_branch_protected` |
| `GET /orgs/{org}/hooks` | Organization › Webhooks: **Read** | yes | webhook: `url_scheme`, `insecure_ssl`, `has_secret` |

## The token to create

Fine-grained PAT, **Resource owner = your org**, **All repositories**, expires in 90 days:

- Organization: **Members: Read**, **Webhooks: Read**, and (see below) **Administration: Read**
- Repository: **Metadata: Read** (added automatically), **Administration: Read**

## Things to verify with your real token

1. **Owner-only org fields.** GitHub doesn't list a permission for `GET /orgs/{org}`.
   Scan once *without* Organization › Administration: Read. If
   `two_factor_required` and `default_repo_permission` still come back (they will
   show as known on the org asset), drop that permission. Least privilege means
   not keeping a permission "just in case".
2. **`security_and_analysis`** on repos is only returned to repo admins / org owners.
   If it's missing, `secret_scanning` is unknown with reason `field_not_returned`.
   That's correct behaviour, not a bug.
3. **The 2FA filter** is owner-only. A non-owner token gets an error, and
   `mfa_enabled` becomes unknown with reason `permission_denied` (or
   `unprocessable` for a 422).

## Rule: never widen the token

If an endpoint needs write access or doesn't support fine-grained tokens, Plumbline
does **not** ask for more. The attribute is marked unknown
(`not_available_read_only`) and shows up in the "Unknown checks" table with its reason.
