package github

// EndpointPermission documents one GitHub endpoint we call and the
// fine-grained token permission it needs. It feeds the /about page;
// docs/permissions.md holds the same table (a test keeps them in sync).
type EndpointPermission struct {
	Endpoint    string
	Permission  string
	FineGrained bool   // listed as available to fine-grained PATs
	UsedFor     string // which normalized attributes come from it
}

// Endpoints is the complete list of GitHub calls Plumbline makes. Every one is
// a GET, and every permission is read-only.
var Endpoints = []EndpointPermission{
	{epOrg, "None listed (owner-only fields need an org owner's token)", true,
		"org: two_factor_required, default_repo_permission, members_can_create_public_repos"},
	{epMembers, "Organization › Members: Read", true, "user list (members)"},
	{epAdmins, "Organization › Members: Read", true, "user: is_admin"},
	{epMembersNoMFA, "Organization › Members: Read (filter is owner-only)", true, "user: mfa_enabled (members)"},
	{epOutside, "Organization › Members: Read", true, "user list (outside collaborators)"},
	{epOutsideNoMFA, "Organization › Members: Read", true, "user: mfa_enabled (outside collaborators)"},
	{epRepos, "Repository › Metadata: Read", true,
		"repo list, visibility, default_branch; secret_scanning (only returned to repo admins / org owners)"},
	{epProtection, "Repository › Administration: Read", true, "repo: default_branch_protected"},
	{epHooks, "Organization › Webhooks: Read", true, "webhook: url_scheme, insecure_ssl, has_secret"},
}
