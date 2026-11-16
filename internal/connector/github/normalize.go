package github

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/Rahul03082001/plumbline-sspm/internal/model"
)

// The raw* structs mirror only the parts of GitHub's JSON we use. Pointer
// fields (*bool, *string) let us tell "false" apart from "null/absent":
// a nil pointer means GitHub didn't tell us, so the attribute is unknown.

type rawOrg struct {
	ID                                 int64   `json:"id"`
	Login                              string  `json:"login"`
	TwoFactorRequirementEnabled        *bool   `json:"two_factor_requirement_enabled"`
	DefaultRepositoryPermission        *string `json:"default_repository_permission"`
	MembersCanCreatePublicRepositories *bool   `json:"members_can_create_public_repositories"`
}

type rawUser struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
}

type rawRepo struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	Visibility    string `json:"visibility"`
	DefaultBranch string `json:"default_branch"`
	Owner         struct {
		Login string `json:"login"`
	} `json:"owner"`
	SecurityAndAnalysis *struct {
		SecretScanning *struct {
			Status string `json:"status"`
		} `json:"secret_scanning"`
	} `json:"security_and_analysis"`
}

type rawHook struct {
	ID     int64 `json:"id"`
	Config *struct {
		URL         string  `json:"url"`
		InsecureSSL any     `json:"insecure_ssl"` // GitHub sends "0"/"1" (sometimes a number)
		Secret      *string `json:"secret"`       // present (masked "********") only when set
	} `json:"config"`
}

// Endpoint patterns, used in evidence, metrics and logs. Patterns never
// contain real org/repo names or query values.
const (
	epOrg          = "GET /orgs/{org}"
	epMembers      = "GET /orgs/{org}/members"
	epAdmins       = "GET /orgs/{org}/members?role=admin"
	epMembersNoMFA = "GET /orgs/{org}/members?filter=2fa_disabled"
	epOutside      = "GET /orgs/{org}/outside_collaborators"
	epOutsideNoMFA = "GET /orgs/{org}/outside_collaborators?filter=2fa_disabled"
	epRepos        = "GET /orgs/{org}/repos"
	epProtection   = "GET /repos/{owner}/{repo}/branches/{branch}/protection"
	epHooks        = "GET /orgs/{org}/hooks"
)

func unknownBecause(reason, endpoint string) model.UnknownReason {
	return model.UnknownReason{Reason: reason, Endpoint: endpoint}
}

// normalizeOrg turns GET /orgs/{org} into the org asset.
func normalizeOrg(body []byte) (model.Asset, error) {
	var o rawOrg
	if err := json.Unmarshal(body, &o); err != nil {
		return model.Asset{}, fmt.Errorf("decode org: %w", err)
	}
	a := model.Asset{
		Kind:       model.KindOrg,
		ExternalID: strconv.FormatInt(o.ID, 10),
		Name:       o.Login,
		Attributes: model.Attributes{},
		Unknown:    map[string]model.UnknownReason{},
	}
	// Owner-only fields come back null for non-owners: null = unknown.
	setBool(&a, "two_factor_required", o.TwoFactorRequirementEnabled, epOrg)
	if o.DefaultRepositoryPermission != nil {
		a.Attributes["default_repo_permission"] = *o.DefaultRepositoryPermission
	} else {
		a.Unknown["default_repo_permission"] = unknownBecause(model.ReasonFieldNotReturned, epOrg)
	}
	setBool(&a, "members_can_create_public_repos", o.MembersCanCreatePublicRepositories, epOrg)
	return a, nil
}

func setBool(a *model.Asset, key string, v *bool, endpoint string) {
	if v == nil {
		a.Unknown[key] = unknownBecause(model.ReasonFieldNotReturned, endpoint)
		return
	}
	a.Attributes[key] = *v
}

// loginSet is a listing turned into a set of logins, plus how complete it is.
type loginSet struct {
	logins   map[string]bool
	status   string
	reason   string
	endpoint string
}

func toLoginSet(l listing) (loginSet, error) {
	s := loginSet{logins: map[string]bool{}, status: l.status, reason: l.reason, endpoint: l.endpoint}
	for _, raw := range l.items {
		var u rawUser
		if err := json.Unmarshal(raw, &u); err != nil {
			return s, fmt.Errorf("decode user: %w", err)
		}
		s.logins[u.Login] = true
	}
	return s, nil
}

// membership answers "is login in this set?" with three values:
// in the set -> (true, known); complete listing and not in it -> (false, known);
// incomplete listing and not in it -> unknown (they might be on a page we missed).
func (s loginSet) membership(login string) (in bool, known bool) {
	if s.logins[login] {
		return true, true
	}
	return false, s.status == "complete"
}

// normalizeUsers builds user assets from members + outside collaborators.
// admins / noMFA / outsideNoMFA are the filtered listings used for flags.
func normalizeUsers(members, outside []rawUser, admins, noMFA, outsideNoMFA loginSet) []model.Asset {
	var out []model.Asset
	add := func(u rawUser, isOutside bool) {
		a := model.Asset{
			Kind:       model.KindUser,
			ExternalID: strconv.FormatInt(u.ID, 10),
			Name:       u.Login,
			Attributes: model.Attributes{"login": u.Login, "is_outside_collaborator": isOutside},
			Unknown:    map[string]model.UnknownReason{},
		}
		mfaSet := noMFA
		if isOutside {
			// Outside collaborators are not org members, so they can't be
			// org owners: is_admin is known to be false.
			a.Attributes["is_admin"] = false
			mfaSet = outsideNoMFA
		} else if in, known := admins.membership(u.Login); known {
			a.Attributes["is_admin"] = in
		} else {
			a.Unknown["is_admin"] = unknownBecause(admins.reason, admins.endpoint)
		}
		// The listing is "users WITHOUT 2FA", so being in it means mfa=false.
		if in, known := mfaSet.membership(u.Login); known {
			a.Attributes["mfa_enabled"] = !in
		} else {
			a.Unknown["mfa_enabled"] = unknownBecause(mfaSet.reason, mfaSet.endpoint)
		}
		out = append(out, a)
	}
	for _, u := range members {
		add(u, false)
	}
	for _, u := range outside {
		add(u, true)
	}
	return out
}

// protection is the outcome of one branch-protection lookup.
type protection struct {
	protected *bool
	reason    string // set when protected is nil
}

// normalizeRepos builds repo assets. prot[i] belongs to repos[i].
func normalizeRepos(repos []rawRepo, prot []protection) []model.Asset {
	out := make([]model.Asset, 0, len(repos))
	for i, r := range repos {
		a := model.Asset{
			Kind:       model.KindRepo,
			ExternalID: strconv.FormatInt(r.ID, 10),
			Name:       r.Name,
			Attributes: model.Attributes{},
			Unknown:    map[string]model.UnknownReason{},
		}
		if r.Visibility != "" {
			a.Attributes["visibility"] = r.Visibility
		} else {
			a.Unknown["visibility"] = unknownBecause(model.ReasonFieldNotReturned, epRepos)
		}
		if r.DefaultBranch != "" {
			a.Attributes["default_branch"] = r.DefaultBranch
		} else {
			a.Unknown["default_branch"] = unknownBecause(model.ReasonFieldNotReturned, epRepos)
		}
		// security_and_analysis is only returned to repo admins / org owners.
		if r.SecurityAndAnalysis != nil && r.SecurityAndAnalysis.SecretScanning != nil {
			a.Attributes["secret_scanning"] = r.SecurityAndAnalysis.SecretScanning.Status == "enabled"
		} else {
			a.Unknown["secret_scanning"] = unknownBecause(model.ReasonFieldNotReturned, epRepos)
		}
		if p := prot[i]; p.protected != nil {
			a.Attributes["default_branch_protected"] = *p.protected
		} else {
			a.Unknown["default_branch_protected"] = unknownBecause(p.reason, epProtection)
		}
		out = append(out, a)
	}
	return out
}

// normalizeHooks builds webhook assets.
func normalizeHooks(hooks []rawHook) []model.Asset {
	out := make([]model.Asset, 0, len(hooks))
	for _, h := range hooks {
		a := model.Asset{
			Kind:       model.KindWebhook,
			ExternalID: strconv.FormatInt(h.ID, 10),
			Name:       fmt.Sprintf("hook %d", h.ID),
			Attributes: model.Attributes{},
			Unknown:    map[string]model.UnknownReason{},
		}
		if h.Config == nil {
			for _, k := range []string{"url_scheme", "insecure_ssl", "has_secret"} {
				a.Unknown[k] = unknownBecause(model.ReasonFieldNotReturned, epHooks)
			}
			out = append(out, a)
			continue
		}
		// Store only scheme://host. Webhook URLs often carry secrets in the
		// path or query (Slack-style tokens), and we never want those in our
		// database, logs, or public UI.
		if u, err := url.Parse(h.Config.URL); err == nil && u.Scheme != "" && u.Host != "" {
			a.Attributes["url_scheme"] = strings.ToLower(u.Scheme)
			a.Name = strings.ToLower(u.Scheme) + "://" + u.Host
		} else {
			a.Unknown["url_scheme"] = unknownBecause(model.ReasonFieldNotReturned, epHooks)
		}
		if v, ok := parseInsecureSSL(h.Config.InsecureSSL); ok {
			a.Attributes["insecure_ssl"] = v
		} else {
			a.Unknown["insecure_ssl"] = unknownBecause(model.ReasonFieldNotReturned, epHooks)
		}
		// GitHub masks a set secret as "********" and omits it when unset.
		a.Attributes["has_secret"] = h.Config.Secret != nil && *h.Config.Secret != ""
		out = append(out, a)
	}
	return out
}

// parseInsecureSSL accepts "0"/"1" strings or 0/1 numbers. Anything else is
// unknown rather than guessed.
func parseInsecureSSL(v any) (bool, bool) {
	switch x := v.(type) {
	case string:
		switch x {
		case "0":
			return false, true
		case "1":
			return true, true
		}
	case float64: // encoding/json decodes every JSON number into float64
		switch x {
		case 0:
			return false, true
		case 1:
			return true, true
		}
	}
	return false, false
}
