package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"

	"golang.org/x/sync/errgroup"

	"github.com/Rahul03082001/plumbline-sspm/internal/connector"
	"github.com/Rahul03082001/plumbline-sspm/internal/model"
)

// protectionConcurrency caps parallel branch-protection calls (spec 7.4).
const protectionConcurrency = 4

// Connector collects one GitHub organization. It implements
// connector.Connector (implicitly: it just has the right method).
type Connector struct {
	client *Client
	org    string
}

// New returns a connector for org using client.
func New(client *Client, org string) *Connector {
	return &Connector{client: client, org: org}
}

// Compile-time check that *Connector satisfies the interface. If the method
// signature drifts, this line stops the build instead of failing at runtime.
var _ connector.Connector = (*Connector)(nil)

// Collect performs the read-only collection described in spec section 7.3.
func (c *Connector) Collect(ctx context.Context) (connector.Snapshot, error) {
	org := url.PathEscape(c.org)
	snap := connector.Snapshot{Collections: map[model.AssetKind]model.Collection{}}

	// --- org ---------------------------------------------------------------
	if resp, err := c.client.get(ctx, epOrg, c.client.base.String()+"/orgs/"+org); err != nil {
		if isFatal(err) {
			return snap, err
		}
		snap.Collections[model.KindOrg] = failed(model.KindOrg, reasonFor(err))
	} else {
		a, err := normalizeOrg(resp.body)
		if err != nil {
			snap.Collections[model.KindOrg] = failed(model.KindOrg, "unexpected_response")
		} else {
			snap.Assets = append(snap.Assets, a)
			snap.Collections[model.KindOrg] = model.Collection{Kind: model.KindOrg, Status: model.CollectionComplete}
		}
	}

	// --- users -------------------------------------------------------------
	members, err := c.client.getAll(ctx, epMembers, "/orgs/"+org+"/members?per_page=100")
	if err != nil {
		return snap, err
	}
	admins, err := c.client.getAll(ctx, epAdmins, "/orgs/"+org+"/members?role=admin&per_page=100")
	if err != nil {
		return snap, err
	}
	noMFA, err := c.client.getAll(ctx, epMembersNoMFA, "/orgs/"+org+"/members?filter=2fa_disabled&per_page=100")
	if err != nil {
		return snap, err
	}
	outside, err := c.client.getAll(ctx, epOutside, "/orgs/"+org+"/outside_collaborators?per_page=100")
	if err != nil {
		return snap, err
	}
	outsideNoMFA, err := c.client.getAll(ctx, epOutsideNoMFA, "/orgs/"+org+"/outside_collaborators?filter=2fa_disabled&per_page=100")
	if err != nil {
		return snap, err
	}
	users, err := buildUsers(members, outside, admins, noMFA, outsideNoMFA)
	if err != nil {
		return snap, err
	}
	snap.Assets = append(snap.Assets, users...)
	// Users come from two listings; the kind is complete only if both are.
	snap.Collections[model.KindUser] = combine(model.KindUser, members, outside)

	// --- repos + branch protection -------------------------------------------
	repoList, err := c.client.getAll(ctx, epRepos, "/orgs/"+org+"/repos?type=all&per_page=100")
	if err != nil {
		return snap, err
	}
	repos := make([]rawRepo, 0, len(repoList.items))
	for _, raw := range repoList.items {
		var r rawRepo
		if err := json.Unmarshal(raw, &r); err != nil {
			return snap, fmt.Errorf("decode repo: %w", err)
		}
		repos = append(repos, r)
	}
	prot, err := c.branchProtection(ctx, repos)
	if err != nil {
		return snap, err
	}
	snap.Assets = append(snap.Assets, normalizeRepos(repos, prot)...)
	snap.Collections[model.KindRepo] = toCollection(model.KindRepo, repoList)

	// --- webhooks ----------------------------------------------------------
	hookList, err := c.client.getAll(ctx, epHooks, "/orgs/"+org+"/hooks?per_page=100")
	if err != nil {
		return snap, err
	}
	hooks := make([]rawHook, 0, len(hookList.items))
	for _, raw := range hookList.items {
		var h rawHook
		if err := json.Unmarshal(raw, &h); err != nil {
			return snap, fmt.Errorf("decode hook: %w", err)
		}
		hooks = append(hooks, h)
	}
	snap.Assets = append(snap.Assets, normalizeHooks(hooks)...)
	snap.Collections[model.KindWebhook] = toCollection(model.KindWebhook, hookList)

	return snap, nil
}

// branchProtection looks up default-branch protection for every repo, at most
// 4 at a time. Each goroutine writes only its own slot of the result slice,
// so no mutex is needed (and `go test -race` checks that claim).
func (c *Connector) branchProtection(ctx context.Context, repos []rawRepo) ([]protection, error) {
	out := make([]protection, len(repos))
	// errgroup.WithContext: if one goroutine returns an error, ctx is
	// cancelled so the others stop early.
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(protectionConcurrency)
	for i, r := range repos {
		if r.DefaultBranch == "" {
			out[i] = protection{reason: model.ReasonFieldNotReturned}
			continue
		}
		// Go 1.22+: each loop iteration has its own i and r, so the
		// closure below captures this iteration's values safely.
		g.Go(func() error {
			path := fmt.Sprintf("/repos/%s/%s/branches/%s/protection",
				url.PathEscape(r.Owner.Login), url.PathEscape(r.Name), url.PathEscape(r.DefaultBranch))
			_, err := c.client.get(gctx, epProtection, c.client.base.String()+path)
			switch {
			case err == nil:
				out[i] = protection{protected: ptr(true)}
			case isFatal(err):
				return err // fails the scan; cancels the other lookups
			default:
				out[i] = classifyProtectionError(err)
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return out, nil
}

// classifyProtectionError implements the 404 rule from spec 7.4:
// "Branch not protected" is a real answer (false); any other 404 means we
// can't tell (no access, or the repo/branch is gone).
func classifyProtectionError(err error) protection {
	var api *APIError
	if errors.As(err, &api) && api.Status == 404 && api.Message == "Branch not protected" {
		return protection{protected: ptr(false)}
	}
	return protection{reason: reasonFor(err)}
}

func buildUsers(members, outside, admins, noMFA, outsideNoMFA listing) ([]model.Asset, error) {
	decode := func(l listing) ([]rawUser, error) {
		us := make([]rawUser, 0, len(l.items))
		for _, raw := range l.items {
			var u rawUser
			if err := json.Unmarshal(raw, &u); err != nil {
				return nil, fmt.Errorf("decode user: %w", err)
			}
			us = append(us, u)
		}
		return us, nil
	}
	m, err := decode(members)
	if err != nil {
		return nil, err
	}
	o, err := decode(outside)
	if err != nil {
		return nil, err
	}
	sets := make([]loginSet, 3)
	for i, l := range []listing{admins, noMFA, outsideNoMFA} {
		if sets[i], err = toLoginSet(l); err != nil {
			return nil, err
		}
	}
	return normalizeUsers(m, o, sets[0], sets[1], sets[2]), nil
}

func toCollection(kind model.AssetKind, l listing) model.Collection {
	return model.Collection{Kind: kind, Status: model.CollectionStatus(l.status), Reason: l.reason}
}

func failed(kind model.AssetKind, reason string) model.Collection {
	return model.Collection{Kind: kind, Status: model.CollectionFailed, Reason: reason}
}

// combine merges several listings of one kind: complete only if all are
// complete, failed only if all failed, partial otherwise.
func combine(kind model.AssetKind, ls ...listing) model.Collection {
	complete, failedN, reason := 0, 0, ""
	for _, l := range ls {
		switch l.status {
		case "complete":
			complete++
		case "failed":
			failedN++
		}
		if reason == "" {
			reason = l.reason
		}
	}
	switch {
	case complete == len(ls):
		return model.Collection{Kind: kind, Status: model.CollectionComplete}
	case failedN == len(ls):
		return model.Collection{Kind: kind, Status: model.CollectionFailed, Reason: reason}
	default:
		return model.Collection{Kind: kind, Status: model.CollectionPartial, Reason: reason}
	}
}

func ptr[T any](v T) *T { return &v } // generic helper: pointer to any value
