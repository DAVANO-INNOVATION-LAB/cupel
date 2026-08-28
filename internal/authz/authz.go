// Package authz decides who may see which models, and how much of a finding
// they are shown.
//
// Scan findings are not neutral facts. A row saying that a named, deployed
// model contains a pickle that calls os.system, at a known path, alongside a
// leaked credential, is a targeting package: it tells an attacker exactly what
// is exploitable and where. So the console cannot simply render whatever the
// cluster holds, and Kubernetes RBAC alone cannot express the rule that is
// needed — RBAC authorizes resource *types*, so anyone able to read a
// namespace reads every finding in it at full detail.
//
// Two independent controls apply, in this order:
//
//   - Scope decides which models a subject may see at all. This is tenancy,
//     and it is deny-by-default: a subject with no matching scope sees nothing,
//     not an empty list of someone else's models.
//   - Role decides how much of each finding they are shown. A model's owner
//     needs the exploit path in order to fix it; an auditor needs the verdict
//     and never needs the path.
//
// Both are enforced here rather than in the UI, because a control implemented
// in a browser is not a control.
package authz

import (
	"fmt"
	"sort"
	"strings"
)

// Role is what a subject may do, and how much detail they receive.
type Role string

const (
	// RoleAdmin administers Cupel itself: every tenant, every detail, and
	// configuration. Intended to be rare.
	RoleAdmin Role = "admin"

	// RoleSecurity investigates and dispositions findings across the tenants
	// it is scoped to. Sees full detail, because triage without the location
	// and the description is guesswork.
	RoleSecurity Role = "security"

	// RoleOwner owns models. Sees full detail for models inside its scope —
	// the owner is the person who has to fix the finding, and withholding the
	// path from them only means it never gets fixed — but cannot disposition
	// findings, since accepting your own risk is not a control.
	RoleOwner Role = "owner"

	// RoleAuditor evidences compliance. Sees verdicts, risk scores, severity
	// counts and framework posture; never sees the exploit path, the
	// description, or a secret's location. Auditors are frequently external,
	// and the compliance question ("was this scanned and what was decided")
	// does not require the answer to "how would I exploit it".
	RoleAuditor Role = "auditor"

	// RoleViewer sees that a model exists and what it was judged to be.
	// Nothing about why.
	RoleViewer Role = "viewer"
)

// Capability is a discrete action a role may perform.
type Capability string

const (
	CapViewInventory   Capability = "view:inventory"    // model list and verdicts
	CapViewFindings    Capability = "view:findings"     // finding rows at all
	CapViewFindingPath Capability = "view:finding-path" // location and description
	CapViewCompliance  Capability = "view:compliance"
	CapRunScan         Capability = "scan:create"
	CapWaive           Capability = "finding:waive" // create ArtifactExceptions
	CapManage          Capability = "admin:manage"  // policies, connectors, config
	// CapViewAudit reads the tamper-evident decision log. It is separate from
	// compliance because the two answer different questions: compliance says
	// which controls a model satisfies, the audit chain says who decided what
	// and proves the record has not been edited since.
	CapViewAudit Capability = "view:audit"
)

var roleCapabilities = map[Role][]Capability{
	RoleAdmin: {
		CapViewInventory, CapViewFindings, CapViewFindingPath,
		CapViewCompliance, CapRunScan, CapWaive, CapManage, CapViewAudit,
	},
	RoleSecurity: {
		CapViewInventory, CapViewFindings, CapViewFindingPath,
		CapViewCompliance, CapRunScan, CapWaive, CapViewAudit,
	},
	RoleOwner: {
		CapViewInventory, CapViewFindings, CapViewFindingPath,
		CapViewCompliance, CapRunScan,
	},
	RoleAuditor: {
		CapViewInventory, CapViewFindings, CapViewCompliance, CapViewAudit,
	},
	RoleViewer: {
		CapViewInventory,
	},
}

// AllCapabilities lists every capability any role grants, sorted.
//
// Callers that describe a subject enumerate this rather than keeping their own
// list. A hand-maintained copy goes stale silently: the capability exists, the
// server enforces it, and the console never hears about it — so the feature it
// gates stays invisible with nothing to indicate why.
func AllCapabilities() []Capability {
	seen := map[Capability]bool{}
	var out []Capability
	for _, caps := range roleCapabilities {
		for _, c := range caps {
			if !seen[c] {
				seen[c] = true
				out = append(out, c)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ParseRole validates a role name from a token claim or a binding.
func ParseRole(s string) (Role, error) {
	r := Role(strings.ToLower(strings.TrimSpace(s)))
	if _, ok := roleCapabilities[r]; !ok {
		return "", fmt.Errorf("unknown role %q; known roles: %s", s, strings.Join(RoleNames(), ", "))
	}
	return r, nil
}

// RoleNames lists every role, sorted.
func RoleNames() []string {
	names := make([]string, 0, len(roleCapabilities))
	for r := range roleCapabilities {
		names = append(names, string(r))
	}
	sort.Strings(names)
	return names
}

// Scope limits a subject to a set of tenants. A tenant is a Kubernetes
// namespace, so tenancy lines up with the boundary the cluster already
// enforces rather than inventing a second one.
type Scope struct {
	// Namespaces the subject may see. Empty means none.
	Namespaces []string
	// AllNamespaces grants every tenant. Only ever set for admins and for
	// security subjects explicitly bound cluster-wide.
	AllNamespaces bool
}

// Subject is an authenticated caller: who they are, what they may do, and
// where. It is built from an OIDC token by the API server, never from
// anything the browser sends.
type Subject struct {
	// Username as asserted by the identity provider.
	Username string
	// Groups from the token, retained for auditing the decision.
	Groups []string
	// Roles the subject holds. A subject may hold several; capabilities are
	// the union, and detail level is the most permissive of them.
	Roles []Role
	// Scope limits which tenants those roles apply to.
	Scope Scope
}

// Can reports whether the subject holds a capability through any of its roles.
func (s Subject) Can(c Capability) bool {
	for _, r := range s.Roles {
		for _, have := range roleCapabilities[r] {
			if have == c {
				return true
			}
		}
	}
	return false
}

// CanSeeNamespace reports whether the subject may see anything in a namespace.
//
// Deny by default: a subject with no scope sees nothing. The distinction
// matters because "you have no models" and "you may not see these models" must
// look identical to the caller, and the only safe way to guarantee that is for
// the filter to run before anything is serialised.
func (s Subject) CanSeeNamespace(ns string) bool {
	if s.Scope.AllNamespaces {
		return true
	}
	for _, allowed := range s.Scope.Namespaces {
		if allowed == ns {
			return true
		}
	}
	return false
}

// Anonymous is the zero subject: no roles, no scope, sees nothing. Returned
// when authentication fails, so a bug in the auth path fails closed.
func Anonymous() Subject { return Subject{Username: "anonymous"} }
