package authz

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"sigs.k8s.io/yaml"
)

// Binding grants a role over a set of tenants to whoever matches Group.
//
// Bindings are configuration, not code, because the mapping between an
// organisation's identity provider groups and Cupel's roles is the one part of
// this that is different at every site. Nothing here trusts the browser: the
// group list comes from a verified token.
type Binding struct {
	// Group is the identity-provider group this binding matches. A single
	// trailing "*" wildcards a prefix, so "ml-team-*" matches "ml-team-fraud".
	// Wildcards are not permitted anywhere else, because a mid-string wildcard
	// is very easy to write more broadly than intended.
	Group string `json:"group"`
	// Role granted to members of that group.
	Role Role `json:"role"`
	// Namespaces the role applies to. Ignored when AllNamespaces is set.
	Namespaces []string `json:"namespaces,omitempty"`
	// AllNamespaces grants the role over every tenant. Reserve it for
	// platform administrators and the central security team.
	AllNamespaces bool `json:"allNamespaces,omitempty"`
}

// Validate reports whether a binding is usable. Invalid bindings are rejected
// at load time rather than ignored at request time: a binding that silently
// does nothing is indistinguishable from one that was never written, and the
// failure mode is someone believing access is granted when it is not.
func (b Binding) Validate() error {
	if strings.TrimSpace(b.Group) == "" {
		return fmt.Errorf("binding has no group")
	}
	if i := strings.Index(b.Group, "*"); i >= 0 && i != len(b.Group)-1 {
		return fmt.Errorf("binding group %q: %q is only allowed as a trailing wildcard", b.Group, "*")
	}
	if _, err := ParseRole(string(b.Role)); err != nil {
		return fmt.Errorf("binding for group %q: %w", b.Group, err)
	}
	if !b.AllNamespaces && len(b.Namespaces) == 0 {
		return fmt.Errorf("binding for group %q grants %q over no namespaces; set namespaces or allNamespaces",
			b.Group, b.Role)
	}
	if b.AllNamespaces && len(b.Namespaces) > 0 {
		return fmt.Errorf("binding for group %q sets both namespaces and allNamespaces", b.Group)
	}
	for _, ns := range b.Namespaces {
		if strings.TrimSpace(ns) == "" {
			return fmt.Errorf("binding for group %q has an empty namespace", b.Group)
		}
	}
	return nil
}

// matches reports whether a group name satisfies the binding.
func (b Binding) matches(group string) bool {
	if strings.HasSuffix(b.Group, "*") {
		// path.Match is deliberately not used: it would also treat "?" and
		// character classes as patterns, which is more surface than intended.
		return strings.HasPrefix(group, strings.TrimSuffix(b.Group, "*"))
	}
	return b.Group == group
}

// Bindings is an ordered set of bindings. Order does not affect the outcome:
// a subject receives the union of every binding it matches, so bindings can
// only ever grant, never revoke. Revocation is removing the binding or the
// group membership.
type Bindings []Binding

// Validate checks every binding and reports all problems at once, since fixing
// them one error per restart is miserable.
func (bs Bindings) Validate() error {
	var problems []string
	for i, b := range bs {
		if err := b.Validate(); err != nil {
			problems = append(problems, fmt.Sprintf("  [%d] %v", i, err))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("invalid role bindings:\n%s", strings.Join(problems, "\n"))
	}
	return nil
}

// Claims is the subset of a verified OIDC token Cupel reads.
type Claims struct {
	Username string
	Groups   []string
}

// SubjectFor resolves a verified token's claims into a Subject.
//
// A subject with no matching binding gets no roles and no scope, which
// CanSeeNamespace and the redactors both treat as "sees nothing". That is the
// intended outcome for an authenticated employee who simply has no business
// with model security, and it is also the outcome if the group mapping is
// misconfigured — so the failure direction is closed.
func (bs Bindings) SubjectFor(c Claims) Subject {
	s := Subject{Username: c.Username, Groups: c.Groups}

	roles := map[Role]bool{}
	namespaces := map[string]bool{}

	for _, b := range bs {
		for _, g := range c.Groups {
			if !b.matches(g) {
				continue
			}
			roles[b.Role] = true
			if b.AllNamespaces {
				s.Scope.AllNamespaces = true
			}
			for _, ns := range b.Namespaces {
				namespaces[ns] = true
			}
			break // one match per binding is enough
		}
	}

	for r := range roles {
		s.Roles = append(s.Roles, r)
	}
	sort.Slice(s.Roles, func(i, j int) bool { return s.Roles[i] < s.Roles[j] })

	if !s.Scope.AllNamespaces {
		for ns := range namespaces {
			s.Scope.Namespaces = append(s.Scope.Namespaces, ns)
		}
		sort.Strings(s.Scope.Namespaces)
	}
	return s
}

// Describe renders the effective access of a subject for an audit log or a
// "who am I" endpoint. Operators need to be able to answer "why can this
// person see that" without reading the binding list themselves.
func (s Subject) Describe() string {
	if len(s.Roles) == 0 {
		return fmt.Sprintf("%s: no roles; sees nothing", s.Username)
	}
	roles := make([]string, 0, len(s.Roles))
	for _, r := range s.Roles {
		roles = append(roles, string(r))
	}
	scope := "no tenants"
	if s.Scope.AllNamespaces {
		scope = "all tenants"
	} else if len(s.Scope.Namespaces) > 0 {
		scope = "tenants " + strings.Join(s.Scope.Namespaces, ", ")
	}
	detail := "verdicts only"
	if s.Can(CapViewFindingPath) {
		detail = "full finding detail"
	} else if s.Can(CapViewFindings) {
		detail = "findings without location or description"
	}
	return fmt.Sprintf("%s: %s over %s (%s)", s.Username, strings.Join(roles, "+"), scope, detail)
}

// ParseBindings reads role bindings from YAML or JSON.
//
// YAML because this file is written and reviewed by people, and a config that
// cannot carry a comment cannot explain why a group was granted a role. JSON is
// accepted too since YAML is a superset. Either a bare list or an object with a
// "bindings" key works: both shapes get written by hand, and rejecting one over
// a stylistic difference helps nobody.
func ParseBindings(raw []byte) (Bindings, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, fmt.Errorf("the bindings file is empty; nobody would be able to sign in")
	}

	var wrapper struct {
		Bindings Bindings `json:"bindings"`
	}
	if err := yaml.Unmarshal(raw, &wrapper); err == nil && len(wrapper.Bindings) > 0 {
		return wrapper.Bindings, nil
	}

	var list Bindings
	if err := yaml.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("expected a list of bindings, or an object with a "+
			"\"bindings\" key: %w", err)
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("no bindings found; nobody would be able to sign in")
	}
	return list, nil
}
