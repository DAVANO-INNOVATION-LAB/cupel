package authz

import (
	"strings"
	"testing"
)

func siteBindings() Bindings {
	return Bindings{
		{Group: "cupel-admins", Role: RoleAdmin, AllNamespaces: true},
		{Group: "secops", Role: RoleSecurity, AllNamespaces: true},
		{Group: "ml-team-fraud", Role: RoleOwner, Namespaces: []string{"team-fraud"}},
		{Group: "ml-team-nlp", Role: RoleOwner, Namespaces: []string{"team-nlp"}},
		{Group: "external-audit", Role: RoleAuditor, Namespaces: []string{"team-fraud", "team-nlp"}},
	}
}

// The whole point of tenancy: one team's engineer cannot see another team's
// models, however the identity provider is configured.
func TestOwnerIsConfinedToTheirOwnTenant(t *testing.T) {
	s := siteBindings().SubjectFor(Claims{Username: "kim", Groups: []string{"ml-team-fraud"}})

	if !s.CanSeeNamespace("team-fraud") {
		t.Error("owner cannot see their own tenant")
	}
	if s.CanSeeNamespace("team-nlp") {
		t.Error("owner can see another team's tenant")
	}
	if s.Scope.AllNamespaces {
		t.Error("owner was granted cluster-wide scope")
	}
	if !s.Can(CapViewFindingPath) {
		t.Error("owner cannot see the detail needed to fix their own model")
	}
	if s.Can(CapWaive) {
		t.Error("owner can waive findings on their own model")
	}
}

// Someone who authenticates successfully but matches no binding must see
// nothing. This is the shape a misconfigured group mapping produces.
func TestAuthenticatedButUnboundSeesNothing(t *testing.T) {
	s := siteBindings().SubjectFor(Claims{Username: "newhire", Groups: []string{"all-staff"}})

	if len(s.Roles) != 0 {
		t.Errorf("unbound user received roles %v", s.Roles)
	}
	if s.CanSeeNamespace("team-fraud") {
		t.Error("unbound user can see a tenant")
	}
	if !strings.Contains(s.Describe(), "sees nothing") {
		t.Errorf("Describe should say plainly that access is empty: %q", s.Describe())
	}
}

// Belonging to several teams grants the union, and nothing beyond it.
func TestMembershipInSeveralTeamsUnionsTenants(t *testing.T) {
	s := siteBindings().SubjectFor(Claims{
		Username: "lead", Groups: []string{"ml-team-fraud", "ml-team-nlp"},
	})
	if !s.CanSeeNamespace("team-fraud") || !s.CanSeeNamespace("team-nlp") {
		t.Errorf("scope = %+v, want both tenants", s.Scope)
	}
	if s.CanSeeNamespace("team-payments") {
		t.Error("union granted a tenant no binding mentions")
	}
	if s.Scope.AllNamespaces {
		t.Error("two scoped bindings escalated to cluster-wide")
	}
}

func TestClusterWideBindingGrantsEveryTenant(t *testing.T) {
	s := siteBindings().SubjectFor(Claims{Username: "soc", Groups: []string{"secops"}})
	if !s.Scope.AllNamespaces {
		t.Fatal("secops did not receive cluster-wide scope")
	}
	if !s.CanSeeNamespace("a-namespace-created-tomorrow") {
		t.Error("cluster-wide scope does not cover new tenants")
	}
	if !s.Can(CapWaive) {
		t.Error("security role cannot disposition findings")
	}
}

// An auditor is often external. They may see posture across tenants, and must
// never receive the exploit path.
func TestAuditorSeesPostureNotExploitPaths(t *testing.T) {
	s := siteBindings().SubjectFor(Claims{Username: "ext", Groups: []string{"external-audit"}})

	if !s.Can(CapViewCompliance) || !s.Can(CapViewInventory) {
		t.Error("auditor cannot see what they are there to audit")
	}
	if s.Can(CapViewFindingPath) {
		t.Error("auditor received exploit paths")
	}
	if s.Can(CapRunScan) || s.Can(CapWaive) {
		t.Error("auditor can change state")
	}
	if !strings.Contains(s.Describe(), "without location") {
		t.Errorf("Describe does not convey the detail limit: %q", s.Describe())
	}
}

func TestTrailingWildcardMatchesTeamPrefix(t *testing.T) {
	bs := Bindings{{Group: "ml-team-*", Role: RoleOwner, Namespaces: []string{"shared"}}}

	if s := bs.SubjectFor(Claims{Groups: []string{"ml-team-anything"}}); len(s.Roles) == 0 {
		t.Error("trailing wildcard did not match a prefixed group")
	}
	if s := bs.SubjectFor(Claims{Groups: []string{"other-team"}}); len(s.Roles) != 0 {
		t.Error("wildcard matched an unrelated group")
	}
	// A bare "*" is a valid, if alarming, binding; make sure it is at least
	// explicit rather than accidental.
	if !(Binding{Group: "*"}).matches("literally-anything") {
		t.Error("bare wildcard did not match")
	}
}

// A binding that silently does nothing is worse than one that fails loudly,
// because someone believes access was granted.
func TestInvalidBindingsAreRejectedAtLoad(t *testing.T) {
	cases := map[string]Binding{
		"no group":            {Role: RoleOwner, Namespaces: []string{"a"}},
		"unknown role":        {Group: "g", Role: "superuser", Namespaces: []string{"a"}},
		"no scope at all":     {Group: "g", Role: RoleOwner},
		"both scopes":         {Group: "g", Role: RoleOwner, Namespaces: []string{"a"}, AllNamespaces: true},
		"empty namespace":     {Group: "g", Role: RoleOwner, Namespaces: []string{" "}},
		"mid-string wildcard": {Group: "ml-*-team", Role: RoleOwner, Namespaces: []string{"a"}},
	}
	for name, b := range cases {
		if err := b.Validate(); err == nil {
			t.Errorf("%s: accepted an invalid binding %+v", name, b)
		}
	}

	// Every problem is reported at once.
	err := Bindings{
		{Role: RoleOwner, Namespaces: []string{"a"}},
		{Group: "g", Role: "nope", Namespaces: []string{"a"}},
	}.Validate()
	if err == nil {
		t.Fatal("invalid binding set was accepted")
	}
	if strings.Count(err.Error(), "\n") < 2 {
		t.Errorf("only one problem reported: %v", err)
	}
}

func TestValidBindingsPass(t *testing.T) {
	if err := siteBindings().Validate(); err != nil {
		t.Errorf("the documented example bindings do not validate: %v", err)
	}
}

// Bindings only ever grant. Removing access means removing the binding or the
// group membership, never adding a "deny" that has to be evaluated in order.
func TestBindingOrderDoesNotChangeTheOutcome(t *testing.T) {
	forward := siteBindings()
	reversed := make(Bindings, len(forward))
	for i, b := range forward {
		reversed[len(forward)-1-i] = b
	}
	claims := Claims{Username: "kim", Groups: []string{"ml-team-fraud", "external-audit"}}

	a := forward.SubjectFor(claims)
	b := reversed.SubjectFor(claims)
	if a.Describe() != b.Describe() {
		t.Errorf("order changed the outcome:\n  %s\n  %s", a.Describe(), b.Describe())
	}
}
