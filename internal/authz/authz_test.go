package authz

import (
	"encoding/json"
	"strings"
	"testing"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
)

func findings() []securityv1alpha1.Finding {
	return []securityv1alpha1.Finding{
		{
			ID: "TESS-PICKLE-001", Title: "Pickle imports a dangerous callable",
			Severity: "Critical", Category: "model",
			Location:    "weights.pkl",
			Description: "pickle stream references posix.system, which executes on load",
		},
		{
			ID: "aws-secret-access-key", Title: "AWS Secret Access Key",
			Severity: "Critical", Category: "secret",
			Location:    "config/creds.env:14",
			Description: "a live-looking AWS secret is embedded in the artifact",
		},
	}
}

func subject(role Role, namespaces ...string) Subject {
	return Subject{
		Username: "u",
		Roles:    []Role{role},
		Scope:    Scope{Namespaces: namespaces},
	}
}

// The exploit path is the part that turns a finding into a targeting package.
// Roles that do not need it must not receive it — and "must not receive it"
// means it is absent from the serialised payload, not merely hidden by the UI.
func TestExploitPathIsWithheldFromRolesThatDoNotNeedIt(t *testing.T) {
	cases := []struct {
		role     Role
		wantPath bool
	}{
		{RoleAdmin, true},
		{RoleSecurity, true},
		{RoleOwner, true},    // has to fix it
		{RoleAuditor, false}, // needs the verdict, never the path
		{RoleViewer, false},
	}

	for _, tc := range cases {
		t.Run(string(tc.role), func(t *testing.T) {
			views, red := RedactFindings(subject(tc.role, "team-a"), "team-a", findings(), "model-inspector")

			if tc.role == RoleViewer {
				if len(views) != 0 {
					t.Fatalf("viewer received %d findings; a viewer sees verdicts only", len(views))
				}
				return
			}
			if len(views) != 2 {
				t.Fatalf("got %d findings, want 2", len(views))
			}

			// Serialise, because the guarantee is about the bytes on the wire.
			blob, err := json.Marshal(views)
			if err != nil {
				t.Fatal(err)
			}
			leaked := strings.Contains(string(blob), "weights.pkl") ||
				strings.Contains(string(blob), "creds.env") ||
				strings.Contains(string(blob), "posix.system")

			if tc.wantPath && !leaked {
				t.Error("role needs the exploit path to act on the finding but did not receive it")
			}
			if !tc.wantPath {
				if leaked {
					t.Errorf("exploit path leaked to %s: %s", tc.role, blob)
				}
				if !red.DetailWithheld {
					t.Error("detail was withheld but the response does not say so")
				}
				for _, v := range views {
					if !v.Redacted {
						t.Error("redacted row is not marked redacted; it would read as complete")
					}
					// The severity and title still have to survive, or the
					// finding is invisible rather than redacted.
					if v.Severity == "" || v.ID == "" {
						t.Error("redaction removed the fields that make a finding countable")
					}
				}
			}
		})
	}
}

// Tenancy is the outer control: a subject outside the tenant gets nothing,
// not a redacted list. Even the number of findings against a named model says
// something about that model.
func TestOtherTenantsSeeNothingAtAll(t *testing.T) {
	// A security analyst — the most privileged non-admin role — still scoped
	// to their own tenant only.
	s := subject(RoleSecurity, "team-a")

	views, red := RedactFindings(s, "team-b", findings(), "clamav")
	if len(views) != 0 {
		t.Fatalf("subject scoped to team-a received %d findings from team-b", len(views))
	}
	if red.HiddenFindings != 2 {
		t.Errorf("hidden count = %d, want 2 so the view is known to be partial", red.HiddenFindings)
	}
	blob, _ := json.Marshal(struct {
		V []FindingView `json:"v"`
		R Redaction     `json:"r"`
	}{views, red})
	if strings.Contains(string(blob), "weights.pkl") || strings.Contains(string(blob), "PICKLE") {
		t.Errorf("cross-tenant response leaked finding content: %s", blob)
	}
}

// Deny by default. A subject with no scope is the shape a bug in the auth path
// produces, so it must be the safest shape.
func TestNoScopeSeesNothing(t *testing.T) {
	for _, s := range []Subject{
		Anonymous(),
		{Username: "u", Roles: []Role{RoleAdmin}}, // admin, but bound to no tenant
	} {
		if s.CanSeeNamespace("team-a") {
			t.Errorf("%s with no scope can see a namespace", s.Username)
		}
		views, _ := RedactFindings(s, "team-a", findings(), "clamav")
		if len(views) != 0 {
			t.Errorf("%s with no scope received findings", s.Username)
		}
	}
}

func TestAllNamespacesGrantsEveryTenant(t *testing.T) {
	s := Subject{Username: "admin", Roles: []Role{RoleAdmin}, Scope: Scope{AllNamespaces: true}}
	for _, ns := range []string{"team-a", "team-b", "anything"} {
		if !s.CanSeeNamespace(ns) {
			t.Errorf("cluster-scoped admin cannot see %q", ns)
		}
	}
}

func TestInventoryIsFilteredByTenant(t *testing.T) {
	models := []ModelView{
		{ModelName: "fraud", ModelVersion: "v1", Namespace: "team-a", Verdict: "Quarantined"},
		{ModelName: "secret-project", ModelVersion: "v9", Namespace: "team-b", Verdict: "Approved"},
	}
	visible, red := FilterModels(subject(RoleOwner, "team-a"), models)

	if len(visible) != 1 || visible[0].Namespace != "team-a" {
		t.Fatalf("got %+v, want only the team-a model", visible)
	}
	if red.HiddenFindings != 1 {
		t.Errorf("hidden count = %d, want 1", red.HiddenFindings)
	}
	blob, _ := json.Marshal(visible)
	if strings.Contains(string(blob), "secret-project") {
		t.Errorf("another tenant's model name leaked: %s", blob)
	}
}

// Waiving your own finding is not a control, so owners cannot do it.
func TestOnlySecurityRolesCanWaive(t *testing.T) {
	cases := map[Role]bool{
		RoleAdmin: true, RoleSecurity: true,
		RoleOwner: false, RoleAuditor: false, RoleViewer: false,
	}
	for role, want := range cases {
		if got := subject(role).Can(CapWaive); got != want {
			t.Errorf("%s waive = %v, want %v", role, got, want)
		}
	}
}

// Several roles union their capabilities: a user who is both an owner and an
// auditor should not lose the detail their owner role grants.
func TestMultipleRolesUnionCapabilities(t *testing.T) {
	s := Subject{
		Username: "u",
		Roles:    []Role{RoleAuditor, RoleOwner},
		Scope:    Scope{Namespaces: []string{"team-a"}},
	}
	if !s.Can(CapViewFindingPath) {
		t.Error("owner+auditor lost the detail the owner role grants")
	}
	if s.Can(CapWaive) {
		t.Error("owner+auditor gained a capability neither role has")
	}
}

func TestParseRoleRejectsUnknown(t *testing.T) {
	if _, err := ParseRole("superuser"); err == nil {
		t.Error("unknown role was accepted")
	}
	// The error should say what is valid, since these come from IdP group
	// mappings that people get wrong.
	_, err := ParseRole("superuser")
	if !strings.Contains(err.Error(), "auditor") {
		t.Errorf("error does not list valid roles: %v", err)
	}
	for _, name := range RoleNames() {
		if _, err := ParseRole(name); err != nil {
			t.Errorf("RoleNames returned %q which ParseRole rejects", name)
		}
	}
	if _, err := ParseRole("  ADMIN  "); err != nil {
		t.Errorf("role parsing should tolerate case and spacing: %v", err)
	}
}
