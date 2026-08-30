package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/audit"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/authz"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/scanners"
)

// chainObjects builds a sealed chain and the cluster objects holding it, so the
// endpoint is exercised against a log that actually verifies rather than a
// hand-written fixture that only looks like one.
func chainObjects(t *testing.T, n int) []runtime.Object {
	t.Helper()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var prev *audit.Record
	var objs []runtime.Object
	for i := 1; i <= n; i++ {
		sealed := audit.Seal(audit.Record{
			Seq:     uint64(i),
			Time:    base.Add(time.Duration(i) * time.Minute),
			Type:    "VerdictIssued",
			Subject: fmt.Sprintf("model-%03d/v1", i),
			Actor:   "system",
			Detail:  map[string]string{"verdict": "Approved"},
		}, prev)
		objs = append(objs, &securityv1alpha1.AuditRecord{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("audit-%012d", sealed.Seq),
				Namespace: "cupel-system",
			},
			Spec: securityv1alpha1.AuditRecordSpec{
				Seq:      int64(sealed.Seq),
				Time:     metav1.NewTime(sealed.Time),
				Type:     string(sealed.Type),
				Subject:  sealed.Subject,
				Actor:    sealed.Actor,
				Detail:   sealed.Detail,
				PrevHash: sealed.PrevHash,
				Hash:     sealed.Hash,
			},
		})
		c := sealed
		prev = &c
	}
	return objs
}

func getAudit(t *testing.T, s *Server, query, user string, groups ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := loggedIn(t, s, httptest.NewRequest(http.MethodGet, "/api/audit"+query, nil), user, groups...)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

// The point of the log is the proof, so the endpoint has to report it.
func TestAuditEndpointVerifiesTheWholeChain(t *testing.T) {
	s := testServer(t, chainObjects(t, 12)...)

	rec := getAudit(t, s, "?limit=3", "soc", "secops")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var got struct {
		Chain struct {
			Valid    bool     `json:"valid"`
			Length   uint64   `json:"length"`
			Problems []string `json:"problems"`
		} `json:"chain"`
		Records  []map[string]any `json:"records"`
		Retained int              `json:"retained"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Chain.Valid {
		t.Errorf("a sealed chain did not verify: %v", got.Chain.Problems)
	}
	// The window bounds what is sent, never what is checked: asking for three
	// records must still verify all twelve, or the badge means nothing.
	if got.Chain.Length != 12 {
		t.Errorf("verified length %d, want 12 — the limit narrowed the proof", got.Chain.Length)
	}
	if len(got.Records) != 3 {
		t.Fatalf("returned %d records, want 3", len(got.Records))
	}
	if seq, _ := got.Records[0]["seq"].(float64); seq != 12 {
		t.Errorf("first record is seq %v, want the newest (12)", got.Records[0]["seq"])
	}
	if got.Retained != 12 {
		t.Errorf("retained %d, want 12", got.Retained)
	}
}

// A tampered record must not be reported as an intact chain, which is the only
// failure here that actually matters.
func TestAuditEndpointReportsATamperedChain(t *testing.T) {
	objs := chainObjects(t, 6)
	edited := objs[3].(*securityv1alpha1.AuditRecord)
	edited.Spec.Actor = "somebody-else" // hash no longer commits to the contents
	s := testServer(t, objs...)

	rec := getAudit(t, s, "", "soc", "secops")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var got struct {
		Chain struct {
			Valid    bool     `json:"valid"`
			Problems []string `json:"problems"`
		} `json:"chain"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Chain.Valid {
		t.Fatal("an edited record was reported as an intact chain")
	}
	if len(got.Chain.Problems) == 0 {
		t.Error("the chain was reported broken without saying what broke")
	}
}

// The chain cannot be filtered without breaking its own links, so a subject
// scoped to particular namespaces is refused rather than handed a partial log
// that would fail to verify through no fault of theirs.
func TestNamespaceScopedSubjectsCannotReadTheAuditLog(t *testing.T) {
	s := testServer(t, chainObjects(t, 4)...)

	if rec := getAudit(t, s, "", "ext", "auditors"); rec.Code != http.StatusForbidden {
		t.Errorf("a namespace-scoped auditor got %d, want 403", rec.Code)
	}
	// And a role without the capability at all, cluster-wide or not.
	if rec := getAudit(t, s, "", "reader", "viewers"); rec.Code != http.StatusForbidden {
		t.Errorf("a viewer got %d, want 403", rec.Code)
	}
	// Nothing leaks in either refusal.
	rec := getAudit(t, s, "", "reader", "viewers")
	if body := rec.Body.String(); strings.Contains(body, "model-001") {
		t.Errorf("a refusal leaked a subject: %s", body)
	}
}

// A capability the server enforces but whoami never mentions leaves the console
// hiding the feature it gates, with nothing to say why.
func TestWhoamiReportsEveryCapability(t *testing.T) {
	s := testServer(t)
	req := loggedIn(t, s, httptest.NewRequest(http.MethodGet, "/api/whoami", nil), "soc", "secops")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	var got struct {
		Capabilities map[string]bool `json:"capabilities"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	for _, c := range authz.AllCapabilities() {
		if _, ok := got.Capabilities[string(c)]; !ok {
			t.Errorf("whoami never mentions %q, so the console cannot gate on it", c)
		}
	}
}

// The console prints commands naming the operator image. It used to carry its
// own copy of the tag, which stayed correct only for as long as somebody
// remembered to edit two files at once.
func TestWhoamiReportsTheRunningVersion(t *testing.T) {
	s := testServer(t)
	req := loggedIn(t, s, httptest.NewRequest(http.MethodGet, "/api/whoami", nil), "soc", "secops")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	var got struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Version != scanners.ImageTag {
		t.Errorf("whoami reports version %q, want the shipped tag %q", got.Version, scanners.ImageTag)
	}
}
