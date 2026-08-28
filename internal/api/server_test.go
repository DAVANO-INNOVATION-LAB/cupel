package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/authz"
)

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := securityv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

// testServer skips OIDC discovery, which needs a live provider, and exercises
// everything after authentication — which is where the authorization lives.
func testServer(t *testing.T, objs ...runtime.Object) *Server {
	t.Helper()
	codec, err := newSessionCodec([]byte(strings.Repeat("k", 32)), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return &Server{
		k8s: fake.NewClientBuilder().WithScheme(testScheme(t)).WithRuntimeObjects(objs...).Build(),
		cfg: Config{
			Namespace: "cupel-system",
			Bindings: authz.Bindings{
				{Group: "secops", Role: authz.RoleSecurity, AllNamespaces: true},
				{Group: "team-a", Role: authz.RoleOwner, Namespaces: []string{"team-a"}},
				{Group: "auditors", Role: authz.RoleAuditor, Namespaces: []string{"team-a"}},
				{Group: "viewers", Role: authz.RoleViewer, Namespaces: []string{"team-a"}},
			},
		},
		sessions: codec,
	}
}

func loggedIn(t *testing.T, s *Server, req *http.Request, user string, groups ...string) *http.Request {
	t.Helper()
	rec := httptest.NewRecorder()
	if err := s.sessions.issue(rec, req, user, groups); err != nil {
		t.Fatal(err)
	}
	res := rec.Result()
	defer res.Body.Close()
	for _, c := range res.Cookies() {
		req.AddCookie(c)
	}
	return req
}

func report(model, ns, verdict string) *securityv1alpha1.ModelSecurityReport {
	return &securityv1alpha1.ModelSecurityReport{
		ObjectMeta: metav1.ObjectMeta{Name: "msr-" + model, Namespace: ns},
		Spec:       securityv1alpha1.ModelSecurityReportSpec{ModelName: model, ModelVersion: "v1"},
		Status:     securityv1alpha1.ModelSecurityReportStatus{Verdict: verdict, RiskScore: 60},
	}
}

// Without a valid session nothing is served. This is the property everything
// else depends on.
func TestUnauthenticatedRequestsSeeNothing(t *testing.T) {
	s := testServer(t, report("fraud", "team-a", "Quarantined"))
	for _, path := range []string{"/api/whoami", "/api/models", "/api/findings?model=fraud&version=v1"} {
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s returned %d without a session, want 401", path, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "fraud") {
			t.Errorf("%s leaked a model name to an anonymous caller", path)
		}
	}
}

// A cookie whose signature does not verify must be rejected, or the entire
// authorization model is a suggestion.
func TestForgedSessionIsRejected(t *testing.T) {
	s := testServer(t, report("fraud", "team-a", "Quarantined"))

	forged := `{"u":"attacker","g":["secops"],"e":99999999999}`
	for _, value := range []string{
		forged,                    // unsigned
		forged + ".notasignature", // wrong signature
		"", "..", "garbage",
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/models", nil)
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: value})
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("forged session %q was accepted (%d)", value, rec.Code)
		}
	}

	// A session signed with a different key must not verify either.
	other, _ := newSessionCodec([]byte(strings.Repeat("x", 32)), time.Hour)
	rec := httptest.NewRecorder()
	_ = other.issue(rec, httptest.NewRequest(http.MethodGet, "/", nil), "attacker", []string{"secops"})
	req := httptest.NewRequest(http.MethodGet, "/api/models", nil)
	otherRes := rec.Result()
	defer otherRes.Body.Close()
	for _, c := range otherRes.Cookies() {
		req.AddCookie(c)
	}
	out := httptest.NewRecorder()
	s.Handler().ServeHTTP(out, req)
	if out.Code != http.StatusUnauthorized {
		t.Errorf("a session signed with another key was accepted (%d)", out.Code)
	}
}

// Tenancy has to hold at the API, not only in the UI.
func TestTenantScopingIsEnforcedServerSide(t *testing.T) {
	s := testServer(t,
		report("fraud", "team-a", "Quarantined"),
		report("secret-project", "team-b", "Approved"),
	)

	req := loggedIn(t, s, httptest.NewRequest(http.MethodGet, "/api/models", nil), "kim", "team-a")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "fraud") {
		t.Error("the subject cannot see their own tenant's model")
	}
	if strings.Contains(body, "secret-project") {
		t.Errorf("another tenant's model leaked over the API: %s", body)
	}
}

// An auditor may see that a finding exists and never where it is.
func TestAuditorNeverReceivesExploitPathsOverTheAPI(t *testing.T) {
	scan := &securityv1alpha1.ArtifactScan{
		ObjectMeta: metav1.ObjectMeta{Name: "scan-fraud", Namespace: "team-a"},
		Spec:       securityv1alpha1.ArtifactScanSpec{ModelName: "fraud", ModelVersion: "v1"},
	}
	rep := &securityv1alpha1.ArtifactScanReport{
		ObjectMeta: metav1.ObjectMeta{Name: "asr-fraud", Namespace: "team-a"},
		Scanner:    "model-inspector",
		ScanRef:    "scan-fraud",
		Findings: []securityv1alpha1.Finding{{
			ID: "TESS-PICKLE-001", Title: "Pickle imports a dangerous callable",
			Severity: "Critical", Location: "weights.pkl",
			Description: "pickle stream references posix.system, which executes on load",
		}},
	}
	s := testServer(t, report("fraud", "team-a", "Quarantined"), scan, rep)

	get := func(user string, groups ...string) string {
		req := loggedIn(t, s, httptest.NewRequest(http.MethodGet, "/api/findings?model=fraud&version=v1", nil), user, groups...)
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d: %s", user, rec.Code, rec.Body.String())
		}
		return rec.Body.String()
	}

	sec := get("soc", "secops")
	if !strings.Contains(sec, "weights.pkl") {
		t.Error("security cannot see the location it needs to triage")
	}

	aud := get("ext", "auditors")
	if strings.Contains(aud, "weights.pkl") || strings.Contains(aud, "posix.system") {
		t.Errorf("the exploit path reached an auditor: %s", aud)
	}
	if !strings.Contains(aud, "TESS-PICKLE-001") {
		t.Error("the auditor cannot see that a finding exists at all")
	}
	if !strings.Contains(aud, "redacted") {
		t.Error("the redacted response does not say it was redacted")
	}
}

// Accepting risk on your own model is not a control.
func TestOwnersCannotAcceptRisk(t *testing.T) {
	s := testServer(t)
	body := `{"modelName":"fraud","modelVersion":"v1","reason":"looks fine to me","rules":["blockUnsafeModel"]}`

	req := loggedIn(t, s,
		httptest.NewRequest(http.MethodPost, "/api/exceptions", strings.NewReader(body)), "kim", "team-a")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("an owner accepted risk on their own model (%d): %s", rec.Code, rec.Body.String())
	}

	// Security may, and the record carries their identity.
	req2 := loggedIn(t, s,
		httptest.NewRequest(http.MethodPost, "/api/exceptions", strings.NewReader(body)), "soc", "secops")
	rec2 := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusCreated {
		t.Fatalf("security could not accept risk (%d): %s", rec2.Code, rec2.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(rec2.Body.Bytes(), &out)
	if out["approvedBy"] != "soc" {
		t.Errorf("the acceptance was not attributed to the caller: %v", out)
	}
}

// An unexplained waiver is indistinguishable from a mistake later.
func TestExceptionsRequireAReason(t *testing.T) {
	s := testServer(t)
	req := loggedIn(t, s, httptest.NewRequest(http.MethodPost, "/api/exceptions",
		strings.NewReader(`{"modelName":"fraud","modelVersion":"v1","reason":""}`)), "soc", "secops")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("an exception with no reason was accepted (%d)", rec.Code)
	}
}

// Someone who authenticates but matches no binding sees nothing, rather than
// erroring in a way that might be handled permissively somewhere.
func TestAuthenticatedButUnboundSeesAnEmptyInventory(t *testing.T) {
	s := testServer(t, report("fraud", "team-a", "Quarantined"))
	req := loggedIn(t, s, httptest.NewRequest(http.MethodGet, "/api/models", nil), "newhire", "all-staff")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "fraud") {
		t.Errorf("an unbound user saw a model: %s", rec.Body.String())
	}
}

// The console renders untrusted finding text, so the response carries a policy
// that would contain a script even if escaping ever regressed.
func TestSecurityHeadersArePresent(t *testing.T) {
	s := testServer(t)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	for header, want := range map[string]string{
		"Content-Security-Policy": "frame-ancestors 'none'",
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
	} {
		if got := rec.Header().Get(header); !strings.Contains(got, want) {
			t.Errorf("%s = %q, want it to contain %q", header, got, want)
		}
	}
}

func TestSessionsExpire(t *testing.T) {
	// A non-positive TTL is floored to a sane default by newSessionCodec, so
	// expiry is exercised by signing an already-past payload directly.
	codec, err := newSessionCodec([]byte(strings.Repeat("k", 32)), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	expired, _ := json.Marshal(session{Username: "u", Expires: time.Now().Add(-time.Hour).Unix()})
	http.SetCookie(rec, &http.Cookie{Name: sessionCookie, Value: codec.sign(expired)})
	var value string
	res := rec.Result()
	defer res.Body.Close()
	for _, c := range res.Cookies() {
		if c.Name == sessionCookie {
			value = c.Value
		}
	}
	if _, err := codec.verify(value); err == nil {
		t.Error("an expired session verified")
	}
}

func TestShortSessionKeysAreRejected(t *testing.T) {
	if _, err := newSessionCodec([]byte("tooshort"), time.Hour); err == nil {
		t.Error("a short session key was accepted; forging a cookie would be feasible")
	}
}
