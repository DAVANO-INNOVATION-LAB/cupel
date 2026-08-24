package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/authz"
)

func resourceScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := securityv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return scheme
}

// serverFor builds a server with the given objects, bypassing OIDC so the
// authorization logic can be exercised directly.
func serverFor(t *testing.T, objs ...client.Object) *Server {
	t.Helper()
	c := fake.NewClientBuilder().WithScheme(resourceScheme(t)).WithObjects(objs...).Build()
	return &Server{k8s: c, cfg: Config{Namespace: "cupel-system"}}
}

func subjectWith(role authz.Role, namespaces ...string) authz.Subject {
	s := authz.Subject{Username: "tester", Roles: []authz.Role{role}}
	if len(namespaces) == 0 {
		s.Scope.AllNamespaces = true
	} else {
		s.Scope.Namespaces = namespaces
	}
	return s
}

func call(t *testing.T, h func(http.ResponseWriter, *http.Request, authz.Subject),
	sub authz.Subject, method, target string, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	}
	w := httptest.NewRecorder()
	h(w, r, sub)
	return w
}

func connector(name, ns string) *securityv1alpha1.ModelRegistryConnector {
	return &securityv1alpha1.ModelRegistryConnector{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec: securityv1alpha1.ModelRegistryConnectorSpec{
			Type: "MLflow", RegistryURL: "http://mlflow:5000",
		},
	}
}

// Tenant scoping is the whole point: a subject scoped to one namespace must
// not learn what exists in another, even when the operator's client can see it.
func TestConnectorsAreScopedToTenants(t *testing.T) {
	s := serverFor(t, connector("theirs", "team-b"), connector("mine", "team-a"))

	w := call(t, s.handleConnectors, subjectWith(authz.RoleOwner, "team-a"), "GET", "/api/connectors", "")
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var body struct {
		Connectors []connectorView `json:"connectors"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Connectors) != 1 || body.Connectors[0].Name != "mine" {
		t.Fatalf("a team-a subject must see only team-a sources, got %+v", body.Connectors)
	}
}

// A credential reference is an operational detail. The console needs to know
// one exists, not which secret it is.
func TestConnectorNeverExposesTheSecretName(t *testing.T) {
	c := connector("mine", "cupel-system")
	c.Spec.AuthSecretRef = &securityv1alpha1.SecretKeyRef{Name: "mlflow-token", Key: "token"}
	s := serverFor(t, c)

	w := call(t, s.handleConnectors, subjectWith(authz.RoleAdmin), "GET", "/api/connectors", "")
	if strings.Contains(w.Body.String(), "mlflow-token") {
		t.Fatalf("the secret name must not be serialized: %s", w.Body.String())
	}
	var body struct {
		Connectors []connectorView `json:"connectors"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if !body.Connectors[0].HasCredential {
		t.Fatal("the console still needs to know a credential is configured")
	}
}

func TestCreatingASourceRequiresManage(t *testing.T) {
	s := serverFor(t)
	payload := `{"name":"new-source","type":"MLflow","registryUrl":"http://mlflow:5000"}`

	for _, role := range []authz.Role{authz.RoleViewer, authz.RoleOwner, authz.RoleSecurity, authz.RoleAuditor} {
		w := call(t, s.handleCreateConnector, subjectWith(role), "POST", "/api/connectors", payload)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s must not be able to add a model source, got %d", role, w.Code)
		}
	}

	w := call(t, s.handleCreateConnector, subjectWith(authz.RoleAdmin), "POST", "/api/connectors", payload)
	if w.Code != http.StatusCreated {
		t.Fatalf("an admin should be able to add a source, got %d: %s", w.Code, w.Body)
	}
}

// Adding a source decides which models enter the pipeline at all, so who did
// it is worth recording.
func TestCreatingASourceRecordsWhoDidIt(t *testing.T) {
	s := serverFor(t)
	sub := subjectWith(authz.RoleAdmin)
	sub.Username = "alice@davano.net"

	w := call(t, s.handleCreateConnector, sub, "POST", "/api/connectors",
		`{"name":"src","type":"MLflow","registryUrl":"http://mlflow:5000"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("got %d: %s", w.Code, w.Body)
	}

	var got securityv1alpha1.ModelRegistryConnector
	key := client.ObjectKey{Name: "src", Namespace: "cupel-system"}
	if err := s.k8s.Get(context.Background(), key, &got); err != nil {
		t.Fatal(err)
	}
	if got.Annotations["security.davano.io/created-by"] != "alice@davano.net" {
		t.Fatalf("the creator should be recorded, got %v", got.Annotations)
	}
}

func TestConnectorRequestValidation(t *testing.T) {
	s := serverFor(t)
	admin := subjectWith(authz.RoleAdmin)

	cases := []struct{ name, payload, why string }{
		{"bad name", `{"name":"Not A Name","registryUrl":"http://x"}`,
			"a name that is not a DNS label would fail at the API server with a worse message"},
		{"no endpoint", `{"name":"x"}`, "a source with no endpoint cannot sync"},
		{"not a url", `{"name":"x","registryUrl":"mlflow.internal:5000"}`,
			"a scheme-less endpoint silently fails at request time"},
		{"bad duration", `{"name":"x","registryUrl":"http://x","pollInterval":"soon"}`,
			"an unparseable duration should be rejected with an explanation"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := call(t, s.handleCreateConnector, admin, "POST", "/api/connectors", tc.payload)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("%s: want 400, got %d", tc.why, w.Code)
			}
			if !strings.Contains(w.Body.String(), "error") {
				t.Fatal("a rejection should explain itself")
			}
		})
	}
}

// There must be no way to hand the server a token: a credential typed into a
// form is a credential in a request log.
func TestConnectorRequestHasNoTokenField(t *testing.T) {
	s := serverFor(t)
	w := call(t, s.handleCreateConnector, subjectWith(authz.RoleAdmin), "POST", "/api/connectors",
		`{"name":"src","registryUrl":"http://x","token":"hunter2","secretName":"ref"}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("got %d: %s", w.Code, w.Body)
	}

	var got securityv1alpha1.ModelRegistryConnector
	key := client.ObjectKey{Name: "src", Namespace: "cupel-system"}
	if err := s.k8s.Get(context.Background(), key, &got); err != nil {
		t.Fatal(err)
	}
	// The token is silently dropped; only the reference survives.
	encoded, _ := json.Marshal(got.Spec)
	if strings.Contains(string(encoded), "hunter2") {
		t.Fatal("a token supplied to the API must never reach the stored object")
	}
	if got.Spec.AuthSecretRef == nil || got.Spec.AuthSecretRef.Name != "ref" {
		t.Fatal("the secret reference should have been kept")
	}
}

func TestScansAreScopedToTenants(t *testing.T) {
	mine := &securityv1alpha1.ArtifactScan{
		ObjectMeta: metav1.ObjectMeta{Name: "mine", Namespace: "team-a"},
		Spec:       securityv1alpha1.ArtifactScanSpec{ModelName: "m", ModelVersion: "1"},
	}
	theirs := &securityv1alpha1.ArtifactScan{
		ObjectMeta: metav1.ObjectMeta{Name: "theirs", Namespace: "team-b"},
		Spec:       securityv1alpha1.ArtifactScanSpec{ModelName: "secret", ModelVersion: "1"},
	}
	s := serverFor(t, mine, theirs)

	w := call(t, s.handleScans, subjectWith(authz.RoleOwner, "team-a"), "GET", "/api/scans", "")
	if strings.Contains(w.Body.String(), "secret") {
		t.Fatalf("a scan from another tenant leaked: %s", w.Body.String())
	}
}

// A scan still running has no risk score. Reporting zero would make it look
// like a clean result.
func TestUnscoredScanIsNotReportedAsZero(t *testing.T) {
	scan := &securityv1alpha1.ArtifactScan{
		ObjectMeta: metav1.ObjectMeta{Name: "running", Namespace: "cupel-system"},
		Spec:       securityv1alpha1.ArtifactScanSpec{ModelName: "m", ModelVersion: "1"},
		Status:     securityv1alpha1.ArtifactScanStatus{Phase: "Scanning"},
	}
	s := serverFor(t, scan)

	w := call(t, s.handleScans, subjectWith(authz.RoleAdmin), "GET", "/api/scans", "")
	var body struct {
		Scans []scanView `json:"scans"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Scans) != 1 {
		t.Fatalf("want 1 scan, got %d", len(body.Scans))
	}
	if body.Scans[0].Scored {
		t.Fatal("a scan with no verdict must not report a score")
	}
}

func TestComplianceRequiresCapability(t *testing.T) {
	s := serverFor(t)
	// Viewer sees verdicts but not compliance.
	w := call(t, s.handleCompliance, subjectWith(authz.RoleViewer), "GET", "/api/compliance", "")
	if w.Code != http.StatusForbidden {
		t.Fatalf("a viewer must not read compliance reports, got %d", w.Code)
	}
	w = call(t, s.handleCompliance, subjectWith(authz.RoleAuditor), "GET", "/api/compliance", "")
	if w.Code != http.StatusOK {
		t.Fatalf("an auditor should read compliance reports, got %d", w.Code)
	}
}

func TestExceptionsRequireFindingAccess(t *testing.T) {
	s := serverFor(t)
	w := call(t, s.handleExceptions, subjectWith(authz.RoleViewer), "GET", "/api/exceptions", "")
	if w.Code != http.StatusForbidden {
		t.Fatalf("a viewer cannot see findings, so not the waivers against them either; got %d", w.Code)
	}
}

// An acceptance with no webhook-established identity must be reported as
// unsigned, not smoothed into looking attributed.
func TestUnsignedExceptionIsMarkedUnsigned(t *testing.T) {
	e := &securityv1alpha1.ArtifactException{
		ObjectMeta: metav1.ObjectMeta{Name: "waiver", Namespace: "cupel-system"},
		Spec: securityv1alpha1.ArtifactExceptionSpec{
			ModelName: "m", ModelVersion: "1", Reason: "reviewed",
		},
	}
	s := serverFor(t, e)

	w := call(t, s.handleExceptions, subjectWith(authz.RoleSecurity), "GET", "/api/exceptions", "")
	var body struct {
		Exceptions []exceptionView `json:"exceptions"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Exceptions[0].Signed {
		t.Fatal("an exception with no approver or timestamp is not signed")
	}
}

func TestParseDurationRejectsNonsense(t *testing.T) {
	if _, err := parseDuration("soon"); err == nil {
		t.Fatal("an unparseable duration must be rejected")
	}
	if _, err := parseDuration("-5m"); err == nil {
		t.Fatal("a negative interval must be rejected")
	}
	d, err := parseDuration("")
	if err != nil || d != nil {
		t.Fatal("an empty duration means unset, not an error")
	}
	d, err = parseDuration("24h")
	if err != nil || d == nil {
		t.Fatal("24h should parse")
	}
}
