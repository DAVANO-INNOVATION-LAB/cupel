//go:build mlflow_live

// This test drives a real MLflow tracking server in Docker end to end:
// register a malicious pickle model, then run Cupel's full source pipeline
// (List -> Resolve -> inspect -> policy -> WriteBack) against it and assert the
// version is Quarantined and the verdict is written back as an MLflow tag.
//
// It is gated behind the mlflow_live build tag so the default suite stays
// Docker-free. Run it with:
//
//	go test -tags mlflow_live -run TestMLflowLive ./internal/modelsource/ -v
//
// Requires Docker and the ghcr.io/mlflow/mlflow:v2.19.0 image.
package modelsource

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"testing"
	"time"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/inspector"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/policy"
)

const (
	mlflowImage     = "ghcr.io/mlflow/mlflow:v2.19.0"
	mlflowContainer = "cupel-mlflow-live-test"
	mlflowPort      = "5077"
	mlflowModelName = "fraud-detector"
)

func TestMLflowLive(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}

	baseURL := "http://localhost:" + mlflowPort
	startMLflow(t)
	registerMaliciousModel(t)

	src := NewMLflow(MLflowOptions{BaseURL: baseURL})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// --- List ---
	versions, err := src.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var target *Version
	for i := range versions {
		if versions[i].ModelName == mlflowModelName {
			target = &versions[i]
			break
		}
	}
	if target == nil {
		t.Fatalf("List did not return %q; got %+v", mlflowModelName, versions)
	}
	t.Logf("listed %s/%s source=%s", target.ModelName, target.Version, target.Artifact.URI)

	// --- Resolve ---
	dest := t.TempDir()
	artifact, err := src.Resolve(ctx, *target, dest)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if artifact.SizeBytes == 0 {
		t.Fatal("Resolve staged 0 bytes")
	}

	// --- Inspect + policy (the same spine the operator and CLI run) ---
	report, err := inspector.Inspect(dest, inspector.DefaultLimits())
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if len(report.Findings) == 0 {
		t.Fatal("inspector found nothing in a malicious pickle")
	}
	sev := severityCounts(report.Findings)
	result := securityv1alpha1.ScannerResult{
		Scanner: "model-inspector", Status: "Failed",
		Findings: int32(len(report.Findings)), Severities: sev,
	}
	eval := policy.Evaluate(
		[]securityv1alpha1.ScannerResult{result},
		securityv1alpha1.ArtifactRef{URI: target.Artifact.URI, Format: "pickle"},
		nil, nil, time.Now(),
	)
	if eval.Verdict != securityv1alpha1.VerdictQuarantined {
		t.Fatalf("verdict = %q, want Quarantined (findings: %+v)", eval.Verdict, report.Findings)
	}
	if eval.RiskScore < 50 {
		t.Errorf("risk score = %d, want >= 50 for a load-time RCE", eval.RiskScore)
	}
	t.Logf("verdict=%s risk=%d findings=%d", eval.Verdict, eval.RiskScore, len(report.Findings))

	// --- WriteBack ---
	verdict := Verdict{
		Verdict: eval.Verdict, RiskScore: eval.RiskScore,
		Malware: eval.MalwareStatus, Secrets: eval.SecretsStatus,
		ScanTime: time.Now(),
	}
	if err := src.WriteBack(ctx, *target, verdict); err != nil {
		t.Fatalf("WriteBack: %v", err)
	}

	// Confirm the tag is readable back through the REST API.
	got := readVerdictTag(t, baseURL, target.Version)
	if got != securityv1alpha1.VerdictQuarantined {
		t.Fatalf("verdict tag written back = %q, want Quarantined", got)
	}
	t.Logf("write-back confirmed: %s=%s on %s v%s", TagVerdict, got, mlflowModelName, target.Version)
}

func startMLflow(t *testing.T) {
	t.Helper()
	_ = exec.Command("docker", "rm", "-f", mlflowContainer).Run()
	run := exec.Command("docker", "run", "-d", "--name", mlflowContainer,
		"-p", mlflowPort+":5000", mlflowImage,
		"mlflow", "server", "--host", "0.0.0.0", "--port", "5000",
		"--backend-store-uri", "sqlite:////tmp/mlflow.db",
		"--artifacts-destination", "/tmp/artifacts", "--serve-artifacts",
	)
	if out, err := run.CombinedOutput(); err != nil {
		t.Fatalf("docker run mlflow: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", mlflowContainer).Run() })

	deadline := time.Now().Add(60 * time.Second)
	url := "http://localhost:" + mlflowPort + "/api/2.0/mlflow/registered-models/search"
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return
			}
		}
		time.Sleep(time.Second)
	}
	t.Fatal("mlflow did not become ready within 60s")
}

// registerMaliciousModel logs a protocol-5 pickle whose __reduce__ runs
// os.system, then registers it — the canonical model-supply-chain payload.
func registerMaliciousModel(t *testing.T) {
	t.Helper()
	script := `
import mlflow, pickle, os
mlflow.set_tracking_uri('http://localhost:5000')
class Exploit:
    def __reduce__(self):
        return (os.system, ('echo pwned',))
with mlflow.start_run() as run:
    with open('/tmp/weights.pkl','wb') as f:
        pickle.dump(Exploit(), f)
    mlflow.log_artifact('/tmp/weights.pkl', artifact_path='model')
    mlflow.register_model(f'runs:/{run.info.run_id}/model', '` + mlflowModelName + `')
print('registered')
`
	cmd := exec.Command("docker", "exec", mlflowContainer, "python", "-c", script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("register model: %v: %s", err, out)
	}
}

func severityCounts(findings []securityv1alpha1.Finding) securityv1alpha1.SeverityCounts {
	var c securityv1alpha1.SeverityCounts
	for _, f := range findings {
		switch f.Severity {
		case "Critical":
			c.Critical++
		case "High":
			c.High++
		case "Medium":
			c.Medium++
		case "Low":
			c.Low++
		default:
			c.Unknown++
		}
	}
	return c
}

func readVerdictTag(t *testing.T, baseURL, version string) string {
	t.Helper()
	u := fmt.Sprintf("%s/api/2.0/mlflow/model-versions/get?name=%s&version=%s", baseURL, mlflowModelName, version)
	resp, err := http.Get(u)
	if err != nil {
		t.Fatalf("get model version: %v", err)
	}
	defer resp.Body.Close()

	var payload struct {
		ModelVersion struct {
			Tags []struct {
				Key   string `json:"key"`
				Value string `json:"value"`
			} `json:"tags"`
		} `json:"model_version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode model version: %v", err)
	}
	for _, tag := range payload.ModelVersion.Tags {
		if tag.Key == TagVerdict {
			return tag.Value
		}
	}
	return ""
}
