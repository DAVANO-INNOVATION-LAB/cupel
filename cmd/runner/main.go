// Command runner is the in-pod half of Cupel. Scan Jobs invoke it three ways:
//
//	fetch    resolve an artifact URI and stage the bytes into the workspace
//	inspect  run the built-in model-format scanner over the workspace
//	aibom    describe the model itself and render its bill of materials
//	publish  parse a scanner's output and record an ArtifactScanReport
//
// Keeping these in one binary means the scan pod only needs the Cupel image
// plus the scanner image, and only the publish step ever holds cluster
// credentials.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/aibom"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/audit"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/compliance"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/controller"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/evidence"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/inspector"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/naming"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/provenance"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/resolver"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/results"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	var err error
	switch os.Args[1] {
	case "fetch":
		err = runFetch(ctx, os.Args[2:])
	case "inspect":
		err = runInspect(os.Args[2:])
	case "publish":
		err = runPublish(ctx, os.Args[2:])
	case "verify-provenance":
		err = runVerifyProvenance(os.Args[2:])
	case "aibom":
		err = runAIBOM(ctx, os.Args[2:])
	case "evidence":
		err = runBuildEvidence(ctx, os.Args[2:])
	case "verify-evidence":
		err = runVerifyEvidence(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "cupel-runner %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `cupel-runner - in-pod scan steps for Cupel

Usage:
  cupel-runner fetch   --uri URI --dest DIR [--metadata FILE]
  cupel-runner inspect --workspace DIR --out FILE
  cupel-runner publish --scan NAME --namespace NS --scanner NAME --format FMT --results FILE [--metadata FILE]
  cupel-runner verify-provenance --workspace DIR --out FILE
  cupel-runner aibom   --workspace DIR --out FILE [--bom-dir DIR]
  cupel-runner evidence --scan NAME --namespace NS [--out FILE]
  cupel-runner verify-evidence FILE

verify-evidence exit codes: 0 the bundle is intact, 4 it is not, 1 it could not be read.
`)
}

// artifactMetadata is handed from the fetch step to the publish step through
// the shared results volume, so the recorded digest is the one actually
// scanned rather than one re-derived later.
type artifactMetadata struct {
	URI       string `json:"uri"`
	Digest    string `json:"digest"`
	MediaType string `json:"mediaType"`
	SizeBytes int64  `json:"sizeBytes"`
}

func runFetch(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("fetch", flag.ExitOnError)
	uri := fs.String("uri", "", "artifact URI to resolve")
	dest := fs.String("dest", "/workspace", "directory to stage the artifact into")
	metadataPath := fs.String("metadata", "", "write resolved artifact metadata here")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *uri == "" {
		return fmt.Errorf("--uri is required")
	}

	reg := resolver.NewRegistry()
	if !reg.Supports(*uri) {
		return fmt.Errorf("no resolver for artifact URI %q", *uri)
	}

	start := time.Now()
	artifact, err := reg.Resolve(ctx, *uri, *dest)
	if err != nil {
		return err
	}
	fmt.Printf("staged %s (%d bytes, digest %s) in %s\n",
		artifact.URI, artifact.SizeBytes, artifact.Digest, time.Since(start).Round(time.Millisecond))

	if *metadataPath != "" {
		metadata := artifactMetadata{
			URI:       artifact.URI,
			Digest:    artifact.Digest,
			MediaType: artifact.MediaType,
			SizeBytes: artifact.SizeBytes,
		}
		if err := writeJSON(*metadataPath, metadata); err != nil {
			return err
		}
	}
	return nil
}

func runInspect(args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ExitOnError)
	workspace := fs.String("workspace", "/workspace", "staged artifact directory")
	out := fs.String("out", "", "write the findings report here")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("--out is required")
	}

	report, err := inspector.Inspect(*workspace, inspector.DefaultLimits())
	if err != nil {
		return err
	}
	fmt.Printf("inspected %d files, %d findings, formats %v\n",
		report.FilesScanned, len(report.Findings), report.Formats)

	// The inspector exits 0 even when it finds problems: the verdict is the
	// controller's to make, and a non-zero exit would mark the Job failed and
	// lose the findings.
	return writeJSON(*out, report)
}

// runAIBOM is the AI bill of materials scanner's entry point.
//
// It reads the model's own headers and renders CycloneDX 1.6 and SPDX 3.0.1
// alongside the findings, so the document and the risk assessment it belongs
// with are produced by the same pass over the same bytes and cannot be
// separated in transit.
func runAIBOM(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("aibom", flag.ExitOnError)
	workspace := fs.String("workspace", "/workspace", "staged artifact directory")
	out := fs.String("out", "", "write the findings report here")
	bomDir := fs.String("bom-dir", "", "write the rendered documents here")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("--out is required")
	}

	report, docs, err := aibom.Generate(ctx, *workspace, aibom.Options{})
	if err != nil {
		return err
	}

	if docs != nil && *bomDir != "" {
		for name, body := range map[string][]byte{
			"model.cdx.json":  docs.CycloneDX,
			"model.spdx.json": docs.SPDX,
		} {
			path := filepath.Join(*bomDir, name)
			// 0644 for the same reason writeJSON uses it: these are handed
			// between containers in the scan pod, which may run as different
			// UIDs, and the path is an emptyDir private to the pod.
			if err := os.WriteFile(path, body, 0o644); err != nil { //nolint:gosec // G306: shared within the pod's emptyDir by design
				return fmt.Errorf("write %s: %w", path, err)
			}
		}
	}

	if report.Generated {
		fmt.Printf("described %s model at %s: %d files, %d tensors, %d findings\n",
			report.Format, report.ModelPath, report.Files, report.TensorCount,
			len(report.Findings))
	} else {
		fmt.Printf("no bill of materials produced: %d findings\n", len(report.Findings))
	}

	// As with inspect, a non-zero exit would mark the Job failed and lose the
	// findings. The verdict belongs to the controller.
	return writeJSON(*out, report)
}

// runVerifyProvenance is the provenance scanner's entry point.
//
// The trust policy arrives as a file rather than over the API, because this
// step runs in a pod with no cluster credentials — only the publish step ever
// holds those. The controller renders the TrustedPublishers into a ConfigMap
// and projects it here read-only.
func runVerifyProvenance(args []string) error {
	fs := flag.NewFlagSet("verify-provenance", flag.ExitOnError)
	workspace := fs.String("workspace", "/workspace", "staged artifact directory")
	out := fs.String("out", "", "write the findings report here")
	policyPath := fs.String("trust-policy", "", "trust policy JSON rendered from TrustedPublishers")
	metadataPath := fs.String("metadata", "", "artifact metadata written by the fetch step")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("--out is required")
	}

	policy, err := loadTrustPolicy(*policyPath)
	if err != nil {
		return err
	}

	// The URI scopes which publishers may sign this artifact. Without it a
	// signature valid for one repository would admit an artifact from
	// anywhere, so a missing metadata file must not silently widen trust.
	artifactURI := ""
	if *metadataPath != "" {
		if meta, err := readArtifactMetadata(*metadataPath); err == nil {
			artifactURI = meta.URI
		}
	}

	verifier, err := provenance.NewVerifier(policy)
	if err != nil {
		// A bad trust root is a cluster configuration fault. Record it as a
		// finding rather than failing the Job, so the scan still produces a
		// report saying why provenance could not be established.
		return writeJSON(*out, provenanceReport{Findings: []securityv1alpha1.Finding{{
			ID:          provenance.FindingNotConfigured,
			Title:       "Trust root could not be loaded",
			Severity:    "Medium",
			Category:    "provenance",
			Description: err.Error(),
		}}})
	}

	result, err := verifier.Verify(*workspace, artifactURI)
	if err != nil {
		return err
	}

	report := provenanceReport{Findings: make([]securityv1alpha1.Finding, 0, len(result.Findings))}
	for _, f := range result.Findings {
		report.Findings = append(report.Findings, securityv1alpha1.Finding{
			ID:          f.ID,
			Title:       f.Title,
			Severity:    f.Severity,
			Category:    f.Category,
			Location:    f.Location,
			Description: f.Description,
		})
	}
	return writeJSON(*out, report)
}

type provenanceReport struct {
	Findings []securityv1alpha1.Finding `json:"findings"`
}

// loadTrustPolicy reads the rendered trust policy. A missing file is not an
// error: it means the cluster has not configured provenance, which the verifier
// reports as its own finding rather than treating as a scan failure.
func loadTrustPolicy(path string) (provenance.Policy, error) {
	if path == "" {
		return provenance.Policy{}, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return provenance.Policy{}, nil
		}
		return provenance.Policy{}, fmt.Errorf("read trust policy: %w", err)
	}
	var policy provenance.Policy
	if err := json.Unmarshal(raw, &policy); err != nil {
		return provenance.Policy{}, fmt.Errorf("parse trust policy: %w", err)
	}
	return policy, nil
}

func readArtifactMetadata(path string) (*artifactMetadata, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var meta artifactMetadata
	if err := json.Unmarshal(raw, &meta); err != nil {
		return nil, err
	}
	return &meta, nil
}

func runPublish(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("publish", flag.ExitOnError)
	scanName := fs.String("scan", "", "ArtifactScan this report belongs to")
	namespace := fs.String("namespace", "", "namespace of the ArtifactScan")
	scannerName := fs.String("scanner", "", "scanner that produced the results")
	format := fs.String("format", "", "result format")
	resultsPath := fs.String("results", "", "scanner output file")
	metadataPath := fs.String("metadata", "", "artifact metadata written by the fetch step")
	if err := fs.Parse(args); err != nil {
		return err
	}
	for name, value := range map[string]string{
		"--scan": *scanName, "--namespace": *namespace,
		"--scanner": *scannerName, "--format": *format, "--results": *resultsPath,
	} {
		if value == "" {
			return fmt.Errorf("%s is required", name)
		}
	}

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return err
	}
	if err := securityv1alpha1.AddToScheme(scheme); err != nil {
		return err
	}

	cfg, err := ctrl.GetConfig()
	if err != nil {
		return fmt.Errorf("load cluster config: %w", err)
	}
	k8s, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return fmt.Errorf("build client: %w", err)
	}

	status := "Passed"
	message := ""
	parsed, err := results.Parse(*format, *resultsPath)
	if err != nil {
		// A parse failure must not look like a clean scan.
		status = "Error"
		message = err.Error()
		parsed = &results.Parsed{}
	} else if parsed.Severities.Total() > 0 {
		status = "Failed"
		message = fmt.Sprintf("%d findings", parsed.Severities.Total())
	}

	now := metav1.Now()
	report := &securityv1alpha1.ArtifactScanReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:      naming.ScanReport(*scanName, *scannerName),
			Namespace: *namespace,
			Labels: map[string]string{
				"security.davano.io/scan":    *scanName,
				"security.davano.io/scanner": *scannerName,
			},
		},
		Scanner: *scannerName,
		ScanRef: *scanName,
		Summary: securityv1alpha1.ScannerResult{
			Scanner:        *scannerName,
			Status:         status,
			Findings:       parsed.Severities.Total(),
			Severities:     parsed.Severities,
			Drift:          parsed.Drift,
			Unexamined:     parsed.Unexamined,
			Produced:       parsed.Produced,
			Message:        message,
			CompletionTime: &now,
		},
		Findings: parsed.Findings,
	}

	if *metadataPath != "" {
		if metadata, err := readMetadata(*metadataPath); err == nil && metadata.Digest != "" {
			if report.Annotations == nil {
				report.Annotations = map[string]string{}
			}
			// The controller lifts this onto the ArtifactScan and then the
			// ModelSecurityReport, where the admission gate uses it to refuse
			// a verdict that does not belong to the bytes being deployed.
			report.Annotations[controller.AnnotationArtifactDigest] = metadata.Digest
			report.Annotations["security.davano.io/artifact-uri"] = metadata.URI
		}
	}

	if err := k8s.Create(ctx, report); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return fmt.Errorf("create scan report: %w", err)
		}
		// A retried Job re-publishes; overwrite the previous attempt.
		existing := &securityv1alpha1.ArtifactScanReport{}
		key := client.ObjectKey{Name: report.Name, Namespace: report.Namespace}
		if err := k8s.Get(ctx, key, existing); err != nil {
			return fmt.Errorf("get existing scan report: %w", err)
		}
		report.ResourceVersion = existing.ResourceVersion
		if err := k8s.Update(ctx, report); err != nil {
			return fmt.Errorf("update scan report: %w", err)
		}
	}

	fmt.Printf("published %s report for scan %s: %s (%d findings)\n",
		*scannerName, *scanName, status, parsed.Severities.Total())
	return nil
}

func readMetadata(path string) (artifactMetadata, error) {
	var metadata artifactMetadata
	data, err := os.ReadFile(path)
	if err != nil {
		return metadata, err
	}
	err = json.Unmarshal(data, &metadata)
	return metadata, err
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", path, err)
	}
	// 0644, not 0600: these files are handed between containers in the scan
	// pod (fetch writes metadata, publish reads it), and a scanner image may
	// run as a different UID than the runner. The path is an emptyDir private
	// to the pod, so world-readable inside it is the intent.
	if err := os.WriteFile(path, data, 0o644); err != nil { //nolint:gosec // G306: shared within the pod's emptyDir by design
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// runVerifyEvidence checks an evidence bundle offline.
//
// Offline is the requirement, not a convenience: a bundle is handed to an
// authorizing official who may have no access to the cluster that produced it,
// and frequently no network at all. Everything needed to check it is inside
// the file.
func runVerifyEvidence(args []string) error {
	fs := flag.NewFlagSet("verify-evidence", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "emit the verification result as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("an evidence bundle file is required")
	}

	raw, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	var bundle evidence.Bundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return fmt.Errorf("parse evidence bundle: %w", err)
	}

	result, err := evidence.Verify(&bundle)
	if err != nil {
		return err
	}

	if *asJSON {
		encoded, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(encoded))
	} else {
		fmt.Printf("subject:   %s/%s\n", bundle.Subject.Model, bundle.Subject.Version)
		fmt.Printf("verdict:   %s (risk %d)\n", bundle.Verdict.Decision, bundle.Verdict.RiskScore)
		fmt.Printf("produced:  %s by %s\n", bundle.GeneratedAt.Format(time.RFC3339), bundle.Producer)
		fmt.Printf("digest:    %s\n", statusWord(result.DigestMatches, "unmodified", "MODIFIED"))
		auditState := statusWord(result.ChainValid, "intact", "BROKEN")
		if len(bundle.Audit.Records) == 0 {
			auditState = "none recorded"
		}
		fmt.Printf("audit:     %s (%d record(s))\n", auditState, len(bundle.Audit.Records))
		fmt.Printf("coverage:  %d of %d scanners completed\n",
			bundle.Coverage.ScannersCompleted, bundle.Coverage.ScannersRequested)

		if len(result.Problems) > 0 {
			fmt.Println("\nproblems:")
			for _, p := range result.Problems {
				fmt.Printf("  - %s\n", p)
			}
		}
		if len(bundle.Coverage.OutOfScope) > 0 {
			fmt.Println("\nnot assessed by this tool:")
			for _, o := range bundle.Coverage.OutOfScope {
				fmt.Printf("  - %s\n", o)
			}
		}
	}

	// A distinct exit code so a pipeline can tell a failed check from a failed
	// run: an unreadable file exits 1, a bundle that does not verify exits 4.
	if !result.Valid {
		os.Exit(4)
	}
	return nil
}

func statusWord(ok bool, yes, no string) string {
	if ok {
		return yes
	}
	return no
}

// runBuildEvidence assembles an evidence bundle for one model version.
//
// It reads from the cluster and writes a file. That direction matters: the
// bundle exists so somebody who cannot reach the cluster — an assessor, an
// authorizing official, a customer's security team — can still check what was
// decided and on what basis.
func runBuildEvidence(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("evidence", flag.ExitOnError)
	scanName := fs.String("scan", "", "ArtifactScan to build a bundle for")
	namespace := fs.String("namespace", os.Getenv("POD_NAMESPACE"), "namespace of the scan")
	out := fs.String("out", "", "write the bundle here; default stdout")
	producer := fs.String("producer", "tessera", "identifier recorded as the producer")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *scanName == "" || *namespace == "" {
		return fmt.Errorf("--scan and --namespace are required")
	}

	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		return err
	}
	if err := securityv1alpha1.AddToScheme(scheme); err != nil {
		return err
	}
	cfg, err := ctrl.GetConfig()
	if err != nil {
		return fmt.Errorf("load cluster config: %w", err)
	}
	k8s, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return err
	}

	var scan securityv1alpha1.ArtifactScan
	if err := k8s.Get(ctx, client.ObjectKey{Name: *scanName, Namespace: *namespace}, &scan); err != nil {
		return fmt.Errorf("read scan: %w", err)
	}

	in := evidence.Input{
		Now:      time.Now(),
		Producer: *producer,
		Subject: evidence.Subject{
			Model: scan.Spec.ModelName, Version: scan.Spec.ModelVersion,
			ArtifactURI: scan.Spec.Artifact.URI, ArtifactDigest: scan.Status.ScannedDigest,
			Namespace: scan.Namespace,
		},
		Verdict: evidence.Verdict{
			Decision: scan.Status.Verdict, Policy: scan.Spec.PolicyRef,
			Trigger: scan.Spec.Trigger, TriggeredBy: scan.Spec.TriggeredBy,
		},
		Frameworks: []string{string(compliance.NISTAIRMF10), string(compliance.NIST80053R5)},
	}
	if scan.Status.RiskScore != nil {
		in.Verdict.RiskScore = *scan.Status.RiskScore
	}
	if scan.Status.CompletionTime != nil {
		in.Verdict.ScannedAt = scan.Status.CompletionTime.Time
	}

	// Every scanner the policy asked for, with whether it produced a result.
	// A scanner that did not run is the difference between "found nothing" and
	// "did not look", and the bundle has to carry it.
	for _, res := range scan.Status.Results {
		in.Scanners = append(in.Scanners, evidence.ScannerRun{
			Name:      res.Scanner,
			Completed: res.Status == "Passed" || res.Status == "Failed",
			Findings:  int(res.Findings),
			Message:   res.Message,
		})
	}

	// The findings behind the verdict, not a summary of them.
	var reports securityv1alpha1.ArtifactScanReportList
	if err := k8s.List(ctx, &reports, client.InNamespace(*namespace)); err != nil {
		return fmt.Errorf("list reports: %w", err)
	}
	for _, rep := range reports.Items {
		if rep.ScanRef == scan.Name {
			in.Findings = append(in.Findings, rep.Findings...)
		}
	}

	// Risks a human took responsibility for, with whether the identity was
	// established by the webhook or merely asserted.
	var exceptions securityv1alpha1.ArtifactExceptionList
	if err := k8s.List(ctx, &exceptions, client.InNamespace(*namespace)); err != nil {
		return fmt.Errorf("list exceptions: %w", err)
	}
	for _, ex := range exceptions.Items {
		if ex.Spec.ModelName != scan.Spec.ModelName || ex.Spec.ModelVersion != scan.Spec.ModelVersion {
			continue
		}
		acc := evidence.Acceptance{
			FindingIDs: ex.Spec.FindingIDs, Rules: ex.Spec.Rules,
			Reason: ex.Spec.Reason, ApprovedBy: ex.Spec.ApprovedBy,
			ScannedDigest: ex.Spec.ScannedDigest,
			Signed:        ex.Spec.ApprovedBy != "" && ex.Spec.ApprovedAt != nil,
		}
		if ex.Spec.ApprovedAt != nil {
			acc.ApprovedAt = ex.Spec.ApprovedAt.Time
		}
		if ex.Spec.ExpiresAt != nil {
			t := ex.Spec.ExpiresAt.Time
			acc.ExpiresAt = &t
		}
		in.Acceptances = append(in.Acceptances, acc)
	}

	// The whole chain and its checkpoint. Build verifies the chain and then
	// excerpts this subject's entries; filtering here first would hand it a
	// scattered set of records and ask whether they form a chain.
	recorder := &audit.Recorder{Client: k8s, Namespace: *namespace}
	if records, cp, err := recorder.Chain(ctx); err == nil {
		in.AuditChain = records
		in.AuditCheckpoint = cp
		in.AuditAnchor = cp.Anchor()
	}

	bundle, err := evidence.Build(in)
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')

	if *out == "" {
		_, err = os.Stdout.Write(encoded)
		return err
	}
	return os.WriteFile(*out, encoded, 0o600)
}
