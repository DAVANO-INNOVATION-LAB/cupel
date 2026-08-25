package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/audit"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/controller"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/maintenance"
	cupelwebhook "github.com/DAVANO-INNOVATION-LAB/cupel/internal/webhook"
)

// A year of ordinary operation, run through the parts that were never bounded.
//
// Everything about resisting an attacker was thought through here. Nothing about
// surviving a year of being used was: the audit chain grew until the manager ran
// out of memory, and nothing in the codebase deleted a single object. This walks
// the whole shape of that year and checks the three things that have to remain
// true at the end of it — the log still verifies, the stored size has settled,
// and the gate still refuses what it refused on day one.
func TestAYearOfOperationLeavesAWorkingSystem(t *testing.T) {
	ctx := context.Background()
	scheme := admissionScheme(t)
	c := fake.NewClientBuilder().WithScheme(scheme).Build()

	recorder := &audit.Recorder{Client: c, Namespace: "cupel-system"}
	archiveDir := t.TempDir()
	sink := audit.DirSink{Dir: archiveDir}
	archiver := &audit.Archiver{Recorder: recorder, Sink: sink, Threshold: 500, Retain: 100}
	pruner := &maintenance.Pruner{Client: c, MaxAge: 90 * 24 * time.Hour}

	now := time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)
	pruner.Now = func() time.Time { return now }

	// Fifty-two weeks, twenty model versions a week: a scan, its verdict record
	// and its admission record each time.
	const weeks, perWeek = 52, 20
	totalScans := 0
	for w := 0; w < weeks; w++ {
		age := time.Duration(weeks-w) * 7 * 24 * time.Hour
		for i := 0; i < perWeek; i++ {
			name := fmt.Sprintf("m-%02d-%02d", w, i)
			completion := metav1.NewTime(now.Add(-age))

			scan := &securityv1alpha1.ArtifactScan{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ml"},
				Spec: securityv1alpha1.ArtifactScanSpec{
					ModelName: name, ModelVersion: "v1",
				},
			}
			scan.Status.Phase = "Completed"
			scan.Status.CompletionTime = &completion
			if err := c.Create(ctx, scan); err != nil {
				t.Fatal(err)
			}
			totalScans++

			if _, err := recorder.Append(ctx, audit.VerdictIssued(name, "v1", "Approved", 3, "")); err != nil {
				t.Fatal(err)
			}
			if _, err := recorder.Append(ctx, audit.DeploymentDecision(
				name, "v1", "ml", "serving", true, "verdict Approved")); err != nil {
				t.Fatal(err)
			}
		}

		// Maintenance runs on its schedule throughout, not once at the end.
		if _, err := archiver.Run(ctx); err != nil {
			t.Fatalf("week %d: archive failed: %v", w, err)
		}
	}

	pruned, err := pruner.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// --- 1. the log still verifies, end to end ---
	records, cp, err := recorder.Chain(ctx)
	if err != nil {
		t.Fatal(err)
	}
	written := uint64(weeks * perWeek * 2)
	v := audit.VerifyFrom(records, cp.Anchor(), cp)
	if !v.Valid {
		t.Fatalf("after a year the audit chain does not verify: %v", v.Problems)
	}
	if v.Length != written {
		t.Errorf("the log accounts for %d records, %d were written: records were lost", v.Length, written)
	}

	// --- 2. what is stored has settled ---
	var storedRecords securityv1alpha1.AuditRecordList
	if err := c.List(ctx, &storedRecords); err != nil {
		t.Fatal(err)
	}
	var storedScans securityv1alpha1.ArtifactScanList
	if err := c.List(ctx, &storedScans); err != nil {
		t.Fatal(err)
	}

	t.Logf("a year: %d audit records written, %d still in etcd (%d archived)",
		written, len(storedRecords.Items), v.Anchored)
	t.Logf("        %d scans created, %d pruned, %d still in etcd",
		totalScans, pruned, len(storedScans.Items))

	if uint64(len(storedRecords.Items)) >= written {
		t.Errorf("%d of %d records still stored: the chain is not being archived",
			len(storedRecords.Items), written)
	}
	if len(storedRecords.Items) > archiver.Threshold {
		t.Errorf("%d records stored, above the %d threshold: archiving is not keeping up",
			len(storedRecords.Items), archiver.Threshold)
	}
	if len(storedScans.Items) >= totalScans {
		t.Errorf("%d of %d scans still stored: retention is not running",
			len(storedScans.Items), totalScans)
	}

	// --- 3. the archive plus what is left reconstitutes the year ---
	//
	// This is the claim archiving has to earn. The records were moved, not
	// discarded, so reading the segments back and putting the retained tail on
	// the end must give the same log that was written — verifying from genesis,
	// with nothing missing.
	entries, err := os.ReadDir(archiveDir)
	if err != nil {
		t.Fatal(err)
	}
	var segments []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".jsonl") {
			segments = append(segments, e.Name())
		}
	}
	sort.Strings(segments)
	if len(segments) == 0 {
		t.Fatal("a year of scanning produced no archive segments")
	}

	var rebuilt []audit.Record
	for _, name := range segments {
		data, err := os.ReadFile(filepath.Join(archiveDir, name))
		if err != nil {
			t.Fatalf("segment %s cannot be read back: %v", name, err)
		}
		dec := json.NewDecoder(bytes.NewReader(data))
		for dec.More() {
			var r audit.Record
			if err := dec.Decode(&r); err != nil {
				t.Fatalf("segment %s does not parse: %v", name, err)
			}
			rebuilt = append(rebuilt, r)
		}
	}
	t.Logf("        %d segments on disk holding %d records", len(segments), len(rebuilt))

	rebuilt = append(rebuilt, records...)
	whole := audit.Verify(rebuilt, cp)
	if !whole.Valid {
		t.Fatalf("the archive and the retained tail do not reassemble into the log: %v", whole.Problems)
	}
	if uint64(len(rebuilt)) != written {
		t.Fatalf("reassembled %d records, %d were written: the archive lost some",
			len(rebuilt), written)
	}

	// --- 4. the gate still refuses what it refused on day one ---
	blockedReport := &securityv1alpha1.ModelSecurityReport{
		ObjectMeta: metav1.ObjectMeta{
			Name: controller.ModelReportName("hostile", "v1"), Namespace: "ml",
		},
		Spec: securityv1alpha1.ModelSecurityReportSpec{ModelName: "hostile", ModelVersion: "v1"},
	}
	blockedReport.Status.Verdict = "Blocked"
	blockedReport.Status.RiskScore = 90
	blockedReport.Status.LastScanTime = &metav1.Time{Time: now}

	gate := &cupelwebhook.ModelGate{
		Client: fake.NewClientBuilder().WithScheme(scheme).WithObjects(blockedReport).Build(),
	}
	if err := gate.InjectDecoder(admission.NewDecoder(scheme)); err != nil {
		t.Fatal(err)
	}
	if resp := gate.Handle(ctx, deploymentFor(t, "hostile", "v1")); resp.Allowed {
		t.Fatal("after a year of maintenance the gate admitted a blocked model")
	}
}
