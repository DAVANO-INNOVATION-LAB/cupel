package maintenance

import (
	"context"
	"fmt"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
)

var now = time.Date(2026, 8, 24, 12, 0, 0, 0, time.UTC)

func testClient(t *testing.T, objs ...client.Object) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := securityv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...).Build()
}

func scan(name string, age time.Duration, finished bool) *securityv1alpha1.ArtifactScan {
	s := &securityv1alpha1.ArtifactScan{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "ml"},
		Spec: securityv1alpha1.ArtifactScanSpec{
			ModelName: "fraud", ModelVersion: "v1",
		},
	}
	if finished {
		t := metav1.NewTime(now.Add(-age))
		s.Status.Phase = "Completed"
		s.Status.CompletionTime = &t
	}
	return s
}

func names(t *testing.T, c client.Client) []string {
	t.Helper()
	var list securityv1alpha1.ArtifactScanList
	if err := c.List(context.Background(), &list); err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, s := range list.Items {
		out = append(out, s.Name)
	}
	return out
}

func TestOldFinishedScansArePruned(t *testing.T) {
	c := testClient(t,
		scan("ancient", 200*24*time.Hour, true),
		scan("recent", 2*24*time.Hour, true),
	)
	p := &Pruner{Client: c, Now: func() time.Time { return now }}

	n, err := p.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("pruned %d, want 1", n)
	}
	if got := names(t, c); len(got) != 1 || got[0] != "recent" {
		t.Fatalf("wrong scans left: %v", got)
	}
}

// A scan that has not finished is not old, it is in progress.
func TestAnUnfinishedScanIsNeverPruned(t *testing.T) {
	c := testClient(t, scan("still-running", 0, false))
	p := &Pruner{Client: c, Now: func() time.Time { return now.Add(10 * 365 * 24 * time.Hour) }}

	n, err := p.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("an unfinished scan was deleted because it had no completion time to be recent")
	}
}

// The admission gate reads the model's security report, which points at a scan.
// Deleting that scan would leave a verdict in force with its evidence gone.
func TestTheScanBehindALiveVerdictIsKept(t *testing.T) {
	c := testClient(t,
		scan("ancient-but-current", 200*24*time.Hour, true),
		scan("ancient-superseded", 200*24*time.Hour, true),
		&securityv1alpha1.ModelSecurityReport{
			ObjectMeta: metav1.ObjectMeta{Name: "fraud-v1", Namespace: "ml"},
			Spec: securityv1alpha1.ModelSecurityReportSpec{
				ModelName: "fraud", ModelVersion: "v1", ScanRef: "ancient-but-current",
			},
		},
	)
	p := &Pruner{Client: c, Now: func() time.Time { return now }}

	n, err := p.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("pruned %d, want only the superseded one", n)
	}
	got := names(t, c)
	if len(got) != 1 || got[0] != "ancient-but-current" {
		t.Fatalf("retention deleted the scan the current verdict rests on: %v", got)
	}
}

// Someone has to be able to turn this off.
func TestANegativeMaxAgeNeverPrunes(t *testing.T) {
	c := testClient(t, scan("ancient", 5000*24*time.Hour, true))
	p := &Pruner{Client: c, MaxAge: -1, Now: func() time.Time { return now }}

	n, err := p.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 || len(names(t, c)) != 1 {
		t.Fatal("retention ran when it was switched off")
	}
}

// The point of the exercise: the object count settles instead of climbing.
func TestTheObjectCountSettles(t *testing.T) {
	var objs []client.Object
	// Two years of a cluster scanning two hundred model versions a week, at one
	// scan each. Reports are owned by their scan and go with it.
	for week := 0; week < 104; week++ {
		for i := 0; i < 200; i++ {
			objs = append(objs, scan(fmt.Sprintf("s-%03d-%03d", week, i),
				time.Duration(104-week)*7*24*time.Hour, true))
		}
	}
	c := testClient(t, objs...)
	before := len(names(t, c))

	p := &Pruner{Client: c, Now: func() time.Time { return now }}
	if _, err := p.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	after := len(names(t, c))

	t.Logf("two years of scanning: %d scans before retention, %d after", before, after)
	if after >= before {
		t.Fatal("retention removed nothing")
	}
	// 90 days is roughly thirteen weeks of scans.
	if after > 14*200 {
		t.Errorf("%d scans left after a 90-day retention, want about %d", after, 13*200)
	}
}
