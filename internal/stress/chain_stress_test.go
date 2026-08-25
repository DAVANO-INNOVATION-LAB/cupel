//go:build stress

package stress

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	kruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/audit"
)

func stressScheme(t testing.TB) *kruntime.Scheme {
	t.Helper()
	s := kruntime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := securityv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func stressRecorder(t testing.TB) (*audit.Recorder, client.Client) {
	c := fake.NewClientBuilder().WithScheme(stressScheme(t)).Build()
	return &audit.Recorder{Client: c, Namespace: "cupel-system"}, c
}

// Append is supposed to cost the same at record one and record half a million.
// If it does not, the fix that made it O(1) did not hold, and the cost returns
// as a slow creep that nobody attributes to the audit log.
func TestAppendCostDoesNotGrowWithTheChain(t *testing.T) {
	r, _ := stressRecorder(t)
	ctx := context.Background()

	const total = 200_000
	const sample = 2_000

	var marks []struct {
		at  int
		per time.Duration
	}

	start := time.Now()
	batch := time.Now()
	for i := 0; i < total; i++ {
		if _, err := r.Append(ctx, audit.Record{
			Type: audit.EventVerdictIssued, Subject: fmt.Sprintf("m/v%d", i),
		}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		if (i+1)%sample == 0 {
			marks = append(marks, struct {
				at  int
				per time.Duration
			}{i + 1, time.Since(batch) / sample})
			batch = time.Now()
		}
	}
	elapsed := time.Since(start)

	first := marks[0].per
	last := marks[len(marks)-1].per
	t.Logf("%d appends in %s (%.0f/s)", total, elapsed.Round(time.Millisecond),
		float64(total)/elapsed.Seconds())
	t.Logf("per-append at %d: %s   at %d: %s   ratio %.2fx",
		marks[0].at, first.Round(time.Microsecond),
		marks[len(marks)-1].at, last.Round(time.Microsecond),
		float64(last)/float64(first))

	// Some growth is the store's, not ours. An order of magnitude is not.
	if float64(last) > 10*float64(first) {
		t.Errorf("appending got %.1fx slower over %d records: the cost is scaling with "+
			"chain length again", float64(last)/float64(first), total)
	}
}

// Two controllers and a webhook share one chain. The design says the API server
// arbitrates: the record name embeds its sequence, so racing writers collide on
// AlreadyExists and the loser rebuilds on the winner. That has never been run.
func TestConcurrentWritersProduceOneLinearChain(t *testing.T) {
	r, _ := stressRecorder(t)
	ctx := context.Background()

	const writers = 24
	const each = 500

	var wg sync.WaitGroup
	var failures int64
	seen := sync.Map{}
	var duplicates int64

	start := time.Now()
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				rec, err := r.Append(ctx, audit.Record{
					Type:    audit.EventVerdictIssued,
					Subject: fmt.Sprintf("w%d/v%d", w, i),
				})
				if err != nil {
					atomic.AddInt64(&failures, 1)
					continue
				}
				if _, loaded := seen.LoadOrStore(rec.Seq, w); loaded {
					atomic.AddInt64(&duplicates, 1)
				}
			}
		}(w)
	}
	wg.Wait()
	elapsed := time.Since(start)

	records, cp, err := r.Chain(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d writers x %d appends in %s: %d stored, %d failed, %d sequence collisions",
		writers, each, elapsed.Round(time.Millisecond), len(records), failures, duplicates)

	if duplicates > 0 {
		t.Errorf("%d records were handed the same sequence number: two writers both "+
			"believed they had a position", duplicates)
	}
	if failures > 0 {
		t.Errorf("%d appends failed outright under contention; the audit trail is "+
			"incomplete by that many decisions", failures)
	}
	v := audit.VerifyFrom(records, cp.Anchor(), cp)
	if !v.Valid {
		t.Fatalf("concurrent writers produced a chain that does not verify: %v", v.Problems)
	}
	if want := writers * each; len(records) != want {
		t.Errorf("%d records stored, %d were appended: %d went missing", len(records), want, want-len(records))
	}
}

// The claim behind the cache fix is that memory stops tracking chain length.
// Measure what a retained chain actually costs in the process.
func TestRetainedChainMemoryFootprint(t *testing.T) {
	r, c := stressRecorder(t)
	ctx := context.Background()

	var before runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	const n = 100_000
	for i := 0; i < n; i++ {
		if _, err := r.Append(ctx, audit.VerdictIssued(
			fmt.Sprintf("model-%d", i), "v1", "Approved", 12, "sha256:abcdef")); err != nil {
			t.Fatal(err)
		}
	}

	var after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&after)

	perRecord := float64(after.HeapAlloc-before.HeapAlloc) / float64(n)
	t.Logf("%d records held in the store: %.1f MiB heap, %.0f bytes per record",
		n, float64(after.HeapAlloc-before.HeapAlloc)/(1<<20), perRecord)

	// Extrapolate the failure the audit predicted, against a 512Mi limit.
	atLimit := (512 << 20) / perRecord
	t.Logf("at %.0f bytes each, a 512Mi process would hold about %.0f records", perRecord, atLimit)

	// The number that matters is not this one — it is that the manager no
	// longer holds them at all. Confirm the exclusion is still in force.
	opts := audit.ClientOptions()
	if opts.Cache == nil || len(opts.Cache.DisableFor) == 0 {
		t.Fatal("the manager would cache this")
	}
	_ = c
	_ = schema.GroupVersionKind{}
}
