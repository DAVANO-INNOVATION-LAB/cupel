//go:build stress

package stress

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kruntime "k8s.io/apimachinery/pkg/runtime"
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
	// The gate decodes workloads, and a decoder without apps/v1 fails closed —
	// which would make every admission look like a denial.
	if err := appsv1.AddToScheme(s); err != nil {
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

// What an informer cache costs per audit record.
//
// This is the number behind the out-of-memory kill: the cache holds one of
// these per record, for every record ever written, for as long as the process
// runs. Measured in isolation, because the point is the resident size of the
// objects themselves and nothing else.
func TestWhatCachingTheChainWouldCost(t *testing.T) {
	const n = 100_000

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	cache := make([]securityv1alpha1.AuditRecord, 0, n)
	for i := 0; i < n; i++ {
		cache = append(cache, securityv1alpha1.AuditRecord{
			ObjectMeta: metav1.ObjectMeta{
				Name:      fmt.Sprintf("audit-%012d", i+1),
				Namespace: "cupel-system",
				Labels:    map[string]string{"security.davano.io/audit-type": "verdict-issued"},
			},
			Spec: securityv1alpha1.AuditRecordSpec{
				Seq: int64(i + 1), Type: "verdict-issued",
				Subject: fmt.Sprintf("model-%d/v1", i), Actor: "system",
				Detail:   map[string]string{"verdict": "Approved", "risk": "12", "digest": "sha256:abcdef"},
				PrevHash: strings.Repeat("a", 64), Hash: strings.Repeat("b", 64),
			},
		})
	}

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(cache)

	delta := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	if delta <= 0 {
		t.Skipf("heap measurement unstable (delta %d)", delta)
	}
	per := float64(delta) / float64(n)
	limit := (512 << 20) / per
	t.Logf("%d cached records cost %.0f MiB, %.0f bytes each", n, float64(delta)/(1<<20), per)
	t.Logf("a 512Mi manager caching these would die at roughly %.0f records", limit)

	// A cluster scanning 200 model versions a week writes two records each.
	weeks := limit / (200 * 2)
	t.Logf("at 200 model versions a week that is about %.0f weeks before the manager "+
		"restarts and cannot come back", weeks)

	if opts := audit.ClientOptions(); opts.Cache == nil || len(opts.Cache.DisableFor) == 0 {
		t.Fatal("the manager still caches the chain: this is a live failure, not a measurement")
	}
}
