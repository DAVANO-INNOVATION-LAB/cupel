package audit

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// A default install has three writers before a single pod is admitted: the scan
// controller, the promotion controller and the admission webhook. Under load
// the webhook's writers scale with how many pods are being admitted at once.
//
// This used to drop a quarter of the log at eight writers. Two things caused
// it, and both look like sensible code: a small fixed retry budget, and a
// loser advancing one position at a time while the head moved faster than that.
// Every dropped record is a decision that happened and was never written down.
func TestConcurrentAppendsDoNotDropRecords(t *testing.T) {
	const writers, each = 8, 60

	r := testRecorder(t)
	ctx := context.Background()

	var wg sync.WaitGroup
	var lost int64
	seq := sync.Map{}
	var collisions int64

	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				rec, err := r.Append(ctx, Record{
					Type:    EventDeploymentAdmitted,
					Subject: fmt.Sprintf("w%d/v%d", w, i),
				})
				if err != nil {
					atomic.AddInt64(&lost, 1)
					continue
				}
				if _, dup := seq.LoadOrStore(rec.Seq, w); dup {
					atomic.AddInt64(&collisions, 1)
				}
			}
		}(w)
	}
	wg.Wait()

	if lost > 0 {
		t.Errorf("%d of %d decisions never reached the audit chain under %d concurrent writers",
			lost, writers*each, writers)
	}
	if collisions > 0 {
		t.Errorf("%d records were issued a sequence number another record already had", collisions)
	}

	records, cp, err := r.Chain(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != writers*each {
		t.Errorf("%d records stored, %d appended", len(records), writers*each)
	}
	if v := VerifyFrom(records, cp.Anchor(), cp); !v.Valid {
		t.Fatalf("concurrent appends produced a chain that does not verify: %v", v.Problems)
	}
}

// alwaysTaken is a chain whose head is permanently contended: every position a
// writer tries has just been claimed by somebody else.
type alwaysTaken struct {
	client.Client
	attempts int64
}

func (c *alwaysTaken) Create(_ context.Context, o client.Object, _ ...client.CreateOption) error {
	atomic.AddInt64(&c.attempts, 1)
	return apierrors.NewAlreadyExists(
		schema.GroupResource{Group: "security.davano.io", Resource: "auditrecords"},
		o.GetName())
}

// The attempt ceiling is a runaway guard, not a deadline: what actually stops a
// contended append is the caller's context. That only holds if the retry loop
// gives the deadline up promptly — otherwise raising the ceiling trades a
// dropped record for an admission webhook that hangs until Kubernetes times it
// out, which is a worse failure and a harder one to see.
func TestAContendedAppendStopsAtTheCallersDeadline(t *testing.T) {
	stub := &alwaysTaken{Client: testRecorder(t).Client}
	r := &Recorder{Client: stub, Namespace: "cupel-system"}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := r.Append(ctx, Record{Type: EventDeploymentAdmitted, Subject: "w/v"})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("an append that never won a race reported success")
	}
	// Generous, because a loaded CI machine is slow — but far short of what
	// 4096 attempts would take, which is the thing being ruled out.
	if elapsed > 3*time.Second {
		t.Errorf("the append ran %v past a 200ms deadline; the context is not bounding it", elapsed)
	}
	if n := atomic.LoadInt64(&stub.attempts); n >= maxAppendAttempts {
		t.Errorf("burned the whole %d-attempt guard (%d) instead of stopping at the deadline",
			maxAppendAttempts, n)
	}
}
