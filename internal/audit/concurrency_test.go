package audit

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
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
