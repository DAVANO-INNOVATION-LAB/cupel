//go:build stress

package stress

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/audit"
)

// How much concurrency does the chain tolerate before it starts losing records?
//
// A cluster runs at least three writers by default — the scan controller, the
// promotion controller and the admission webhook — and the webhook's writers
// scale with how many pods are being admitted at once. This maps where the
// retry budget runs out.
func TestWhereContentionStartsLosingRecords(t *testing.T) {
	for _, writers := range []int{1, 2, 4, 8, 16, 32, 64} {
		t.Run(fmt.Sprintf("%d-writers", writers), func(t *testing.T) {
			r, _ := stressRecorder(t)
			ctx := context.Background()
			const each = 200

			var wg sync.WaitGroup
			var lost int64
			var mu sync.Mutex
			reasons := map[string]int{}
			for w := 0; w < writers; w++ {
				wg.Add(1)
				go func(w int) {
					defer wg.Done()
					for i := 0; i < each; i++ {
						if _, err := r.Append(ctx, audit.Record{
							Type: audit.EventDeploymentAdmitted, Subject: fmt.Sprintf("w%d/v%d", w, i),
						}); err != nil {
							atomic.AddInt64(&lost, 1)
							mu.Lock()
							reasons[classify(err)]++
							mu.Unlock()
						}
					}
				}(w)
			}
			wg.Wait()

			total := int64(writers * each)
			pct := 100 * float64(lost) / float64(total)
			t.Logf("%2d writers: %d/%d decisions lost (%.1f%%)", writers, lost, total, pct)
			if lost > 0 {
				t.Errorf("%.1f%% of the audit trail was dropped at %d concurrent writers: %v",
					pct, writers, reasons)
			}
		})
	}
}

// classify buckets an append failure by what actually went wrong.
func classify(err error) string {
	m := err.Error()
	switch {
	case strings.Contains(m, "lost the head and could not read it back"):
		return "head-vanished"
	case strings.Contains(m, "lost 64 races"):
		return "retries-exhausted"
	case strings.Contains(m, "gave up after"):
		return "deadline"
	case strings.Contains(m, "already exists"):
		return "collision-escaped"
	default:
		return m
	}
}
