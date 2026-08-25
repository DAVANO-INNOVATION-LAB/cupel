package maintenance

import (
	"context"
	"time"

	"github.com/go-logr/logr"

	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/audit"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/metrics"
)

// DefaultInterval is how often maintenance runs.
//
// Nothing here is urgent. The chain has to grow by tens of thousands of records
// before archiving has anything to do, and retention measures in months, so
// running often would only mean listing objects to discover there is nothing to
// remove.
const DefaultInterval = time.Hour

// Loop runs archiving and retention on a schedule, and publishes the size of
// the things that grow.
//
// It is a leader-elected runnable: two replicas archiving the same chain would
// race to write the same segment and then race to move the same boundary.
type Loop struct {
	Archiver  *audit.Archiver
	Pruner    *Pruner
	Namespace string
	Interval  time.Duration
	Log       logr.Logger
}

// NeedLeaderElection keeps this to one replica.
func (l *Loop) NeedLeaderElection() bool { return true }

// Start runs maintenance until the context is cancelled.
func (l *Loop) Start(ctx context.Context) error {
	interval := l.Interval
	if interval <= 0 {
		interval = DefaultInterval
	}

	// Publish the sizes straight away, so a dashboard has a value before the
	// first hour is up and an operator inheriting a long-running cluster sees
	// where it already stands.
	l.observe(ctx)
	l.once(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			l.observe(ctx)
			l.once(ctx)
		}
	}
}

func (l *Loop) once(ctx context.Context) {
	if l.Archiver != nil && l.Archiver.Sink != nil {
		n, err := l.Archiver.Run(ctx)
		switch {
		case err != nil:
			metrics.AuditArchiveRuns.WithLabelValues(l.Namespace, "error").Inc()
			// Worth saying out loud. A failing archive changes nothing today,
			// which is exactly why it can run for months before anyone looks.
			l.Log.Error(err, "audit archive failed; the chain will keep growing until this is fixed")
		case n > 0:
			metrics.AuditArchiveRuns.WithLabelValues(l.Namespace, "archived").Inc()
			metrics.AuditRecordsArchived.WithLabelValues(l.Namespace).Add(float64(n))
			l.Log.Info("archived audit records", "count", n)
		default:
			metrics.AuditArchiveRuns.WithLabelValues(l.Namespace, "nothing-to-do").Inc()
		}
	}

	if l.Pruner != nil {
		n, err := l.Pruner.Run(ctx)
		if err != nil {
			l.Log.Error(err, "scan retention failed")
		} else if n > 0 {
			metrics.ScanObjectsPruned.WithLabelValues(l.Pruner.Namespace).Add(float64(n))
			l.Log.Info("pruned finished scans", "count", n)
		}
	}
}

// observe publishes how long the chain is and how much of it is still stored.
func (l *Loop) observe(ctx context.Context) {
	if l.Archiver == nil || l.Archiver.Recorder == nil {
		return
	}
	length, retained, err := l.Archiver.Recorder.Size(ctx)
	if err != nil {
		l.Log.Error(err, "could not measure the audit chain")
		return
	}
	metrics.AuditChainLength.WithLabelValues(l.Namespace).Set(float64(length))
	metrics.AuditChainRetained.WithLabelValues(l.Namespace).Set(float64(retained))
}
