// Package metrics defines Cupel's Prometheus metrics.
//
// The question an operator most needs answered about a security gate is not
// "is it up" but "what did it let through, and why". A gate that fails open —
// as this one does by default, with failurePolicy: Ignore and
// --require-report=false — is indistinguishable from a working gate unless the
// admissions it waved through are counted. Everything here exists to make that
// visible.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"sigs.k8s.io/controller-runtime/pkg/metrics"
)

// Admission decision outcomes.
const (
	OutcomeAllowed        = "allowed"
	OutcomeDenied         = "denied"
	OutcomeAllowedNoScan  = "allowed_unscanned"
	OutcomeAllowedAudit   = "allowed_audit"
	OutcomeAllowedWarn    = "allowed_warn"
	OutcomeAllowedSkipped = "allowed_skip_annotation"
	// OutcomeAllowedUnidentified is a workload that looks like it serves a
	// model whose identity Cupel could not determine. It is counted apart
	// from OutcomeAllowed because the two are opposite facts — one is an
	// approval, the other is the gate admitting that it did not gate.
	OutcomeAllowedUnidentified = "allowed_unidentified_model"
	OutcomeError               = "error"
)

var (
	// AuditWriteFailures counts admission decisions the gate could not append
	// to the tamper-evident chain.
	//
	// A failed write never changes the decision — losing the paper trail must
	// not turn a denial into an admission. The consequence is that the chain
	// can fall silently behind reality, so any non-zero value here means the
	// audit trail is incomplete for that namespace and cannot be read as one.
	AuditWriteFailures = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cupel_audit_write_failures_total",
			Help: "Admission decisions that could not be appended to the audit chain. Any non-zero value means the audit trail is incomplete.",
		},
		[]string{"namespace"},
	)

	// AdmissionDecisions counts what the gate did, by outcome.
	//
	// allowed_unscanned is the number that matters: it is how often a workload
	// was admitted purely because Cupel had nothing to say about it. A rising
	// value means coverage is incomplete, not that models are safe.
	AdmissionDecisions = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cupel_admission_decisions_total",
			Help: "Admission decisions by outcome. allowed_unscanned counts workloads admitted because no security report existed.",
		},
		[]string{"outcome", "namespace"},
	)

	// AdmissionDuration tracks how long the gate takes to decide. The webhook
	// has a 10s API-server timeout, past which the failurePolicy decides —
	// so latency here is a correctness concern, not just a performance one.
	AdmissionDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "cupel_admission_duration_seconds",
			Help:    "Time spent evaluating an admission request.",
			Buckets: []float64{.001, .005, .01, .05, .1, .5, 1, 2.5, 5, 10},
		},
	)

	// ScanVerdicts counts completed scans by the verdict they reached.
	ScanVerdicts = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cupel_scan_verdicts_total",
			Help: "Completed scans by verdict.",
		},
		[]string{"verdict"},
	)

	// ScanDuration measures a scan from creation to verdict. The buckets run
	// long because a large artifact over a slow link legitimately takes tens
	// of minutes.
	ScanDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "cupel_scan_duration_seconds",
			Help:    "Time from ArtifactScan creation to a final verdict.",
			Buckets: prometheus.ExponentialBuckets(10, 2, 10),
		},
	)

	// ScannerResults counts individual scanner outcomes, so a scanner that is
	// silently erroring on every artifact is visible before its absence gets
	// mistaken for a clean bill of health.
	ScannerResults = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cupel_scanner_results_total",
			Help: "Scanner completions by scanner and status.",
		},
		[]string{"scanner", "status"},
	)

	// SourceSyncFailures counts failed polls of a model source, labelled by
	// the source and a coarse reason.
	SourceSyncFailures = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "cupel_source_sync_failures_total",
			Help: "Failed model-source syncs by source and reason.",
		},
		[]string{"source", "reason"},
	)

	// ModelsTracked is the number of model versions a source last reported.
	ModelsTracked = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cupel_models_tracked",
			Help: "Model versions discovered by a source at its last successful sync.",
		},
		[]string{"source", "connector"},
	)
)

// Register adds every Cupel metric to the controller-runtime registry, which
// is what the manager already serves on its metrics endpoint.
func Register() {
	metrics.Registry.MustRegister(
		AdmissionDecisions,
		AdmissionDuration,
		ScanVerdicts,
		ScanDuration,
		ScannerResults,
		SourceSyncFailures,
		ModelsTracked,
		AuditWriteFailures,
	)
}
