package webhook

import (
	"context"
	"fmt"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/audit"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/metrics"
)

// Recording admission decisions into the tamper-evident chain.
//
// audit.DeploymentDecision and the DeploymentBlocked and DeploymentAdmitted
// event types existed from the beginning and nothing called them. The chain
// therefore held scans, verdicts and accepted risks — everything except the
// moment a model reached or failed to reach production, which is the event an
// authorizing official asks about first.
//
// Two decisions shape what gets written.
//
// Not every admission is recorded. A Deployment scaling to fifty replicas is
// fifty admission requests, and appending fifty records with a hash chain that
// serialises on a sequence number would turn a routine scale-up into API
// contention inside a webhook. An ordinary approval is also already implied by
// the VerdictIssued record it rests on. What is recorded is every denial, and
// every admission that happened *despite* something — an unscanned model, a
// skip annotation, audit or warn mode, an unidentifiable model. Those are the
// admissions nobody can reconstruct later, and they are rare.
//
// A failed write never changes the decision. The gate's job is to gate; losing
// the paper trail must not turn a denial into an admission or an admission into
// an error the failurePolicy then interprets. Failures are counted so a chain
// that has stopped recording is visible rather than assumed intact.
const auditWriteTimeout = 3 * time.Second

// auditableOutcomes are the admission outcomes worth a chain record. An
// ordinary approval is absent on purpose; see above.
var auditableOutcomes = map[string]bool{
	metrics.OutcomeDenied:              true,
	metrics.OutcomeAllowedNoScan:       true,
	metrics.OutcomeAllowedAudit:        true,
	metrics.OutcomeAllowedWarn:         true,
	metrics.OutcomeAllowedSkipped:      true,
	metrics.OutcomeAllowedUnidentified: true,
	metrics.OutcomeAllowedUnexamined:   true,
}

// recordDecision appends the admission decision to the audit chain when the
// outcome is one that cannot be reconstructed from the rest of the trail.
func (g *ModelGate) recordDecision(ctx context.Context, req admission.Request, obj *unstructured.Unstructured, ref ModelRef, outcome, reason string) {
	if g.Recorder == nil || !auditableOutcomes[outcome] {
		return
	}

	// The chain write must not inherit the admission request's deadline: a
	// caller that gives up does not make the decision unrecorded.
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditWriteTimeout)
	defer cancel()

	record := audit.DeploymentDecision(
		orUnknown(ref.Model), orUnknown(ref.Version),
		req.Namespace, workloadName(req, obj),
		outcome != metrics.OutcomeDenied, reason)

	// Who asked, and what for. Without these a record says a workload was
	// blocked without saying who tried, which is the first question asked of
	// an audit trail.
	record.Detail["outcome"] = outcome
	record.Detail["kind"] = obj.GetKind()
	record.Detail["operation"] = string(req.Operation)
	if req.UserInfo.Username != "" {
		record.Actor = req.UserInfo.Username
	}
	if ref.StorageURI != "" {
		record.Detail["storageURI"] = ref.StorageURI
	}
	if ref.Digest != "" {
		record.Detail["digest"] = ref.Digest
	}

	if _, err := g.Recorder.Append(writeCtx, record); err != nil {
		metrics.AuditWriteFailures.WithLabelValues(req.Namespace).Inc()
		logf.FromContext(ctx).Error(err, "could not record admission decision in the audit chain",
			"outcome", outcome, "model", ref.Model, "namespace", req.Namespace)
	}
}

// workloadName names the object the decision was about. On a CREATE the
// object's own name may still be empty because generateName has not been
// expanded yet, so the request's name is preferred where it exists.
func workloadName(req admission.Request, obj *unstructured.Unstructured) string {
	if req.Name != "" {
		return req.Name
	}
	if name := obj.GetName(); name != "" {
		return name
	}
	if gen := obj.GetGenerateName(); gen != "" {
		return gen + "<generated>"
	}
	return fmt.Sprintf("<unnamed %s>", obj.GetKind())
}
