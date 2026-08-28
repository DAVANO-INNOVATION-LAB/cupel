package api

import (
	"net/http"
	"strconv"

	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/audit"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/authz"
)

// defaultAuditWindow is how many of the most recent records are returned when
// the caller does not ask for a number. The whole chain is verified either
// way — the limit bounds what is transferred, never what is checked.
const defaultAuditWindow = 50

// maxAuditWindow caps a caller-supplied limit. A chain runs to hundreds of
// thousands of records in a busy cluster and no browser needs all of them in
// one response.
const maxAuditWindow = 500

// handleAudit serves the decision log and the proof that it is intact.
//
// The verdict says what was decided; this says who decided it, when, and that
// nobody has quietly edited the answer since. It is the record that outlives
// everything else — scans are pruned and their findings go with them, but the
// chain is what a regulator or an incident review actually reads.
func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, sub authz.Subject) {
	if !sub.Can(authz.CapViewAudit) {
		forbid(w, "your role cannot read the audit log")
		return
	}

	// The chain is cluster-wide and its records name a subject as
	// "model/version", with no namespace to filter on. More importantly, a
	// filtered chain cannot be verified at all: every record commits to the one
	// before it, so removing the entries a tenant may not see breaks the links
	// and the answer becomes "this log has been tampered with" for a reader who
	// has done nothing wrong. Serving a partial chain would trade the one
	// property the log exists to provide for a weaker version of a view that
	// already exists elsewhere, so a namespace-scoped subject is told plainly
	// that this is not theirs to read rather than handed something misleading.
	if !sub.Scope.AllNamespaces {
		forbid(w, "the audit log is cluster-wide and cannot be filtered to your "+
			"namespaces without breaking the proof that it is intact; it needs a "+
			"cluster-wide binding to read")
		return
	}

	limit := defaultAuditWindow
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "limit must be a positive whole number"})
			return
		}
		limit = min(n, maxAuditWindow)
	}

	rec := &audit.Recorder{Client: s.k8s, Namespace: s.cfg.Namespace}
	records, checkpoint, err := rec.Chain(r.Context())
	if err != nil {
		internalError(w, "cannot read the audit chain")
		return
	}

	// Verified over everything held, not over the window returned. A reader who
	// asks for ten records still learns whether the whole log is sound.
	verification := audit.VerifyFrom(records, checkpoint.Anchor(), checkpoint)

	window := records
	if len(window) > limit {
		window = window[len(window)-limit:]
	}
	// Newest first: the reason somebody opens this is almost always the most
	// recent decision.
	shown := make([]audit.Record, 0, len(window))
	for i := len(window) - 1; i >= 0; i-- {
		shown = append(shown, window[i])
	}

	body := map[string]any{
		"chain":    verification,
		"records":  shown,
		"retained": len(records),
		"showing":  len(shown),
	}
	if checkpoint != nil {
		body["checkpoint"] = checkpoint
		// An anchor means older records were archived out of the cluster. Saying
		// so distinguishes a short chain from a long one whose beginning is
		// simply held somewhere else.
		if a := checkpoint.Anchor(); a != nil {
			body["archived"] = a
		}
	}
	writeJSON(w, http.StatusOK, body)
}
