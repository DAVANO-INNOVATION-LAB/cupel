package api

import (
	"fmt"
	"net/http"
	"sort"

	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/authz"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/controller"
)

// handleBOM serves the bill of materials a model's scan produced.
//
// This is the document somebody would otherwise open Tessera Studio to read,
// except Studio browses a directory on a filesystem and this model is a cluster
// object: there is no path to hand it. The document is already here — the scan
// rendered it and the operator keeps it — so the shorter route is to serve it
// from where it is rather than send anybody somewhere else.
func (s *Server) handleBOM(w http.ResponseWriter, r *http.Request, sub authz.Subject) {
	model := r.URL.Query().Get("model")
	version := r.URL.Query().Get("version")
	if model == "" || version == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "model and version are required"})
		return
	}

	var scans securityv1alpha1.ArtifactScanList
	if err := s.k8s.List(r.Context(), &scans); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "cannot list scans"})
		return
	}

	// Most recent scan first: a model rescanned yesterday should hand back
	// yesterday's document, not the first one ever produced for it.
	var candidates []securityv1alpha1.ArtifactScan
	for _, sc := range scans.Items {
		if sc.Spec.ModelName == model && sc.Spec.ModelVersion == version {
			candidates = append(candidates, sc)
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[j].CreationTimestamp.Before(&candidates[i].CreationTimestamp)
	})

	for _, sc := range candidates {
		if !sub.CanSeeNamespace(sc.Namespace) {
			continue
		}
		var cm corev1.ConfigMap
		key := client.ObjectKey{
			Name:      controller.BOMConfigMapName(sc.Name),
			Namespace: sc.Namespace,
		}
		if err := s.k8s.Get(r.Context(), key, &cm); err != nil {
			continue
		}
		names := make([]string, 0, len(cm.Data))
		for n := range cm.Data {
			names = append(names, n)
		}
		sort.Strings(names)

		// A named document if one was asked for, otherwise the index.
		if want := r.URL.Query().Get("document"); want != "" {
			body, ok := cm.Data[want]
			if !ok {
				writeJSON(w, http.StatusNotFound, map[string]string{
					"error": fmt.Sprintf("no document %q in this bill of materials", want)})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Disposition",
				fmt.Sprintf("attachment; filename=%q", want))
			_, _ = w.Write([]byte(body))
			return
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"scan": sc.Name, "namespace": sc.Namespace, "documents": names,
		})
		return
	}

	// Absent is not the same as never produced, and the difference is what a
	// reader needs: a scan that ran without the aibom stage looks identical to
	// one whose document was lost unless the answer says which.
	writeJSON(w, http.StatusNotFound, map[string]string{
		"error": "no bill of materials for this model version; the scan may have run " +
			"without the tessera scanner enabled in its policy",
	})
}
