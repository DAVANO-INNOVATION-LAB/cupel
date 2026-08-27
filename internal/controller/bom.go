package controller

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/naming"
)

// BOMConfigMapName is where a scan's bill of materials is kept.
func BOMConfigMapName(scanName string) string {
	return naming.Stable("bom", scanName)
}

// MaxBOMBytes bounds what is stored. A ConfigMap tops out around a megabyte,
// and an object that large has no business in etcd on every scan regardless.
// A model's bill of materials is metadata rather than content: a few kilobytes
// is typical, so a document past this is a signal, not a normal case.
const MaxBOMBytes = 512 << 10

// bomDocuments are the rendered documents worth keeping, by file suffix.
var bomDocuments = []string{".cdx.json", ".spdx.json", ".sarif.json"}

// PublishBOM stores the bill-of-materials documents a scan produced, so they
// can be read after the Job that made them is gone.
//
// They were written to the results volume, which is an emptyDir: the scanner
// generated a bill of materials, the report recorded that it had, and the
// document itself was destroyed with the pod. A report asserting `produced:
// true` with nothing behind it is worse than one that says nothing.
//
// A ConfigMap rather than a field on the report, because the report is read on
// every reconcile and the documents are read by a person, once, when they want
// one. Owned by the scan, so retention removes it with everything else.
func PublishBOM(ctx context.Context, c client.Client, namespace, scanName, dir string) error {
	docs, err := collectBOMs(dir)
	if err != nil {
		return err
	}
	if len(docs) == 0 {
		return nil
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      BOMConfigMapName(scanName),
			Namespace: namespace,
			Labels: map[string]string{
				"security.davano.io/scan":     scanName,
				"security.davano.io/artifact": "bom",
			},
		},
		Data: docs,
	}

	err = c.Create(ctx, cm)
	if apierrors.IsAlreadyExists(err) {
		existing := &corev1.ConfigMap{}
		key := client.ObjectKey{Name: cm.Name, Namespace: cm.Namespace}
		if err := c.Get(ctx, key, existing); err != nil {
			return fmt.Errorf("get existing bill of materials: %w", err)
		}
		existing.Data = docs
		existing.Labels = cm.Labels
		return c.Update(ctx, existing)
	}
	return err
}

// collectBOMs reads the rendered documents out of the results directory.
func collectBOMs(dir string) (map[string]string, error) {
	if dir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	out := map[string]string{}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		for _, suffix := range bomDocuments {
			if strings.HasSuffix(e.Name(), suffix) {
				names = append(names, e.Name())
				break
			}
		}
	}
	sort.Strings(names)

	total := 0
	for _, name := range names {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		// Refuse to store a document that would not fit rather than storing a
		// truncated one: half a bill of materials is not a bill of materials.
		if total+len(b) > MaxBOMBytes {
			continue
		}
		total += len(b)
		out[name] = string(b)
	}
	return out, nil
}
