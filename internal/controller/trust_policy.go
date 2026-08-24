package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	securityv1alpha1 "github.com/DAVANO-INNOVATION-LAB/cupel/api/v1alpha1"
	"github.com/DAVANO-INNOVATION-LAB/cupel/internal/provenance"
)

const (
	// TrustPolicyConfigMap holds the rendered TrustedPublishers. Scan pods
	// project it read-only; it never contains a private key, only the public
	// material needed to check a signature.
	TrustPolicyConfigMap = "cupel-trust-policy"
	// TrustPolicyKey is the file name inside the ConfigMap.
	TrustPolicyKey = "trust-policy.json"
	// TrustPolicyMountPath is where scan pods see it.
	TrustPolicyMountPath = "/trust"
)

// RenderTrustPolicy flattens TrustedPublisher objects into the policy the
// in-pod verifier consumes.
//
// The scan pod has no cluster credentials, so it cannot read TrustedPublishers
// itself. Rendering them here keeps that property: the pod receives exactly the
// public trust material and nothing else.
func RenderTrustPolicy(publishers []securityv1alpha1.TrustedPublisher, trustRootPath string, requireTLog bool) provenance.Policy {
	policy := provenance.Policy{
		TrustRootPath:          trustRootPath,
		RequireTransparencyLog: requireTLog,
	}
	for _, tp := range publishers {
		p := provenance.Publisher{
			Name:         tp.Name,
			DisplayName:  tp.Spec.DisplayName,
			PublicKeyPEM: tp.Spec.CosignPublicKey,
			URIPrefixes:  tp.Spec.URIPrefixes,
		}
		if tp.Spec.KeylessIdentity != nil {
			p.Issuer = tp.Spec.KeylessIdentity.Issuer
			p.Subject = tp.Spec.KeylessIdentity.Subject
		}
		// A publisher with neither a key nor an identity can verify nothing.
		// Dropping it here keeps the pod from reporting a trusted-publisher
		// count that includes entries incapable of trusting anything.
		if p.PublicKeyPEM == "" && !p.Keyless() {
			continue
		}
		policy.Publishers = append(policy.Publishers, p)
	}
	sort.Slice(policy.Publishers, func(i, j int) bool {
		return policy.Publishers[i].Name < policy.Publishers[j].Name
	})
	return policy
}

// SyncTrustPolicy renders every TrustedPublisher in the namespace into the
// ConfigMap that scan pods mount.
func SyncTrustPolicy(ctx context.Context, c client.Client, namespace, trustRootPath string, requireTLog bool) error {
	var list securityv1alpha1.TrustedPublisherList
	if err := c.List(ctx, &list, client.InNamespace(namespace)); err != nil {
		return fmt.Errorf("list trusted publishers: %w", err)
	}

	policy := RenderTrustPolicy(list.Items, trustRootPath, requireTLog)
	encoded, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return fmt.Errorf("encode trust policy: %w", err)
	}

	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      TrustPolicyConfigMap,
			Namespace: namespace,
			Labels:    map[string]string{LabelManagedBy: ManagerName},
		},
		Data: map[string]string{TrustPolicyKey: string(encoded)},
	}

	var existing corev1.ConfigMap
	err = c.Get(ctx, client.ObjectKey{Name: TrustPolicyConfigMap, Namespace: namespace}, &existing)
	switch {
	case apierrors.IsNotFound(err):
		return c.Create(ctx, cm)
	case err != nil:
		return err
	}
	if existing.Data[TrustPolicyKey] == cm.Data[TrustPolicyKey] {
		return nil
	}
	existing.Data = cm.Data
	return c.Update(ctx, &existing)
}
