// Package kube implements bootstrap.Cluster with client-go, using only the
// identity KSA permissions TASK-03 3.3.2 names: tokenreviews.create and
// pods/nodes get.
package kube

import (
	"context"

	authnv1 "k8s.io/api/authentication/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/Beaver-Dam-Community/Agentarium/services/identity/internal/bootstrap"
)

// Cluster reads token reviews, Pods and Nodes.
type Cluster struct{ Client kubernetes.Interface }

func (c Cluster) ReviewToken(ctx context.Context, token string, audiences []string) (bootstrap.TokenReview, error) {
	tr, err := c.Client.AuthenticationV1().TokenReviews().Create(ctx, &authnv1.TokenReview{
		Spec: authnv1.TokenReviewSpec{Token: token, Audiences: audiences},
	}, metav1.CreateOptions{})
	if err != nil {
		return bootstrap.TokenReview{}, err
	}
	extra := map[string][]string{}
	for k, v := range tr.Status.User.Extra {
		extra[k] = []string(v)
	}
	return bootstrap.TokenReview{
		Authenticated: tr.Status.Authenticated && tr.Status.Error == "",
		Audiences:     tr.Status.Audiences,
		Username:      tr.Status.User.Username,
		Extra:         extra,
	}, nil
}

func (c Cluster) GetPod(ctx context.Context, namespace, name string) (bootstrap.Pod, error) {
	p, err := c.Client.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return bootstrap.Pod{}, bootstrap.ErrNotFound
	}
	if err != nil {
		return bootstrap.Pod{}, err
	}
	return bootstrap.Pod{
		UID:            string(p.UID),
		Namespace:      p.Namespace,
		Name:           p.Name,
		ServiceAccount: p.Spec.ServiceAccountName,
		NodeName:       p.Spec.NodeName,
		Deleting:       p.DeletionTimestamp != nil,
	}, nil
}

func (c Cluster) GetNode(ctx context.Context, name string) (bootstrap.Node, error) {
	n, err := c.Client.CoreV1().Nodes().Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return bootstrap.Node{}, bootstrap.ErrNotFound
	}
	if err != nil {
		return bootstrap.Node{}, err
	}
	return bootstrap.Node{UID: string(n.UID), BootID: n.Status.NodeInfo.BootID}, nil
}
