package podmeta

import (
	"context"
	"errors"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

// Run feeds the resolver from a Pod informer restricted to this node
// (fieldSelector spec.nodeName). It is a metadata cache, not a lifecycle
// history: missed watch history is covered by the lifecycle sources.
func (r *Resolver) Run(ctx context.Context, client kubernetes.Interface) error {
	if client == nil {
		return errors.New("kubernetes client required")
	}
	factory := informers.NewSharedInformerFactoryWithOptions(client, 10*time.Minute,
		informers.WithTweakListOptions(func(o *metav1.ListOptions) {
			o.FieldSelector = fields.OneTermEqualSelector("spec.nodeName", r.c.NodeName).String()
		}))
	informer := factory.Core().V1().Pods().Informer()
	toPod := func(o any) *corev1.Pod {
		if d, ok := o.(cache.DeletedFinalStateUnknown); ok {
			o = d.Obj
		}
		p, _ := o.(*corev1.Pod)
		return p
	}
	if _, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(o any) { r.Upsert(toPod(o)) },
		UpdateFunc: func(_, o any) { r.Upsert(toPod(o)) },
		DeleteFunc: func(o any) { r.Delete(toPod(o)) },
	}); err != nil {
		return err
	}
	factory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), informer.HasSynced) {
		factory.Shutdown()
		return ctx.Err()
	}
	r.MarkSynced()
	<-ctx.Done()
	factory.Shutdown()
	return ctx.Err()
}
