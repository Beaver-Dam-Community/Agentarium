// Command baseline-digests computes the six environment lock baseline_digests
// (TASK-01 4, TASK-16 3.1) with packages/baseline, the same functions the
// TASK-10 drift probe uses. It reads the cluster with get/list only and reads
// the node pool configuration with one GKE clusters.get; it never writes to
// the cluster. Any read error, missing resource type or missing named object
// fails the run, and no digest is written (TASK-01 4).
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	container "google.golang.org/api/container/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/Beaver-Dam-Community/Agentarium/packages/baseline"
)

const clusterFile = "cluster.json"

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("baseline-digests", flag.ContinueOnError)
	fs.SetOutput(stderr)
	kubeContext := fs.String("context", "", "kubeconfig context to read (required for cluster reads; the current context is never used)")
	kubeconfig := fs.String("kubeconfig", "", "kubeconfig path (default: $KUBECONFIG or ~/.kube/config)")
	lockPath := fs.String("lock", "", "environment lock giving project.id, project.location and environment (required for cluster reads)")
	fromDir := fs.String("from-dir", "", "read pre-fetched JSON (<source-id>.json and cluster.json) instead of the cluster")
	writeLock := fs.String("write-lock", "", "update baseline_digests in this environment lock instead of printing JSON")
	timeout := fs.Duration("timeout", 5*time.Minute, "overall read timeout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(stderr, "unexpected arguments:", fs.Args())
		return 2
	}

	var obs baseline.Observation
	var err error
	switch {
	case *fromDir != "" && (*kubeContext != "" || *lockPath != "" || *kubeconfig != ""):
		fmt.Fprintln(stderr, "--from-dir cannot be combined with --context, --kubeconfig or --lock")
		return 2
	case *fromDir != "":
		obs, err = readDir(*fromDir)
	case *kubeContext == "" || *lockPath == "":
		fmt.Fprintln(stderr, "--context and --lock are required (or use --from-dir)")
		return 2
	default:
		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		defer cancel()
		obs, err = readLive(ctx, *kubeconfig, *kubeContext, *lockPath, stderr)
	}
	if err != nil {
		fmt.Fprintln(stderr, "baseline-digests:", err)
		return 1
	}
	d, err := digests(obs)
	if err != nil {
		fmt.Fprintln(stderr, "baseline-digests:", err)
		return 1
	}
	if *writeLock != "" {
		if err := updateLock(*writeLock, d); err != nil {
			fmt.Fprintln(stderr, "baseline-digests:", err)
			return 1
		}
		fmt.Fprintln(stderr, "updated baseline_digests in", *writeLock)
		return 0
	}
	b, _ := json.MarshalIndent(d, "", "  ")
	fmt.Fprintf(stdout, "%s\n", b)
	return 0
}

// digests enforces the installer's fail-closed rules and computes the values.
func digests(obs baseline.Observation) (baseline.Digests, error) {
	var miss []string
	for _, s := range baseline.Sources() {
		for _, m := range baseline.Missing(s, obs.Objects[s.ID]) {
			miss = append(miss, s.Kind+" "+m)
		}
	}
	for _, m := range baseline.MissingReleasePolicies(obs.Objects["tracingpoliciesnamespaced"]) {
		miss = append(miss, "TracingPolicyNamespaced "+m)
	}
	if len(miss) > 0 {
		return baseline.Digests{}, fmt.Errorf("named baseline objects not found: %s", strings.Join(miss, ", "))
	}
	return baseline.Compute(obs)
}

func readDir(dir string) (baseline.Observation, error) {
	obs := baseline.Observation{Objects: map[string][]map[string]any{}}
	for _, s := range baseline.Sources() {
		b, err := os.ReadFile(filepath.Join(dir, s.ID+".json"))
		if err != nil {
			return obs, err
		}
		items, err := baseline.ParseItems(b)
		if err != nil {
			return obs, fmt.Errorf("%s.json: %w", s.ID, err)
		}
		obs.Objects[s.ID] = items
	}
	b, err := os.ReadFile(filepath.Join(dir, clusterFile))
	if err != nil {
		return obs, err
	}
	if err := baseline.DecodeJSON(b, &obs.Cluster); err != nil {
		return obs, fmt.Errorf("%s: %w", clusterFile, err)
	}
	return obs, nil
}

type lockTarget struct {
	Environment string `json:"environment"`
	Project     struct {
		ID       string `json:"id"`
		Location string `json:"location"`
	} `json:"project"`
}

// clusterName derives the GKE cluster name the way platform/gcp/modules/platform
// does (local.name = "agentarium-${env}").
// SPEC-QUESTION: the environment lock has no cluster name key; the name is
// derived from lock.environment to match the Terraform module.
func (l lockTarget) clusterName() string { return "agentarium-" + l.Environment }

func readLockTarget(path string) (lockTarget, error) {
	var l lockTarget
	b, err := os.ReadFile(path)
	if err != nil {
		return l, err
	}
	if err := json.Unmarshal(b, &l); err != nil {
		return l, fmt.Errorf("%s: %w", path, err)
	}
	for k, v := range map[string]string{"environment": l.Environment, "project.id": l.Project.ID, "project.location": l.Project.Location} {
		if v == "" || strings.HasPrefix(v, "REPLACE_WITH") {
			return l, fmt.Errorf("%s: %s is not set", path, k)
		}
	}
	if l.Environment != "prod" && l.Environment != "regression" {
		return l, fmt.Errorf("%s: environment %q is not prod or regression", path, l.Environment)
	}
	return l, nil
}

func readLive(ctx context.Context, kubeconfig, kubeContext, lockPath string, stderr io.Writer) (baseline.Observation, error) {
	obs := baseline.Observation{Objects: map[string][]map[string]any{}}
	target, err := readLockTarget(lockPath)
	if err != nil {
		return obs, err
	}
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	rules.ExplicitPath = kubeconfig
	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{CurrentContext: kubeContext})
	raw, err := cc.RawConfig()
	if err != nil {
		return obs, err
	}
	if _, ok := raw.Contexts[kubeContext]; !ok {
		return obs, fmt.Errorf("kubeconfig context %q not found", kubeContext)
	}
	cfg, err := cc.ClientConfig()
	if err != nil {
		return obs, err
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return obs, err
	}
	name := fmt.Sprintf("projects/%s/locations/%s/clusters/%s", target.Project.ID, target.Project.Location, target.clusterName())
	fmt.Fprintf(stderr, "reading context %q (server %s) and GKE %s\n", kubeContext, cfg.Host, name)

	for _, s := range baseline.Sources() {
		items, err := readSource(ctx, dyn, s)
		if err != nil {
			return obs, fmt.Errorf("%s: %w", s.ID, err)
		}
		obs.Objects[s.ID] = items
	}

	svc, err := container.NewService(ctx)
	if err != nil {
		return obs, err
	}
	cl, err := svc.Projects.Locations.Clusters.Get(name).Context(ctx).Do()
	if err != nil {
		return obs, fmt.Errorf("GKE clusters.get %s: %w", name, err)
	}
	b, err := json.Marshal(cl)
	if err != nil {
		return obs, err
	}
	if err := baseline.DecodeJSON(b, &obs.Cluster); err != nil {
		return obs, err
	}
	return obs, nil
}

// readSource performs only GET and LIST. Every error, including NotFound and
// a missing resource type, is returned.
func readSource(ctx context.Context, dyn dynamic.Interface, s baseline.Source) ([]map[string]any, error) {
	gvr := schema.GroupVersionResource{Group: s.Group(), Version: s.Version(), Resource: s.Resource}
	nss := s.Namespaces
	if !s.Namespaced || len(nss) == 0 {
		nss = []string{""} // cluster-scoped, or all Namespaces
	}
	var out []map[string]any
	for _, ns := range nss {
		var ri dynamic.ResourceInterface = dyn.Resource(gvr)
		if s.Namespaced && ns != "" {
			ri = dyn.Resource(gvr).Namespace(ns)
		}
		if s.IsGet() {
			for _, n := range s.Names {
				u, err := ri.Get(ctx, n, metav1.GetOptions{})
				if err != nil {
					return nil, fmt.Errorf("get %s/%s: %w", ns, n, err)
				}
				m, err := toMap(u.Object)
				if err != nil {
					return nil, err
				}
				out = append(out, m)
			}
			continue
		}
		cont := ""
		for {
			l, err := ri.List(ctx, metav1.ListOptions{Limit: 500, Continue: cont})
			if err != nil {
				return nil, fmt.Errorf("list %q: %w", ns, err)
			}
			for _, it := range l.Items {
				m, err := toMap(it.Object)
				if err != nil {
					return nil, err
				}
				out = append(out, m)
			}
			if cont = l.GetContinue(); cont == "" {
				break
			}
		}
	}
	return out, nil
}

// toMap round-trips through JSON so live objects have the same value types
// (json.Number) as --from-dir input.
func toMap(o map[string]any) (map[string]any, error) {
	b, err := json.Marshal(o)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	return m, baseline.DecodeJSON(b, &m)
}

// updateLock replaces only the top-level baseline_digests value, keeping the
// other keys, their order and their values; the file is re-indented with two
// spaces and ends with a newline. The write is atomic (temp file + rename).
func updateLock(path string, d baseline.Digests) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	out, err := replaceTopLevel(b, "baseline_digests", d)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".baseline-digests-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(out); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(st.Mode().Perm()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func replaceTopLevel(doc []byte, key string, value any) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(doc))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, errors.New("lock is not a JSON object")
	}
	type kv struct {
		k string
		v json.RawMessage
	}
	var kvs []kv
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, err
		}
		k := t.(string)
		if seen[k] {
			return nil, fmt.Errorf("duplicate key %q", k)
		}
		seen[k] = true
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		kvs = append(kvs, kv{k, v})
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing data after lock object")
	}
	nv, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	replaced := false
	for i := range kvs {
		if kvs[i].k == key {
			kvs[i].v, replaced = nv, true
		}
	}
	if !replaced {
		kvs = append(kvs, kv{key, nv})
	}
	var flat bytes.Buffer
	flat.WriteByte('{')
	for i, e := range kvs {
		if i > 0 {
			flat.WriteByte(',')
		}
		kb, _ := json.Marshal(e.k)
		flat.Write(kb)
		flat.WriteByte(':')
		flat.Write(e.v)
	}
	flat.WriteByte('}')
	var out bytes.Buffer
	if err := json.Indent(&out, flat.Bytes(), "", "  "); err != nil {
		return nil, err
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}
