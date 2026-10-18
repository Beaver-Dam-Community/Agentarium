// Command iamcheck fails when IAM policy JSON files grant anything to
// agent-exec principals or whole GKE workload pools, or reference another
// environment's workload pool.
//
//	iamcheck -project-id PROJECT_ID [-project-number NUMBER]
//	    [-cross-env-config inputs.json -role-definition role.json]
//	    [-assets export.ndjson]... [policy.json]...
//
// A plain policy.json (`gcloud ... get-iam-policy --format=json`) is checked
// without any exemption. -assets reads a Cloud Asset Inventory IAM-policy
// export (`gcloud asset export --content-type=iam-policy`, one record per
// line); the resource name and asset type come from each record. Only those
// records can carry the four TASK-06 3.3 cross-environment grants (#97), and
// only when -cross-env-config and -role-definition (the output of
// `gcloud iam roles describe projects/P/roles/agentariumManifestPublicKey
// --format=json`) are given. A resource appearing twice is an input error.
//
// Exit status: 0 clean, 1 violations found, 2 usage or parse error.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Beaver-Dam-Community/Agentarium/platform/gcp/iam/checks"
)

type paths []string

func (p *paths) String() string     { return fmt.Sprint(*p) }
func (p *paths) Set(v string) error { *p = append(*p, v); return nil }

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("iamcheck", flag.ContinueOnError)
	fs.SetOutput(stderr)
	projectID := fs.String("project-id", "", "project ID of the environment whose policies are checked (required)")
	projectNumber := fs.String("project-number", "", "project number of the environment (optional)")
	crossConfig := fs.String("cross-env-config", "", "TASK-06 3.3 cross-environment allowlist inputs (JSON, optional)")
	roleDefinition := fs.String("role-definition", "", "gcloud iam roles describe output of the manifest public-key role (required with -cross-env-config)")
	var assets paths
	fs.Var(&assets, "assets", "Cloud Asset Inventory IAM-policy export (NDJSON); repeatable")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *projectID == "" || (fs.NArg() == 0 && len(assets) == 0) {
		fmt.Fprintln(stderr, "usage: iamcheck -project-id PROJECT_ID [-project-number NUMBER] [-cross-env-config FILE -role-definition FILE] [-assets FILE]... [policy.json]...")
		return 2
	}
	env := checks.Env{ProjectID: *projectID, ProjectNumber: *projectNumber}
	if (*crossConfig == "") != (*roleDefinition == "") {
		fmt.Fprintln(stderr, "-cross-env-config and -role-definition must be given together")
		return 2
	}
	if *crossConfig != "" {
		in, role, err := readAllowlistInputs(*crossConfig, *roleDefinition)
		if err == nil {
			env.CrossEnv, err = checks.CrossEnvAllowlist(in, env, role)
		}
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
	}

	status := 0
	report := func(path string, vs []checks.Violation) {
		for _, v := range vs {
			fmt.Fprintf(stdout, "%s: %s\n", path, v)
			status = 1
		}
	}
	seen := map[string]bool{}
	for _, path := range assets {
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", path, err)
			return 2
		}
		records, err := checks.ParseAssetExport(data, seen)
		if err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", path, err)
			return 2
		}
		for _, a := range records {
			vs, err := checks.CheckAsset(a, env)
			if err != nil {
				fmt.Fprintf(stderr, "%s: %v\n", path, err)
				return 2
			}
			report(path+"#"+a.Name, vs)
		}
	}
	for _, path := range fs.Args() {
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", path, err)
			return 2
		}
		p, err := checks.ParsePolicy(data)
		if err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", path, err)
			return 2
		}
		vs, err := checks.Check(p, env)
		if err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", path, err)
			return 2
		}
		report(path, vs)
	}
	return status
}

func readAllowlistInputs(config, role string) (checks.CrossEnvInputs, checks.RoleDefinition, error) {
	var in checks.CrossEnvInputs
	var def checks.RoleDefinition
	data, err := os.ReadFile(config)
	if err != nil {
		return in, def, err
	}
	if in, err = checks.ParseCrossEnvInputs(data); err != nil {
		return in, def, fmt.Errorf("%s: %w", config, err)
	}
	if data, err = os.ReadFile(role); err != nil {
		return in, def, err
	}
	if def, err = checks.ParseRoleDefinition(data); err != nil {
		return in, def, fmt.Errorf("%s: %w", role, err)
	}
	return in, def, nil
}
