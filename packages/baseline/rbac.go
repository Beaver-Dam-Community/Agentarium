package baseline

import "strings"

// SelectExecRBAC applies the TASK-01 4 exec_rbac selection to full LISTs of
// Roles, RoleBindings (all Namespaces), ClusterRoles and ClusterRoleBindings:
//
//   - every Role and RoleBinding in agent-exec and agent-sensors;
//   - RoleBindings in other Namespaces and ClusterRoleBindings with a subject
//     that is an execution principal of those Namespaces (see execSubject);
//   - the Role/ClusterRole each selected binding's roleRef points to, when it
//     exists (a dangling roleRef keeps only the binding).
//
// Inputs go through Select first (apiVersion/kind filled, deep-copied).
// Objects are returned once each, in no particular order.
func SelectExecRBAC(roles, roleBindings, clusterRoles, clusterRoleBindings []map[string]any) []map[string]any {
	ins := []*[]map[string]any{&roles, &roleBindings, &clusterRoles, &clusterRoleBindings}
	for i, id := range []string{"roles", "rolebindings", "clusterroles", "clusterrolebindings"} {
		src, _ := sourceByID(id)
		*ins[i] = Select(src, *ins[i])
	}
	var out []map[string]any
	seen := map[[4]string]bool{}
	add := func(o map[string]any) {
		k := sortKey(o)
		if !seen[k] {
			seen[k] = true
			out = append(out, o)
		}
	}
	roleIdx := map[[2]string]map[string]any{}
	for _, r := range roles {
		ns, name := nsName(r)
		roleIdx[[2]string{ns, name}] = r
		if contains(ExecNamespaces, ns) {
			add(r)
		}
	}
	croleIdx := map[string]map[string]any{}
	for _, r := range clusterRoles {
		_, name := nsName(r)
		croleIdx[name] = r
	}
	follow := func(b map[string]any, bindingNS string) {
		ref, _ := b["roleRef"].(map[string]any)
		kind, _ := ref["kind"].(string)
		name, _ := ref["name"].(string)
		switch kind {
		case "Role":
			if r, ok := roleIdx[[2]string{bindingNS, name}]; ok && bindingNS != "" {
				add(r)
			}
		case "ClusterRole":
			if r, ok := croleIdx[name]; ok {
				add(r)
			}
		}
	}
	for _, b := range roleBindings {
		ns, _ := nsName(b)
		if contains(ExecNamespaces, ns) || hasExecSubject(b, ns) {
			add(b)
			follow(b, ns)
		}
	}
	for _, b := range clusterRoleBindings {
		if hasExecSubject(b, "") {
			add(b)
			follow(b, "")
		}
	}
	return out
}

func hasExecSubject(binding map[string]any, bindingNS string) bool {
	subs, _ := binding["subjects"].([]any)
	for _, s := range subs {
		if m, ok := s.(map[string]any); ok && execSubject(m, bindingNS) {
			return true
		}
	}
	return false
}

// execSubject reports whether a binding subject is an execution principal of
// agent-exec or agent-sensors: a ServiceAccount in those Namespaces, User
// system:serviceaccount:<ns>:<name>, or Group system:serviceaccounts,
// system:serviceaccounts:<ns>, system:authenticated, system:unauthenticated.
// A ServiceAccount subject without namespace in a RoleBinding refers to the
// binding's Namespace, as the Kubernetes RBAC authorizer resolves it.
func execSubject(s map[string]any, bindingNS string) bool {
	kind, _ := s["kind"].(string)
	name, _ := s["name"].(string)
	switch kind {
	case "ServiceAccount":
		ns, _ := s["namespace"].(string)
		if ns == "" {
			ns = bindingNS
		}
		return contains(ExecNamespaces, ns)
	case "User":
		rest, ok := strings.CutPrefix(name, "system:serviceaccount:")
		if !ok {
			return false
		}
		ns, sa, ok := strings.Cut(rest, ":")
		return ok && sa != "" && contains(ExecNamespaces, ns)
	case "Group":
		switch name {
		case "system:serviceaccounts", "system:authenticated", "system:unauthenticated":
			return true
		}
		ns, ok := strings.CutPrefix(name, "system:serviceaccounts:")
		return ok && contains(ExecNamespaces, ns)
	}
	return false
}
