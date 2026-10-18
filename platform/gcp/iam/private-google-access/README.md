# Private Google Access DNS and route

TASK-06 requires the IPv4-only `googleapis.com.` private zone attached to the
platform VPC. This module enables Cloud DNS, maps `private.googleapis.com.` to
`199.36.153.8` through `.11`, and maps `*.googleapis.com.` to that name. It also
adds a `/30` route via the default internet gateway. The existing default route
already satisfies PGA routing; the explicit route preserves the VIP path if the
default route changes. The platform module owns the subnet's enabled PGA flag.

This follows [Google's DNS and routing configuration](https://docs.cloud.google.com/vpc/docs/configure-private-google-access).
The gateway name does not imply public internet transit for this VIP. The module
adds no NAT, firewall grants, IAM grants, or IPv6 records. NetworkPolicy remains
the per-workload access boundary. Other Google domains and the optional restricted
VIP are outside this TASK-06 DNS contract.

The production root supplies the project and VPC from the platform module and
exports `pga_vip_cidr` for the installation manifest. Resource identifiers are
installation inputs; none are hardcoded here.

## Verification

Run `terraform init -backend=false`, `terraform validate`, and `terraform test`
in this directory. These checks use mock providers and do not prove live DNS or
packet access. After the prerequisite contracts and M1 implementation merge,
review the production plan before applying. In allowed Google API caller Pods,
resolve `secretmanager.googleapis.com`, `oauth2.googleapis.com`, and
`www.googleapis.com`; every returned IPv4 address must be within the VIP range.
Verify authenticated API requests separately and retain forbidden exec-Pod
DNS/PGA probes as negative controls. Record the Pod, resolver, time, answers,
and actual request results. An API authorization error is not proof of denied
network access.

Deleting the private zone changes name resolution for every caller in the VPC.
Do not remove it while VIP-only NetworkPolicies are installed. Reverting Terraform
code alone is not a runtime rollback; inspect the resulting plan and restore a
compatible DNS/egress configuration together.
