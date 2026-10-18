variable "env" {
  description = "Environment name. prod and regression must be applied to different GCP projects."
  type        = string

  validation {
    condition     = contains(["prod", "regression"], var.env)
    error_message = "env must be prod or regression."
  }
}

# TASK-01 keys of deploy/gcp/environment.lock.json (schema owned by TASK-16).
# Missing keys fail type conversion; fixed decisions are re-checked below.
variable "lock" {
  description = "Decoded environment lock (TASK-01 keys)."
  type = object({
    schema_version = number
    environment    = string
    project = object({
      id       = string
      location = string
    })
    gke = object({
      mode              = string
      release_channel   = string
      kubernetes_minor  = string
      datapath_provider = string
      private_nodes     = bool
      ip_family         = string
      # SPEC-QUESTION: control plane access is not defined by the spec; see cluster.tf.
      control_plane = object({
        dns_endpoint_allow_external_traffic = bool
        private_endpoint_only               = bool
        master_global_access                = bool
        authorized_networks = list(object({
          cidr_block   = string
          display_name = string
        }))
      })
    })
    network = object({
      node_cidr          = string
      pods_range         = string
      services_range     = string
      gateway_cluster_ip = string
    })
    node_pools = object({
      exec = object({
        machine_type = string
        disk_size_gb = optional(number, 100)
        disk_type    = optional(string, "pd-balanced")
        node_count   = number
        taints       = list(string)
        labels       = map(string)
      })
      control = object({
        machine_type = string
        disk_size_gb = optional(number, 100)
        disk_type    = optional(string, "pd-balanced")
        node_count   = number
        taints       = list(string)
        labels       = map(string)
      })
      system = object({
        machine_type = string
        disk_size_gb = optional(number, 100)
        disk_type    = optional(string, "pd-balanced")
        node_count   = number
        taints       = list(string)
        labels       = map(string)
      })
      image_type = string
      auto_repair = object({
        exec    = bool
        control = bool
        system  = bool
      })
      workload_metadata = string
    })
  })

  validation {
    condition     = var.lock.environment == var.env
    error_message = "lock.environment must equal env."
  }

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.lock.project.id))
    error_message = "lock.project.id is not a valid GCP project ID (placeholder not replaced?)."
  }

  validation {
    condition     = can(regex("^[a-z]+-[a-z]+[0-9]+(-[a-z])?$", var.lock.project.location))
    error_message = "lock.project.location must be a GCP region or zone."
  }

  validation {
    condition = (
      var.lock.gke.mode == "standard" &&
      var.lock.gke.release_channel == "REGULAR" &&
      var.lock.gke.datapath_provider == "ADVANCED_DATAPATH" &&
      var.lock.gke.private_nodes == true &&
      var.lock.gke.ip_family == "IPV4"
    )
    error_message = "lock.gke must be mode=standard, release_channel=REGULAR, datapath_provider=ADVANCED_DATAPATH, private_nodes=true, ip_family=IPV4 (TASK-01 section 4)."
  }

  validation {
    condition = alltrue([
      for n in var.lock.gke.control_plane.authorized_networks :
      can(cidrnetmask(n.cidr_block)) && try(tonumber(split("/", n.cidr_block)[1]) >= 8, false) && n.display_name != ""
    ])
    error_message = "lock.gke.control_plane.authorized_networks entries must be named IPv4 CIDRs no wider than /8."
  }

  validation {
    condition = (
      var.lock.gke.control_plane.private_endpoint_only ||
      length(var.lock.gke.control_plane.authorized_networks) > 0
    )
    error_message = "a public control plane IP endpoint requires at least one authorized network."
  }

  validation {
    condition = (
      can(regex("^1\\.[0-9]+$", var.lock.gke.kubernetes_minor)) &&
      try(tonumber(split(".", var.lock.gke.kubernetes_minor)[1]) >= 33, false)
    )
    error_message = "lock.gke.kubernetes_minor must be a minor version 1.33 or later, e.g. \"1.33\"."
  }

  validation {
    condition = alltrue([
      for c in [var.lock.network.node_cidr, var.lock.network.pods_range, var.lock.network.services_range] :
      can(cidrnetmask(c)) && try(cidrsubnet(c, 0, 0) == c, false)
    ])
    error_message = "lock.network ranges must be canonical IPv4 CIDRs."
  }

  validation {
    condition = try(
      cidrsubnet("${var.lock.network.gateway_cluster_ip}/${split("/", var.lock.network.services_range)[1]}", 0, 0) == var.lock.network.services_range &&
      var.lock.network.gateway_cluster_ip != cidrhost(var.lock.network.services_range, 0) &&
      var.lock.network.gateway_cluster_ip != cidrhost(var.lock.network.services_range, 1) &&
      var.lock.network.gateway_cluster_ip != cidrhost(var.lock.network.services_range, 10),
      false
    )
    error_message = "lock.network.gateway_cluster_ip must be a host address inside lock.network.services_range other than .1 (kubernetes) and .10 (GKE kube-dns)."
  }

  validation {
    condition = (
      var.lock.node_pools.image_type == "COS_CONTAINERD" &&
      var.lock.node_pools.workload_metadata == "GKE_METADATA" &&
      var.lock.node_pools.auto_repair.exec == false &&
      var.lock.node_pools.auto_repair.control == true &&
      var.lock.node_pools.auto_repair.system == true
    )
    error_message = "lock.node_pools must be image_type=COS_CONTAINERD, workload_metadata=GKE_METADATA, auto_repair exec=false control=true system=true (TASK-01 3.5, section 4)."
  }

  validation {
    condition = (
      toset(var.lock.node_pools.exec.taints) == toset(["agentarium-role=exec:NoSchedule", "agentarium.io/observe-not-ready=true:NoSchedule"]) &&
      length(var.lock.node_pools.exec.taints) == 2 &&
      var.lock.node_pools.control.taints == tolist(["agentarium.io/observe-not-ready=true:NoSchedule"]) &&
      var.lock.node_pools.system.taints == tolist(["components.gke.io/gke-managed-components=true:NoSchedule"])
    )
    error_message = "exec taints must be agentarium-role=exec:NoSchedule and agentarium.io/observe-not-ready=true:NoSchedule; control taints must be only the start taint; system taints must be only components.gke.io/gke-managed-components=true:NoSchedule."
  }

  validation {
    condition = (
      var.lock.node_pools.exec.labels == tomap({ "node-restriction.kubernetes.io/agentarium-role" = "exec" }) &&
      var.lock.node_pools.control.labels == tomap({ "node-restriction.kubernetes.io/agentarium-role" = "control" }) &&
      var.lock.node_pools.system.labels == tomap({ "node-restriction.kubernetes.io/agentarium-role" = "system" })
    )
    error_message = "node pool labels must be node-restriction.kubernetes.io/agentarium-role=exec|control|system only."
  }

  validation {
    condition = alltrue([
      for p in [var.lock.node_pools.exec, var.lock.node_pools.control, var.lock.node_pools.system] :
      p.machine_type != "" && p.node_count >= 1 && floor(p.node_count) == p.node_count
    ])
    error_message = "node pool machine_type must be set and node_count must be a positive integer."
  }

  validation {
    condition = alltrue([
      for p in [var.lock.node_pools.exec, var.lock.node_pools.control, var.lock.node_pools.system] :
      p.disk_size_gb >= 10 && floor(p.disk_size_gb) == p.disk_size_gb &&
      contains(["pd-balanced", "pd-standard"], p.disk_type)
    ])
    error_message = "node pool disk_size_gb must be an integer >= 10 GB and disk_type must be pd-balanced or pd-standard."
  }

}
