module "network_policy_logging" {
  source     = "../../logging"
  project_id = module.platform.project_id
}

