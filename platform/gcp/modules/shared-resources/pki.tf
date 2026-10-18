# SAN grammar for the CA pool CEL expression below.
locals {
  dns_label = "[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?"
  uid       = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"

  # Anchored RE2; "[.]" avoids a backslash inside the CEL string literal.
  spiffe_san_pattern = join("", [
    "^spiffe://agentarium[.]internal/(",
    "ns/${local.dns_label}/sa/${local.dns_label}",
    "|ns/agent-exec/sa/${local.dns_label}/pod/${local.uid}",
    "|node-bridge/${local.uid}/${local.uid}",
    ")$",
  ])
  # CAS template IDs are at most 63 characters. Hash a truncated pool prefix
  # only when the existing valid pool ID leaves insufficient room for a suffix.
  # Keep this derivation aligned with deploy/gcp/base/render.py.
  certificate_template_prefix = length(var.lock.pki.ca_pool) <= 55 ? var.lock.pki.ca_pool : "${substr(var.lock.pki.ca_pool, 0, 38)}-${substr(sha256(var.lock.pki.ca_pool), 0, 16)}"
  certificate_profiles = {
    service = {
      server_auth = true
      san_pattern = "^spiffe://agentarium[.]internal/ns/${local.dns_label}/sa/${local.dns_label}$"
    }
    client = {
      server_auth = false
      san_pattern = "^spiffe://agentarium[.]internal/(ns/agent-exec/sa/${local.dns_label}/pod/${local.uid}|node-bridge/${local.uid}/${local.uid})$"
    }
  }

}

# Certificate Authority Service: one DevOps-tier CA pool (COMMON "service PKI and identifiers",
# TASK-03 3.3.1). roles/privateca.certificateRequester for workload-identity is TASK-06.
resource "google_privateca_ca_pool" "this" {
  project  = local.project_id
  name     = var.lock.pki.ca_pool
  location = var.region
  tier     = "DEVOPS"

  # SPEC-QUESTION: publication is not specified. DevOps tier cannot revoke, so no CRL; the
  # trust bundle is distributed through the agentarium-trust ConfigMap, so the CA
  # certificate is not published either.
  publishing_options {
    publish_ca_cert = false
    publish_crl     = false
  }

  issuance_policy {
    # Workload and service certificates live 24 hours (TASK-03 3.3.1). CAS truncates longer
    # requests to this value.
    maximum_lifetime = "86400s"

    # SPEC-QUESTION: the leaf key type is not specified. Workloads generate the key in memory;
    # only ECDSA P-256 is accepted.
    allowed_key_types {
      elliptic_curve {
        signature_algorithm = "ECDSA_P256"
      }
    }

    # TASK-03 3.3.2 step 4: identity ignores the CSR's SAN and builds the request itself, so a
    # workload CSR is never forwarded verbatim. SPEC-QUESTION: the spec does not name the CAS
    # issuance mode; config-based issuance only is the reading of step 4.
    allowed_issuance_modes {
      allow_config_based_issuance = true
      allow_csr_based_issuance    = false
    }

    # google 8.6.0 requires keyUsage inside any pool baseline_values block.
    # Stage 1 retains the old whole baseline while template IAM is prepared;
    # stage 2 moves both keyUsage and non-CA enforcement to mandatory templates.
    dynamic "baseline_values" {
      for_each = var.certificate_template_issuance_enabled ? [] : [1]
      content {
        ca_options {
          non_ca = true
        }
        key_usage {
          base_key_usage {
            digital_signature = true
          }
          extended_key_usage {
            server_auth = true
            client_auth = true
          }
        }
      }
    }

    identity_constraints {
      # SANs come from the identity service request; the subject is not used by the spec.
      # SPEC-QUESTION: subject passthrough is disabled; whether CAS issues certificates with an
      # empty subject and a single URI SAN on the DevOps tier is a Q0 item.
      allow_subject_alt_names_passthrough = true
      allow_subject_passthrough           = false

      # Exactly one URI SAN in one of the three forms of TASK-03 3.3.1 / COMMON "service PKI and
      # identifiers", matched in full (no prefix match, so no "..", extra "/", query, fragment,
      # percent-encoding or uppercase):
      #   spiffe://agentarium.internal/ns/<namespace>/sa/<ksa>
      #   spiffe://agentarium.internal/ns/agent-exec/sa/<ksa>/pod/<pod_uid>
      #   spiffe://agentarium.internal/node-bridge/<node_uid>/<boot_id>
      # namespace and ksa are DNS-1123 labels; UIDs are lowercase 8-4-4-4-12 (TASK-02 identifier
      # rules). SPEC-QUESTION: the KSA grammar is not specified (Kubernetes allows a DNS-1123
      # subdomain; every KSA in COMMON is a label). SPEC-QUESTION: TASK-03 writes the Pod form
      # with ns/<namespace>; COMMON fixes it to agent-exec, which is used here. SPEC-QUESTION:
      # boot_id is stored as text; the Linux bootID is a lowercase UUID, which is required here.
      # SPEC-QUESTION: matches() (RE2) is standard CEL but not listed in the CAS CEL page; Q0.
      cel_expression {
        title       = "agentarium-spiffe-uri-only"
        description = "Exactly one URI SAN in one of the agentarium.internal SPIFFE forms."
        expression  = "subject_alt_names.size() == 1 && subject_alt_names.all(san, san.type == URI && san.value.matches('${local.spiffe_san_pattern}'))"
      }
    }
  }

  depends_on = [google_project_service.this]
}

# TASK-03/06 shared spec PR #148: profile constraints are enforced by CAS,
# independently of identity's selection and strict returned-leaf validation.
resource "google_privateca_certificate_template" "workload" {
  for_each    = local.certificate_profiles
  project     = local.project_id
  location    = var.region
  name        = "${local.certificate_template_prefix}-${each.key}"
  description = "Agentarium ${each.key} TLS certificate profile"

  predefined_values {
    ca_options {
      is_ca = false
    }
    key_usage {
      base_key_usage {
        digital_signature = true
      }
      extended_key_usage {
        client_auth = true
        server_auth = each.value.server_auth
      }
    }
  }

  # Only pass an extension already fixed by this template's own baseline:
  # a requested isCa=true is overwritten with false. All additional request
  # extensions are dropped. An empty block would be omitted by google 8.6.0
  # and would impose no passthrough restriction.
  passthrough_extensions {
    known_extensions = ["CA_OPTIONS"]
  }
  identity_constraints {
    allow_subject_alt_names_passthrough = true
    allow_subject_passthrough           = false
    cel_expression {
      title       = "agentarium-${each.key}-uri-only"
      description = "Exactly one existing URI SAN for this certificate profile."
      expression  = "subject_alt_names.size() == 1 && subject_alt_names.all(san, san.type == URI && san.value.matches('${each.value.san_pattern}'))"
    }
  }
  depends_on = [google_project_service.this]
}

# Root CA of the pool. SPEC-QUESTION: CA subject, key algorithm and lifetime are not specified;
# they come from the lock.
resource "google_privateca_certificate_authority" "root" {
  project                  = local.project_id
  location                 = var.region
  pool                     = google_privateca_ca_pool.this.name
  certificate_authority_id = var.lock.pki.certificate_authority_id
  type                     = "SELF_SIGNED"
  lifetime                 = var.lock.pki.ca_lifetime
  deletion_protection      = true

  config {
    subject_config {
      subject {
        common_name  = var.lock.pki.ca_common_name
        organization = var.lock.pki.ca_organization
      }
    }

    x509_config {
      ca_options {
        is_ca = true
      }

      key_usage {
        base_key_usage {
          cert_sign = true
          crl_sign  = true
        }

        extended_key_usage {}
      }
    }
  }

  key_spec {
    algorithm = var.lock.pki.ca_key_algorithm
  }
}
