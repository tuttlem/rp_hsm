#[path = "protocol/lifecycle_fixtures.rs"]
mod lifecycle_fixtures;
#[path = "protocol/key_store_fixtures.rs"]
mod key_store_fixtures;
#[path = "contract/protocol_vectors.rs"]
mod protocol_vectors;
#[path = "contract/provisioning_vectors.rs"]
mod provisioning_vectors;
#[path = "contract/state_enforcement_vectors.rs"]
mod state_enforcement_vectors;
#[path = "contract/recovery_zeroize_vectors.rs"]
mod recovery_zeroize_vectors;
#[path = "contract/key_store_vectors.rs"]
mod key_store_vectors;
#[path = "contract/key_lifecycle_vectors.rs"]
mod key_lifecycle_vectors;
#[path = "contract/key_store_recovery_vectors.rs"]
mod key_store_recovery_vectors;
#[path = "contract/auth_command_vectors.rs"]
mod auth_command_vectors;
#[path = "contract/auth_redaction_vectors.rs"]
mod auth_redaction_vectors;
#[path = "contract/crypto_command_vectors.rs"]
mod crypto_command_vectors;
#[path = "contract/crypto_redaction_vectors.rs"]
mod crypto_redaction_vectors;
#[path = "contract/asymmetric_encryption_vectors.rs"]
mod asymmetric_encryption_vectors;
#[path = "contract/policy_command_vectors.rs"]
mod policy_command_vectors;
#[path = "contract/policy_denial_vectors.rs"]
mod policy_denial_vectors;
#[path = "contract/policy_approval_vectors.rs"]
mod policy_approval_vectors;
#[path = "contract/policy_coverage_vectors.rs"]
mod policy_coverage_vectors;
#[path = "contract/audit_command_vectors.rs"]
mod audit_command_vectors;
#[path = "contract/audit_event_vectors.rs"]
mod audit_event_vectors;
#[path = "contract/health_status_vectors.rs"]
mod health_status_vectors;
#[path = "contract/audit_retention_vectors.rs"]
mod audit_retention_vectors;
#[path = "contract/firmware_update_vectors.rs"]
mod firmware_update_vectors;
#[path = "contract/firmware_version_policy_vectors.rs"]
mod firmware_version_policy_vectors;
#[path = "contract/update_recovery_vectors.rs"]
mod update_recovery_vectors;
