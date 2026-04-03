#[path = "protocol/frame_roundtrip.rs"]
mod frame_roundtrip;
#[path = "protocol/lifecycle_fixtures.rs"]
mod lifecycle_fixtures;
#[path = "protocol/malformed_input.rs"]
mod malformed_input;
#[path = "protocol/provisioning_flow.rs"]
mod provisioning_flow;
#[path = "protocol/provisioning_recovery.rs"]
mod provisioning_recovery;
#[path = "protocol/command_gating.rs"]
mod command_gating;
#[path = "protocol/state_transitions.rs"]
mod state_transitions;
#[path = "protocol/state_enforcement.rs"]
mod state_enforcement;
#[path = "protocol/recovery_flow.rs"]
mod recovery_flow;
#[path = "protocol/zeroize_flow.rs"]
mod zeroize_flow;
#[path = "protocol/developer_reset.rs"]
mod developer_reset;
#[path = "protocol/key_store_fixtures.rs"]
mod key_store_fixtures;
#[path = "protocol/persistent_retention.rs"]
mod persistent_retention;
#[path = "protocol/journal_recovery.rs"]
mod journal_recovery;
#[path = "protocol/key_lifecycle.rs"]
mod key_lifecycle;
#[path = "protocol/key_policy_enforcement.rs"]
mod key_policy_enforcement;
#[path = "protocol/store_corruption.rs"]
mod store_corruption;
#[path = "protocol/rollback_detection.rs"]
mod rollback_detection;
#[path = "protocol/store_capacity.rs"]
mod store_capacity;
#[path = "protocol/auth_administrative_access.rs"]
mod auth_administrative_access;
#[path = "protocol/session_boundaries.rs"]
mod session_boundaries;
#[path = "protocol/session_invalidation.rs"]
mod session_invalidation;
#[path = "protocol/auth_lockout.rs"]
mod auth_lockout;
#[path = "protocol/session_freshness.rs"]
mod session_freshness;
#[path = "protocol/crypto_fixtures.rs"]
mod crypto_fixtures;
#[path = "protocol/crypto_surface_validation.rs"]
mod crypto_surface_validation;
#[path = "protocol/managed_signing.rs"]
mod managed_signing;
#[path = "protocol/public_verification.rs"]
mod public_verification;
#[path = "protocol/random_generation.rs"]
mod random_generation;
#[path = "protocol/wrapped_import.rs"]
mod wrapped_import;
#[path = "protocol/high_risk_denials.rs"]
mod high_risk_denials;
#[path = "protocol/policy_command_matrix.rs"]
mod policy_command_matrix;
#[path = "protocol/approval_ticket_lifecycle.rs"]
mod approval_ticket_lifecycle;
#[path = "protocol/protected_action_denials.rs"]
mod protected_action_denials;
#[path = "protocol/approval_staleness.rs"]
mod approval_staleness;
#[path = "protocol/policy_reviewability.rs"]
mod policy_reviewability;
#[path = "protocol/health_status_flow.rs"]
mod health_status_flow;
#[path = "protocol/health_redaction.rs"]
mod health_redaction;
#[path = "protocol/audit_event_capture.rs"]
mod audit_event_capture;
#[path = "protocol/audit_retrieval_flow.rs"]
mod audit_retrieval_flow;
#[path = "protocol/audit_retention_flow.rs"]
mod audit_retention_flow;
#[path = "protocol/audit_disclosure_controls.rs"]
mod audit_disclosure_controls;
#[path = "protocol/audit_fail_closed.rs"]
mod audit_fail_closed;
#[path = "protocol/audit_surface_validation.rs"]
mod audit_surface_validation;
