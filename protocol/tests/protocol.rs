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
