use super::codec::StatusCode;
use super::command::{CommandDefinition, ReplayPolicy};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DeviceState {
    Booting = 0x01,
    Ready = 0x02,
    Operational = 0x03,
    Locked = 0x04,
    Failed = 0x05,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionState {
    Unauthenticated = 0x01,
    Administrator = 0x02,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionTracker {
    pub last_request_fingerprint: Option<u32>,
}

impl SessionTracker {
    pub fn record(&mut self, fingerprint: u32) {
        self.last_request_fingerprint = Some(fingerprint);
    }
}

#[must_use]
pub fn fingerprint_frame(code: u8, payload: &[u8]) -> u32 {
    let mut hash = u32::from(code);
    for &byte in payload {
        hash = hash.rotate_left(5) ^ u32::from(byte);
    }
    hash
}

/// # Errors
///
/// Returns a `StatusCode` when a command is not allowed in the current device
/// or session state.
pub fn ensure_command_allowed(
    definition: CommandDefinition,
    device_state: DeviceState,
    session_state: SessionState,
) -> Result<(), StatusCode> {
    if !definition.allowed_device_states.contains(&device_state) {
        return Err(StatusCode::StateError);
    }

    if session_state != definition.required_session_state
        && definition.required_session_state == SessionState::Administrator
    {
        return Err(StatusCode::AuthorizationError);
    }

    if !definition.enabled {
        return Err(StatusCode::StateError);
    }

    Ok(())
}

/// # Errors
///
/// Returns a `StatusCode` when a replay-sensitive command is repeated with the
/// same tracked fingerprint.
pub fn enforce_replay_policy(
    definition: CommandDefinition,
    tracker: &mut SessionTracker,
    fingerprint: u32,
) -> Result<(), StatusCode> {
    if definition.replay_policy == ReplayPolicy::SingleUse
        && tracker.last_request_fingerprint == Some(fingerprint)
    {
        return Err(StatusCode::ReplayError);
    }

    tracker.record(fingerprint);
    Ok(())
}
