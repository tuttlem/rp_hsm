use rp_hsm::protocol::{DeviceState, ProtocolEngine, SessionState, StatusCode};

use super::lifecycle_fixtures::{encode_request, lifecycle_status_request};

#[test]
fn protected_commands_are_denied_in_provisioned_state() {
    let mut engine = ProtocolEngine::new(DeviceState::Provisioned, SessionState::Administrator);
    let response = engine.handle_bytes(&encode_request(0x82, 0x02, &[0x11]));
    assert_eq!(response.code, StatusCode::StateError.as_u8());
}

#[test]
fn public_status_remains_available_when_locked() {
    let mut engine = ProtocolEngine::new(DeviceState::Locked, SessionState::Unauthenticated);
    let response = engine.handle_bytes(&lifecycle_status_request());
    assert_eq!(response.code, StatusCode::Success.as_u8());
    assert_eq!(response.payload.as_slice(), &[0x04, 0x00, 0x00, 0x00]);
}
