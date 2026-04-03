use rp_hsm::protocol::{
    DeviceState, MessageKind, ProtocolEngine, ProtocolFrame, SessionState, StatusCode,
    encode_frame,
};

fn request(code: u8, flags: u8, payload: &[u8]) -> Vec<u8> {
    let frame = ProtocolFrame::new(MessageKind::Request, code, flags, payload).unwrap_or_default();
    encode_frame(&frame).unwrap_or_default().into_iter().collect()
}

#[test]
fn public_commands_remain_allowed_without_authentication() {
    let mut engine = ProtocolEngine::new(DeviceState::Operational, SessionState::Unauthenticated);
    let response = engine.handle_bytes(&request(0x04, 0x00, &[]));
    assert_eq!(response.code, StatusCode::Success.as_u8());
}

#[test]
fn restricted_commands_return_role_denied_when_role_is_insufficient() {
    let mut engine = ProtocolEngine::new(DeviceState::Operational, SessionState::Administrator);
    let response = engine.handle_bytes(&request(0x8a, 0x00, &[0, 0, 0, 0, 1, 0, 0, 0]));
    assert_eq!(response.code, StatusCode::AuthorizationError.as_u8());
    assert_eq!(response.payload.as_slice(), &[0x03]);
}

#[test]
fn restricted_commands_return_state_denied_when_lifecycle_is_wrong() {
    let mut engine = ProtocolEngine::new(DeviceState::Provisioned, SessionState::KeyManager);
    let response = engine.handle_bytes(&request(0x90, 0x02, &[0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0]));
    assert_eq!(response.code, StatusCode::StateError.as_u8());
    assert_eq!(response.payload.as_slice(), &[0x02]);
}
