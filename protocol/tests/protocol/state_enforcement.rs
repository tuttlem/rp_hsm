use rp_hsm::protocol::{
    DeviceState, MessageKind, ProtocolEngine, ProtocolFrame, SessionState, StatusCode,
    encode_frame,
};

#[test]
fn reserved_command_requires_authorization() {
    let mut engine = ProtocolEngine::new(DeviceState::Operational, SessionState::Unauthenticated);
    let maybe_frame = ProtocolFrame::new(MessageKind::Request, 0x80, 0x00, &[]);
    assert!(maybe_frame.is_some());
    let frame = maybe_frame.unwrap_or_default();
    let maybe_encoded = encode_frame(&frame);
    assert!(maybe_encoded.is_some());
    let encoded = maybe_encoded.unwrap_or_default();
    let response = engine.handle_bytes(&encoded);
    assert_eq!(response.code, StatusCode::AuthorizationError.as_u8());
}

#[test]
fn command_catalog_is_denied_when_out_of_state() {
    let mut engine = ProtocolEngine::new(DeviceState::Locked, SessionState::Unauthenticated);
    let maybe_frame = ProtocolFrame::new(MessageKind::Request, 0x03, 0x00, &[0x00]);
    assert!(maybe_frame.is_some());
    let frame = maybe_frame.unwrap_or_default();
    let maybe_encoded = encode_frame(&frame);
    assert!(maybe_encoded.is_some());
    let encoded = maybe_encoded.unwrap_or_default();
    let response = engine.handle_bytes(&encoded);
    assert_eq!(response.code, StatusCode::StateError.as_u8());
}
