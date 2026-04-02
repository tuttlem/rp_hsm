use rp_hsm::protocol::{
    DeviceState, MessageKind, ProtocolEngine, ProtocolFrame, SessionState, StatusCode,
    encode_frame,
};

#[test]
fn restricted_command_requires_authorization() {
    let mut engine = ProtocolEngine::new(DeviceState::Factory, SessionState::Unauthenticated);
    let maybe_frame = ProtocolFrame::new(MessageKind::Request, 0x80, 0x02, b"owner");
    assert!(maybe_frame.is_some());
    let frame = maybe_frame.unwrap_or_default();
    let maybe_encoded = encode_frame(&frame);
    assert!(maybe_encoded.is_some());
    let encoded = maybe_encoded.unwrap_or_default();
    let response = engine.handle_bytes(&encoded);
    assert_eq!(response.code, StatusCode::AuthorizationError.as_u8());
}

#[test]
fn command_catalog_remains_available_when_locked() {
    let mut engine = ProtocolEngine::new(DeviceState::Locked, SessionState::Unauthenticated);
    let maybe_frame = ProtocolFrame::new(MessageKind::Request, 0x03, 0x00, &[0x00]);
    assert!(maybe_frame.is_some());
    let frame = maybe_frame.unwrap_or_default();
    let maybe_encoded = encode_frame(&frame);
    assert!(maybe_encoded.is_some());
    let encoded = maybe_encoded.unwrap_or_default();
    let response = engine.handle_bytes(&encoded);
    assert_eq!(response.code, StatusCode::Success.as_u8());
    assert_eq!(response.payload.as_slice(), &[5, 0x01, 0x02, 0x03, 0x04, 0x05]);
}
