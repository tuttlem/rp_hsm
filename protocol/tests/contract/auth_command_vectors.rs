use rp_hsm::protocol::{StatusCode, decode_frame, encode_frame, MessageKind, ProtocolFrame};

#[test]
fn authentication_challenge_vector_is_bounded() {
    let mut engine = rp_hsm::protocol::ProtocolEngine::new(
        rp_hsm::protocol::DeviceState::Operational,
        rp_hsm::protocol::SessionState::Unauthenticated,
    );
    let frame = ProtocolFrame::new(MessageKind::Request, 0x06, 0x00, &[0x03]).unwrap_or_default();
    let response = engine.handle_bytes(&encode_frame(&frame).unwrap_or_default());
    assert_eq!(response.code, StatusCode::Success.as_u8());
    assert_eq!(response.payload.as_slice()[4], 0x03);
}

#[test]
fn session_status_vector_is_redacted_and_bounded() {
    let mut engine = rp_hsm::protocol::ProtocolEngine::new(
        rp_hsm::protocol::DeviceState::Operational,
        rp_hsm::protocol::SessionState::Unauthenticated,
    );
    let frame = ProtocolFrame::new(MessageKind::Request, 0x08, 0x00, &[]).unwrap_or_default();
    let response = engine.handle_bytes(&encode_frame(&frame).unwrap_or_default());
    let decoded = decode_frame(&encode_frame(&response).unwrap_or_default()).unwrap_or_default();
    assert_eq!(decoded.code, StatusCode::Success.as_u8());
    assert_eq!(decoded.payload.len(), 6);
}
