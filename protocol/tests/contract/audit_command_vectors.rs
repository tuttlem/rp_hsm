use rp_hsm::protocol::{
    DeviceState, MessageKind, ProtocolEngine, ProtocolFrame, SessionState, StatusCode,
    encode_frame,
};

#[test]
fn get_health_status_vector_is_bounded_and_non_secret() {
    let mut engine = ProtocolEngine::new(DeviceState::Operational, SessionState::Unauthenticated);
    let frame = ProtocolFrame::new(MessageKind::Request, 0x0c, 0x00, &[]).unwrap_or_default();
    let response = engine.handle_bytes(&encode_frame(&frame).unwrap_or_default());
    assert_eq!(response.code, StatusCode::Success.as_u8());
    assert_eq!(response.payload.len(), 13);
    assert_eq!(response.payload[0], DeviceState::Operational as u8);
}

#[test]
fn get_audit_page_vector_contains_bounded_header_and_entry_shape() {
    let mut engine = ProtocolEngine::new(DeviceState::Operational, SessionState::Administrator);
    let health = ProtocolFrame::new(MessageKind::Request, 0x0c, 0x00, &[]).unwrap_or_default();
    let _ = engine.handle_bytes(&encode_frame(&health).unwrap_or_default());

    let audit = ProtocolFrame::new(
        MessageKind::Request,
        0x0d,
        0x00,
        &[0x00, 0x00, 0x00, 0x00, 0x01],
    )
    .unwrap_or_default();
    let response = engine.handle_bytes(&encode_frame(&audit).unwrap_or_default());
    assert_eq!(response.code, StatusCode::Success.as_u8());
    assert!(response.payload.len() >= 22);
    assert_eq!(response.payload[0], 1);
    assert_eq!(response.payload[6], 0);
    assert_eq!(response.payload[7], 1);
    assert_eq!(response.payload[11], 0x05);
}
