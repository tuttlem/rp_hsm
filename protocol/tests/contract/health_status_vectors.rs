use rp_hsm::protocol::{
    AuditJournal, DeviceState, MessageKind, ProtocolEngine, ProtocolFrame, SessionState,
    StatusCode, encode_frame,
};

#[test]
fn health_status_vector_reports_bounded_summary_fields() {
    let mut engine = ProtocolEngine::new(DeviceState::Operational, SessionState::Unauthenticated);
    let frame = ProtocolFrame::new(MessageKind::Request, 0x0c, 0x00, &[]).unwrap_or_default();
    let response = engine.handle_bytes(&encode_frame(&frame).unwrap_or_default());
    assert_eq!(response.code, StatusCode::Success.as_u8());
    assert_eq!(response.payload.len(), 13);
    assert_eq!(response.payload[0], DeviceState::Operational as u8);
    assert_eq!(response.payload[1], 0x01);
    assert_eq!(response.payload[2], SessionState::Unauthenticated as u8);
}

#[test]
fn health_status_vector_reports_degraded_audit_without_raw_storage_bytes() {
    let mut engine = ProtocolEngine::new(DeviceState::Operational, SessionState::Unauthenticated);
    let mut snapshot = AuditJournal::new().snapshot();
    snapshot.corruption_detected = true;
    snapshot.retrieval_locked = true;
    engine.restore_audit_snapshot(snapshot);
    let frame = ProtocolFrame::new(MessageKind::Request, 0x0c, 0x00, &[]).unwrap_or_default();
    let response = engine.handle_bytes(&encode_frame(&frame).unwrap_or_default());
    assert_eq!(response.code, StatusCode::Success.as_u8());
    assert_eq!(response.payload.len(), 13);
    assert_eq!(response.payload[7], 0x05);
    assert_eq!(response.payload[12], 0x01);
}
