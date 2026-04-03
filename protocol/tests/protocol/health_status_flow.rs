use rp_hsm::protocol::{
    AuditJournal, DeviceState, MessageKind, ProtocolEngine, ProtocolFrame, SessionState, StatusCode,
    encode_frame,
};

#[test]
fn health_status_reports_public_operational_summary() {
    let mut engine = ProtocolEngine::new(DeviceState::Operational, SessionState::Unauthenticated);
    let request = ProtocolFrame::new(MessageKind::Request, 0x0c, 0x00, &[]).unwrap_or_default();
    let response = engine.handle_bytes(&encode_frame(&request).unwrap_or_default());
    assert_eq!(response.code, StatusCode::Success.as_u8());
    assert_eq!(response.payload[0], DeviceState::Operational as u8);
    assert_eq!(response.payload.len(), 13);
}

#[test]
fn health_status_reports_representative_device_conditions() {
    for state in [
        DeviceState::Locked,
        DeviceState::Recovery,
        DeviceState::Zeroized,
    ] {
        let mut engine = ProtocolEngine::new(state, SessionState::Unauthenticated);
        let request = ProtocolFrame::new(MessageKind::Request, 0x0c, 0x00, &[]).unwrap_or_default();
        let response = engine.handle_bytes(&encode_frame(&request).unwrap_or_default());
        assert_eq!(response.code, StatusCode::Success.as_u8());
        assert_eq!(response.payload[0], state as u8);
        assert_eq!(response.payload.len(), 13);
    }

    let mut degraded = ProtocolEngine::new(DeviceState::Operational, SessionState::Unauthenticated);
    let mut snapshot = AuditJournal::new().snapshot();
    snapshot.corruption_detected = true;
    snapshot.retrieval_locked = true;
    degraded.restore_audit_snapshot(snapshot);
    let request = ProtocolFrame::new(MessageKind::Request, 0x0c, 0x00, &[]).unwrap_or_default();
    let response = degraded.handle_bytes(&encode_frame(&request).unwrap_or_default());
    assert_eq!(response.code, StatusCode::Success.as_u8());
    assert_eq!(response.payload[7], 0x05);
    assert_eq!(response.payload[12], 0x01);
}

#[test]
fn audit_page_requires_authorized_review_role() {
    let mut engine = ProtocolEngine::new(DeviceState::Operational, SessionState::Unauthenticated);
    let request = ProtocolFrame::new(
        MessageKind::Request,
        0x0d,
        0x00,
        &[0x00, 0x00, 0x00, 0x00, 0x01],
    )
    .unwrap_or_default();
    let response = engine.handle_bytes(&encode_frame(&request).unwrap_or_default());
    assert_eq!(response.code, StatusCode::ValidationError.as_u8());
}
