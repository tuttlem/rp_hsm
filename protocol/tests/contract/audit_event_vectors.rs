use rp_hsm::protocol::{
    AuditEvent, AuditEventClass, AuditEventCode, AuditResultClass, AuthorityRole, DeviceState,
    SessionState, encode_audit_page_payload,
};

#[test]
fn audit_event_vector_uses_bounded_taxonomy_and_detail_shape() {
    let event = AuditEvent::new(
        7,
        AuditEventClass::SecurityDenial,
        AuditEventCode::CommandDenied,
        11,
        DeviceState::Operational,
        AuthorityRole::Administrator,
        SessionState::Administrator,
        AuditResultClass::Denied,
        &[0x80, 0x06],
    );
    assert_eq!(event.sequence_id, 7);
    assert_eq!(event.event_class as u8, 0x02);
    assert_eq!(event.event_code as u8, 0x02);
    assert_eq!(event.result_class as u8, 0x02);
    assert_eq!(event.detail_len, 2);
}

#[test]
#[allow(clippy::expect_used)]
fn audit_page_entry_shape_is_stable_and_metadata_only() {
    let event = AuditEvent::new(
        9,
        AuditEventClass::ObservabilityAccess,
        AuditEventCode::AuditPageViewed,
        13,
        DeviceState::Operational,
        AuthorityRole::Recovery,
        SessionState::Recovery,
        AuditResultClass::Success,
        &[0x04, 0x01],
    );
    let payload = encode_audit_page_payload(
        &[event],
        rp_hsm::protocol::AuditRetrievalCursor {
            start_sequence: 0,
            max_events: 1,
            next_sequence: None,
            truncated: false,
        },
    )
    .expect("page payload");
    assert_eq!(payload[0], 1);
    assert_eq!(payload[1], 0);
    assert_eq!(payload[6], 0);
    assert_eq!(u32::from_le_bytes([payload[7], payload[8], payload[9], payload[10]]), 9);
    assert_eq!(payload[11], AuditEventClass::ObservabilityAccess as u8);
    assert_eq!(payload[12], AuditEventCode::AuditPageViewed as u8);
}
