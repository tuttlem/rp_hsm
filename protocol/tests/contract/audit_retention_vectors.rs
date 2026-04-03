use rp_hsm::protocol::{
    AuditEventClass, AuditEventCode, AuditJournal, AuditResultClass, AuditStoreState,
    AuthorityRole, DeviceState, MessageKind, ProtocolEngine, ProtocolFrame, SessionState,
    StatusCode, MAX_AUDIT_EVENTS, encode_frame, encode_audit_page_payload,
};

fn request(code: u8, flags: u8, payload: &[u8]) -> Vec<u8> {
    let frame = ProtocolFrame::new(MessageKind::Request, code, flags, payload).unwrap_or_default();
    encode_frame(&frame).unwrap_or_default().into_iter().collect()
}

fn begin_auth(engine: &mut ProtocolEngine, role: u8) -> [u8; 4] {
    let response = engine.handle_bytes(&request(0x06, 0x00, &[role]));
    assert_eq!(response.code, StatusCode::Success.as_u8());
    response.payload.as_slice()[0..4].try_into().unwrap_or([0; 4])
}

fn complete_auth(engine: &mut ProtocolEngine, challenge_id: [u8; 4], counter: u32, proof: &[u8]) -> [u8; 4] {
    let mut payload = Vec::from(challenge_id);
    payload.extend_from_slice(&counter.to_le_bytes());
    payload.push(u8::try_from(proof.len()).unwrap_or(0));
    payload.extend_from_slice(proof);
    let response = engine.handle_bytes(&request(0x07, 0x02, &payload));
    assert_eq!(response.code, StatusCode::Success.as_u8());
    response.payload.as_slice()[0..4].try_into().unwrap_or([0; 4])
}

fn authorized(session_id: [u8; 4], counter: u32, inner: &[u8]) -> Vec<u8> {
    let mut payload = Vec::from(session_id);
    payload.extend_from_slice(&counter.to_le_bytes());
    payload.extend_from_slice(inner);
    payload
}

#[test]
#[allow(clippy::expect_used, clippy::panic)]
fn retained_audit_page_vector_reports_truncation_and_cursor_shape() {
    let mut journal = AuditJournal::new();
    for seq in 0..(MAX_AUDIT_EVENTS + 2) {
        journal.record(
            AuditEventClass::ObservabilityAccess,
            AuditEventCode::HealthStatusViewed,
            u32::try_from(seq).unwrap_or(0),
            DeviceState::Operational,
            AuthorityRole::Administrator,
            SessionState::Administrator,
            AuditResultClass::Success,
            &[0x0c],
        );
    }
    let Ok((events, cursor)) = journal.page(0, 4) else {
        panic!("audit page unexpectedly unavailable");
    };
    let Some(payload) = encode_audit_page_payload(events.as_slice(), cursor) else {
        panic!("audit page unexpectedly failed to encode");
    };
    assert_eq!(payload[0], 4);
    assert!(payload[1] <= 1);
    assert!(payload[5] <= 1);
}

#[test]
#[allow(clippy::expect_used, clippy::panic)]
fn locked_audit_store_denies_retrieval_contractually() {
    let mut engine = ProtocolEngine::new(DeviceState::Operational, SessionState::Unauthenticated);
    let mut snapshot = AuditJournal::new().snapshot();
    snapshot.retrieval_locked = true;
    snapshot.corruption_detected = true;
    engine.restore_audit_snapshot(snapshot);
    let challenge = begin_auth(&mut engine, 0x03);
    let session = complete_auth(&mut engine, challenge, 1, b"ADMIN");
    let response = engine.handle_bytes(&request(
        0x0d,
        0x02,
        &authorized(session, 2, &[0, 0, 0, 0, 1]),
    ));
    assert_eq!(response.code, StatusCode::StateError.as_u8());
    let health = ProtocolFrame::new(MessageKind::Request, 0x0c, 0x00, &[]).unwrap_or_default();
    let health_response = engine.handle_bytes(&encode_frame(&health).unwrap_or_default());
    assert!(matches!(
        health_response.payload[7],
        x if x == AuditStoreState::Locked as u8 || x == AuditStoreState::Degraded as u8
    ));
    assert_eq!(health_response.payload[12], 0x01);
}
