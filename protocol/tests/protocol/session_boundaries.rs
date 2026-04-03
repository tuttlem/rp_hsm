use rp_hsm::protocol::{
    DeviceState, MessageKind, ProtocolEngine, ProtocolFrame, SessionState, StatusCode,
    encode_frame,
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
fn explicit_invalidation_removes_authority() {
    let mut engine = ProtocolEngine::new(DeviceState::Operational, SessionState::Unauthenticated);
    let challenge = begin_auth(&mut engine, 0x06);
    let session = complete_auth(&mut engine, challenge, 1, b"KEYMG");

    let invalidate = engine.handle_bytes(&request(0x09, 0x02, &authorized(session, 2, &[])));
    assert_eq!(invalidate.code, StatusCode::Success.as_u8());

    let denied = engine.handle_bytes(&request(0x8a, 0x00, &authorized(session, 3, &[])));
    assert_eq!(denied.code, StatusCode::AuthorizationError.as_u8());
}

#[test]
fn expired_session_loses_privileged_access() {
    let mut engine = ProtocolEngine::new(DeviceState::Operational, SessionState::Unauthenticated);
    let challenge = begin_auth(&mut engine, 0x06);
    let session = complete_auth(&mut engine, challenge, 1, b"KEYMG");

    for _ in 0..10 {
        let _ = engine.handle_bytes(&request(0x01, 0x00, &[]));
    }

    let denied = engine.handle_bytes(&request(0x8a, 0x00, &authorized(session, 2, &[])));
    assert_eq!(denied.code, StatusCode::AuthorizationError.as_u8());
}
