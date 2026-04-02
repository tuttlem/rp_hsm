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

fn complete_auth(
    engine: &mut ProtocolEngine,
    challenge_id: [u8; 4],
    counter: u32,
    proof: &[u8],
) -> [u8; 4] {
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
fn unauthenticated_privileged_command_is_denied() {
    let mut engine = ProtocolEngine::new(DeviceState::Operational, SessionState::Unauthenticated);
    let response = engine.handle_bytes(&request(0x82, 0x02, &authorized([0, 0, 0, 0], 1, &[0x42])));
    assert_eq!(response.code, StatusCode::AuthorizationError.as_u8());
}

#[test]
fn authenticated_admin_can_lock_but_wrong_role_cannot_manage_keys() {
    let mut engine = ProtocolEngine::new(DeviceState::Operational, SessionState::Unauthenticated);
    let admin_challenge = begin_auth(&mut engine, 0x03);
    let admin_session = complete_auth(&mut engine, admin_challenge, 1, b"ADMIN");

    let lock = engine.handle_bytes(&request(0x82, 0x02, &authorized(admin_session, 2, &[0x42])));
    assert_eq!(lock.code, StatusCode::Success.as_u8());

    let wrong_role = engine.handle_bytes(&request(
        0x89,
        0x02,
        &authorized(admin_session, 3, &[0x01, 0x01, 0x01, 0x01, 0x01, 0x04, b't', b'e', b's', b't']),
    ));
    assert!(matches!(
        wrong_role.code,
        x if x == StatusCode::AuthorizationError.as_u8() || x == StatusCode::StateError.as_u8()
    ));
}
