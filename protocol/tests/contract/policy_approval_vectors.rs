use rp_hsm::protocol::{DeviceState, MessageKind, PolicyProfile, ProtocolEngine, ProtocolFrame, SessionState, StatusCode, encode_frame};

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
fn protected_action_returns_bounded_approval_ticket_reference() {
    let mut engine = ProtocolEngine::new(DeviceState::Operational, SessionState::Unauthenticated);
    let profile = PolicyProfile {
        dual_control_enabled: true,
        ..PolicyProfile::default()
    };
    engine.restore_policy_profile(profile);

    let challenge = begin_auth(&mut engine, 0x03);
    let session = complete_auth(&mut engine, challenge, 1, b"ADMIN");
    let response = engine.handle_bytes(&request(
        0x87,
        0x02,
        &authorized(session, 2, &[0xde, 0xad]),
    ));
    assert_eq!(response.code, StatusCode::AuthorizationError.as_u8());
    assert_eq!(response.payload.len(), 5);
    assert_eq!(response.payload[0], 0x05);
}
