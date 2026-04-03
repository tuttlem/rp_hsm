use rp_hsm::protocol::{
    DeviceState, MessageKind, ProtocolEngine, ProtocolFrame, SessionState, StatusCode,
    encode_frame,
};

fn request(code: u8, flags: u8, payload: &[u8]) -> Vec<u8> {
    let frame = ProtocolFrame::new(MessageKind::Request, code, flags, payload).unwrap_or_default();
    encode_frame(&frame).unwrap_or_default().into_iter().collect()
}

#[test]
fn repeated_failed_authentication_triggers_lockout() {
    let mut engine = ProtocolEngine::new(DeviceState::Operational, SessionState::Unauthenticated);
    for counter in 1u32..=3 {
        let begin = engine.handle_bytes(&request(0x06, 0x00, &[0x03]));
        let challenge_id: [u8; 4] = begin.payload.as_slice()[0..4].try_into().unwrap_or([0; 4]);
        let mut payload = Vec::from(challenge_id);
        payload.extend_from_slice(&counter.to_le_bytes());
        payload.push(5);
        payload.extend_from_slice(b"WRONG");
        let response = engine.handle_bytes(&request(0x07, 0x02, &payload));
        assert_eq!(response.code, StatusCode::AuthorizationError.as_u8());
    }

    let locked = engine.handle_bytes(&request(0x06, 0x00, &[0x03]));
    assert_eq!(locked.code, StatusCode::AuthorizationError.as_u8());
}
