use rp_hsm::protocol::{MessageKind, ProtocolEngine, ProtocolFrame, SessionState, StatusCode, DeviceState, encode_frame};

#[test]
fn failed_authentication_does_not_echo_proof_material() {
    let mut engine = ProtocolEngine::new(DeviceState::Operational, SessionState::Unauthenticated);
    let begin = ProtocolFrame::new(MessageKind::Request, 0x06, 0x00, &[0x03]).unwrap_or_default();
    let challenge = engine.handle_bytes(&encode_frame(&begin).unwrap_or_default());
    let challenge_id: [u8; 4] = challenge.payload.as_slice()[0..4].try_into().unwrap_or([0; 4]);

    let mut payload = Vec::from(challenge_id);
    payload.extend_from_slice(&1u32.to_le_bytes());
    payload.push(5);
    payload.extend_from_slice(b"WRONG");
    let complete = ProtocolFrame::new(MessageKind::Request, 0x07, 0x02, &payload).unwrap_or_default();
    let response = engine.handle_bytes(&encode_frame(&complete).unwrap_or_default());
    assert_eq!(response.code, StatusCode::AuthorizationError.as_u8());
    assert!(response.payload.is_empty());
}
