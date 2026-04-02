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
    response.payload.as_slice()[0..4].try_into().unwrap_or([0; 4])
}

fn complete_auth(engine: &mut ProtocolEngine, challenge_id: [u8; 4], counter: u32, proof: &[u8]) -> [u8; 4] {
    let mut payload = Vec::from(challenge_id);
    payload.extend_from_slice(&counter.to_le_bytes());
    payload.push(u8::try_from(proof.len()).unwrap_or(0));
    payload.extend_from_slice(proof);
    let response = engine.handle_bytes(&request(0x07, 0x02, &payload));
    response.payload.as_slice()[0..4].try_into().unwrap_or([0; 4])
}

#[test]
fn reboot_reconciliation_clears_active_authenticated_session() {
    let mut engine = ProtocolEngine::new(DeviceState::Operational, SessionState::Unauthenticated);
    let challenge = begin_auth(&mut engine, 0x06);
    let _session = complete_auth(&mut engine, challenge, 1, b"KEYMG");
    engine.reconcile_boot();

    let status = engine.handle_bytes(&request(0x08, 0x00, &[]));
    assert_eq!(status.code, StatusCode::Success.as_u8());
    assert_eq!(status.payload.as_slice()[0], 0x00);
}
