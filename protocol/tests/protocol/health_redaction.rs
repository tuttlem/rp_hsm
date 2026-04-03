use rp_hsm::protocol::{
    DeviceState, MessageKind, ProtocolEngine, ProtocolFrame, SessionState, StatusCode,
    encode_frame,
};

#[test]
fn health_status_never_echoes_key_material_or_auth_proof_bytes() {
    let mut engine = ProtocolEngine::new(DeviceState::Operational, SessionState::Unauthenticated);
    let response = engine.handle_bytes(
        &encode_frame(&ProtocolFrame::new(MessageKind::Request, 0x0c, 0x00, &[]).unwrap_or_default())
            .unwrap_or_default(),
    );
    assert_eq!(response.code, StatusCode::Success.as_u8());
    assert_eq!(response.payload.len(), 13);
    assert_ne!(response.payload.as_slice(), b"seed-material");
    assert!(!response.payload.as_slice().windows(4).any(|window| window == b"AUTH"));
}
