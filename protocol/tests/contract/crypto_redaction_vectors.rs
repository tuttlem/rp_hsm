use rp_hsm::protocol::{DeviceState, MessageKind, ProtocolEngine, ProtocolFrame, SessionState, StatusCode, encode_frame};

#[test]
fn failed_sign_and_import_do_not_echo_secret_material() {
    let mut engine = ProtocolEngine::new(DeviceState::Operational, SessionState::Unauthenticated);

    let sign = engine.handle_bytes(&encode_frame(&ProtocolFrame::new(
        MessageKind::Request,
        0x90,
        0x02,
        &[0, 0, 0, 0, 1, 0, 0, 0, 0x01, 0x01, 0x04, 0x00, b't', b'e', b's', b't'],
    ).unwrap_or_default()).unwrap_or_default());
    assert_eq!(sign.code, StatusCode::AuthorizationError.as_u8());
    assert!(sign.payload.is_empty());

    let import = engine.handle_bytes(&encode_frame(&ProtocolFrame::new(
        MessageKind::Request,
        0x92,
        0x02,
        &[0, 0, 0, 0, 1, 0, 0, 0, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02, 0x00, 0xaa, 0xbb, 0x01, 0xcc],
    ).unwrap_or_default()).unwrap_or_default());
    assert!(import.payload.is_empty());
}

#[test]
fn random_and_verify_results_are_non_secret_bounded_shapes() {
    let mut engine = ProtocolEngine::new(DeviceState::Operational, SessionState::Unauthenticated);
    let verify = engine.handle_bytes(
        &encode_frame(&ProtocolFrame::new(MessageKind::Request, 0x0b, 0x00, &[0x01, 0x01]).unwrap_or_default())
            .unwrap_or_default(),
    );
    assert_eq!(verify.code, StatusCode::ValidationError.as_u8());

    let challenge = engine.handle_bytes(&encode_frame(&ProtocolFrame::new(MessageKind::Request, 0x06, 0x00, &[0x03]).unwrap_or_default()).unwrap_or_default());
    let challenge_id = &challenge.payload.as_slice()[0..4];
    let mut auth_payload = std::vec::Vec::from(challenge_id);
    auth_payload.extend_from_slice(&1u32.to_le_bytes());
    auth_payload.push(5);
    auth_payload.extend_from_slice(b"ADMIN");
    let session = engine.handle_bytes(&encode_frame(&ProtocolFrame::new(MessageKind::Request, 0x07, 0x02, &auth_payload).unwrap_or_default()).unwrap_or_default());
    let session_id = &session.payload.as_slice()[0..4];
    let mut random_payload = std::vec::Vec::from(session_id);
    random_payload.extend_from_slice(&2u32.to_le_bytes());
    random_payload.push(4);
    let random = engine.handle_bytes(&encode_frame(&ProtocolFrame::new(MessageKind::Request, 0x91, 0x02, &random_payload).unwrap_or_default()).unwrap_or_default());
    assert_eq!(random.code, StatusCode::Success.as_u8());
    assert_eq!(random.payload[0], 4);
    assert_eq!(random.payload.len(), 5);
}
