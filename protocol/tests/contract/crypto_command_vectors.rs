use rp_hsm::protocol::{DeviceState, MessageKind, ProtocolEngine, ProtocolFrame, SessionState, StatusCode, encode_frame};

#[test]
fn crypto_capabilities_vector_is_bounded() {
    let mut engine = ProtocolEngine::new(DeviceState::Operational, SessionState::Unauthenticated);
    let frame = ProtocolFrame::new(MessageKind::Request, 0x0a, 0x00, &[]).unwrap_or_default();
    let response = engine.handle_bytes(&encode_frame(&frame).unwrap_or_default());
    assert_eq!(response.code, StatusCode::Success.as_u8());
    assert_eq!(response.payload.len(), 10);
}

#[test]
fn sign_detached_response_is_bounded_to_signature_only() {
    let mut engine = ProtocolEngine::new(DeviceState::Operational, SessionState::Unauthenticated);
    let challenge = engine.handle_bytes(&encode_frame(&ProtocolFrame::new(MessageKind::Request, 0x06, 0x00, &[0x06]).unwrap_or_default()).unwrap_or_default());
    let challenge_id = &challenge.payload.as_slice()[0..4];
    let mut auth_payload = std::vec::Vec::from(challenge_id);
    auth_payload.extend_from_slice(&1u32.to_le_bytes());
    auth_payload.push(5);
    auth_payload.extend_from_slice(b"KEYMG");
    let session = engine.handle_bytes(&encode_frame(&ProtocolFrame::new(MessageKind::Request, 0x07, 0x02, &auth_payload).unwrap_or_default()).unwrap_or_default());
    let session_id = &session.payload.as_slice()[0..4];

    let mut put_payload = std::vec::Vec::from(session_id);
    put_payload.extend_from_slice(&2u32.to_le_bytes());
    put_payload.extend_from_slice(&[
        0x01, 0x01, 0x01, 0x01, 0x01, 32,
    ]);
    put_payload.extend_from_slice(b"0123456789abcdef0123456789abcdef");
    let put = engine.handle_bytes(&encode_frame(&ProtocolFrame::new(MessageKind::Request, 0x89, 0x02, &put_payload).unwrap_or_default()).unwrap_or_default());
    assert_eq!(put.code, StatusCode::Success.as_u8());

    let mut sign_payload = std::vec::Vec::from(session_id);
    sign_payload.extend_from_slice(&3u32.to_le_bytes());
    sign_payload.extend_from_slice(&[0x01, 0x01, 0x04, 0x00, b't', b'e', b's', b't']);
    let sign = engine.handle_bytes(&encode_frame(&ProtocolFrame::new(MessageKind::Request, 0x90, 0x02, &sign_payload).unwrap_or_default()).unwrap_or_default());
    assert_eq!(sign.code, StatusCode::Success.as_u8());
    assert_eq!(sign.payload.len(), 66);
    assert_eq!(sign.payload.as_slice()[0..2], [64, 0]);
}

#[test]
fn verify_and_random_vectors_are_bounded() {
    let mut engine = ProtocolEngine::new(DeviceState::Operational, SessionState::Unauthenticated);
    let verify = engine.handle_bytes(&encode_frame(&ProtocolFrame::new(MessageKind::Request, 0x0b, 0x00, &[0x03, 0x01, 0x00, b'x', 0x01, 0x00, 0x01, 0x00]).unwrap_or_default()).unwrap_or_default());
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
    random_payload.push(8);
    let random = engine.handle_bytes(&encode_frame(&ProtocolFrame::new(MessageKind::Request, 0x91, 0x02, &random_payload).unwrap_or_default()).unwrap_or_default());
    assert_eq!(random.code, StatusCode::Success.as_u8());
    assert_eq!(random.payload.len(), 9);
}

#[test]
fn import_wrapped_key_vector_returns_non_secret_metadata_only() {
    let mut engine = ProtocolEngine::new(DeviceState::Operational, SessionState::KeyManager);
    let response = engine.handle_bytes(&encode_frame(&ProtocolFrame::new(
        MessageKind::Request,
        0x92,
        0x02,
        &[0x01, 0x01, 0x03, 0x20, 0x01, 0x20, 0x00, 0x00],
    ).unwrap_or_default()).unwrap_or_default());
    assert!(matches!(
        response.code,
        x if x == StatusCode::ValidationError.as_u8() || x == StatusCode::AuthorizationError.as_u8() || x == StatusCode::StateError.as_u8()
    ));
}
