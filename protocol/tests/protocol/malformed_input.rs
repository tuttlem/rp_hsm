use rp_hsm::protocol::{
    MAX_PAYLOAD_LEN, MessageKind, PROTOCOL_VERSION, ProtocolEngine, StatusCode, decode_frame,
    encode_frame,
};

#[test]
fn truncated_frame_is_rejected() {
    let mut engine = ProtocolEngine::new(
        rp_hsm::protocol::DeviceState::Operational,
        rp_hsm::protocol::SessionState::Unauthenticated,
    );
    let response = engine.handle_bytes(&[PROTOCOL_VERSION, MessageKind::Request as u8, 0x01]);
    assert_eq!(response.code, StatusCode::FormatError.as_u8());
}

#[test]
fn oversized_payload_is_rejected() {
    let oversized = u16::try_from(MAX_PAYLOAD_LEN + 1).unwrap_or(u16::MAX).to_le_bytes();
    let bytes = [
        PROTOCOL_VERSION,
        MessageKind::Request as u8,
        0x01,
        0x00,
        oversized[0],
        oversized[1],
    ];
    let result = decode_frame(&bytes);
    assert!(matches!(
        result,
        Err(rp_hsm::protocol::DecodeError::OversizedPayload)
    ));
}

#[test]
fn reserved_flag_misuse_is_rejected() {
    let bytes = [PROTOCOL_VERSION, MessageKind::Request as u8, 0x01, 0x80, 0x00, 0x00];
    let result = decode_frame(&bytes);
    assert!(matches!(
        result,
        Err(rp_hsm::protocol::DecodeError::InvalidFlags)
    ));
}

#[test]
fn invalid_length_is_rejected() {
    let mut engine = ProtocolEngine::new(
        rp_hsm::protocol::DeviceState::Operational,
        rp_hsm::protocol::SessionState::Unauthenticated,
    );
    let maybe_frame =
        rp_hsm::protocol::ProtocolFrame::new(MessageKind::Request, 0x02, 0x00, &[0x00]);
    assert!(maybe_frame.is_some());
    let frame = maybe_frame.unwrap_or_default();
    let maybe_encoded = encode_frame(&frame);
    assert!(maybe_encoded.is_some());
    let mut encoded = maybe_encoded.unwrap_or_default();
    encoded[4] = 0x02;
    let response = engine.handle_bytes(&encoded);
    assert_eq!(response.code, StatusCode::FormatError.as_u8());
}
