use rp_hsm::protocol::{
    MessageKind, ProtocolFrame, PROTOCOL_VERSION, StatusCode, decode_frame, encode_frame,
};

#[test]
fn request_frame_roundtrip_is_lossless() {
    let maybe_frame = ProtocolFrame::new(MessageKind::Request, 0x01, 0x00, &[0xAA, 0xBB]);
    assert!(maybe_frame.is_some());
    let frame = maybe_frame.unwrap_or_default();
    let maybe_encoded = encode_frame(&frame);
    assert!(maybe_encoded.is_some());
    let encoded = maybe_encoded.unwrap_or_default();
    let decoded_result = decode_frame(&encoded);
    assert!(decoded_result.is_ok());
    let decoded = decoded_result.unwrap_or_default();

    assert_eq!(decoded.version, PROTOCOL_VERSION);
    assert_eq!(decoded.kind, MessageKind::Request);
    assert_eq!(decoded.code, 0x01);
    assert_eq!(decoded.payload.as_slice(), &[0xAA, 0xBB]);
}

#[test]
fn response_frame_roundtrip_is_lossless() {
    let maybe_frame = ProtocolFrame::new(
        MessageKind::Response,
        StatusCode::Success.as_u8(),
        0x00,
        &[0x01],
    );
    assert!(maybe_frame.is_some());
    let frame = maybe_frame.unwrap_or_default();
    let maybe_encoded = encode_frame(&frame);
    assert!(maybe_encoded.is_some());
    let encoded = maybe_encoded.unwrap_or_default();
    let decoded_result = decode_frame(&encoded);
    assert!(decoded_result.is_ok());
    let decoded = decoded_result.unwrap_or_default();

    assert_eq!(decoded.kind, MessageKind::Response);
    assert_eq!(decoded.code, StatusCode::Success.as_u8());
    assert_eq!(decoded.payload.as_slice(), &[0x01]);
}
