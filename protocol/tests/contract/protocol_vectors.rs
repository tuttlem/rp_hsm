use rp_hsm::protocol::{
    DeviceState, FLAG_INCLUDE_RESTRICTED, MessageKind, PROTOCOL_VERSION, ProtocolEngine,
    ProtocolFrame, SessionState, StatusCode, encode_frame,
};

fn engine() -> ProtocolEngine {
    ProtocolEngine::new(DeviceState::Operational, SessionState::Unauthenticated)
}

#[test]
fn get_protocol_version_returns_current_version() {
    let mut engine = engine();
    let maybe_frame = ProtocolFrame::new(MessageKind::Request, 0x01, 0x00, &[]);
    assert!(maybe_frame.is_some());
    let frame = maybe_frame.unwrap_or_default();
    let maybe_encoded = encode_frame(&frame);
    assert!(maybe_encoded.is_some());
    let response = engine.handle_bytes(&maybe_encoded.unwrap_or_default());
    assert_eq!(response.code, StatusCode::Success.as_u8());
    assert_eq!(response.payload.as_slice(), &[PROTOCOL_VERSION]);
}

#[test]
fn get_device_status_returns_state_and_session() {
    let mut engine = engine();
    let maybe_frame = ProtocolFrame::new(MessageKind::Request, 0x02, 0x00, &[0x00]);
    assert!(maybe_frame.is_some());
    let frame = maybe_frame.unwrap_or_default();
    let maybe_encoded = encode_frame(&frame);
    assert!(maybe_encoded.is_some());
    let response = engine.handle_bytes(&maybe_encoded.unwrap_or_default());
    assert_eq!(response.code, StatusCode::Success.as_u8());
    assert_eq!(
        response.payload.as_slice(),
        &[DeviceState::Operational as u8, SessionState::Unauthenticated as u8]
    );
}

#[test]
fn get_command_catalog_returns_public_commands() {
    let mut engine = engine();
    let maybe_frame = ProtocolFrame::new(MessageKind::Request, 0x03, 0x00, &[0x00]);
    assert!(maybe_frame.is_some());
    let frame = maybe_frame.unwrap_or_default();
    let maybe_encoded = encode_frame(&frame);
    assert!(maybe_encoded.is_some());
    let response = engine.handle_bytes(&maybe_encoded.unwrap_or_default());
    assert_eq!(response.code, StatusCode::Success.as_u8());
    assert_eq!(
        response.payload.as_slice(),
        &[11, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0a, 0x0b, 0x0c]
    );
}

#[test]
fn unknown_version_is_rejected() {
    let mut engine = engine();
    let maybe_frame = ProtocolFrame::new(MessageKind::Request, 0x01, 0x00, &[]);
    assert!(maybe_frame.is_some());
    let mut frame = maybe_frame.unwrap_or_default();
    frame.version = 9;
    let maybe_encoded = encode_frame(&frame);
    assert!(maybe_encoded.is_some());
    let response = engine.handle_bytes(&maybe_encoded.unwrap_or_default());
    assert_eq!(response.code, StatusCode::VersionError.as_u8());
}

#[test]
fn unknown_command_is_rejected() {
    let mut engine = engine();
    let maybe_frame = ProtocolFrame::new(MessageKind::Request, 0x55, 0x00, &[]);
    assert!(maybe_frame.is_some());
    let frame = maybe_frame.unwrap_or_default();
    let maybe_encoded = encode_frame(&frame);
    assert!(maybe_encoded.is_some());
    let response = engine.handle_bytes(&maybe_encoded.unwrap_or_default());
    assert_eq!(response.code, StatusCode::CommandError.as_u8());
}

#[test]
fn restricted_catalog_entries_are_hidden_from_unauthenticated_clients() {
    let mut engine = engine();
    let maybe_frame = ProtocolFrame::new(
        MessageKind::Request,
        0x03,
        FLAG_INCLUDE_RESTRICTED,
        &[0x01],
    );
    assert!(maybe_frame.is_some());
    let frame = maybe_frame.unwrap_or_default();
    let maybe_encoded = encode_frame(&frame);
    assert!(maybe_encoded.is_some());
    let response = engine.handle_bytes(&maybe_encoded.unwrap_or_default());
    assert_eq!(response.code, StatusCode::Success.as_u8());
    assert_eq!(
        response.payload.as_slice(),
        &[11, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0a, 0x0b, 0x0c]
    );
}
