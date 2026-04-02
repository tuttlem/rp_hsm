#![allow(dead_code)]

use rp_hsm::protocol::{
    DeviceState, ExportPolicy, KeyAlgorithm, KeyOrigin, MessageKind, ProtocolEngine, ProtocolFrame,
    SessionState, decode_frame, encode_frame, revoke_marker,
};

pub const USAGE_SIGN: u8 = 0x01;
pub const USAGE_EXPORT: u8 = 0x80;

pub fn operational_engine() -> ProtocolEngine {
    ProtocolEngine::new(DeviceState::Operational, SessionState::Administrator)
}

pub fn recovery_engine() -> ProtocolEngine {
    ProtocolEngine::new(DeviceState::Recovery, SessionState::Recovery)
}

pub fn developer_engine() -> ProtocolEngine {
    let mut engine = ProtocolEngine::new(DeviceState::Operational, SessionState::Developer);
    engine.set_developer_mode(true);
    engine
}

pub fn encode_request(code: u8, flags: u8, payload: &[u8]) -> Vec<u8> {
    let maybe_frame = ProtocolFrame::new(MessageKind::Request, code, flags, payload);
    assert!(maybe_frame.is_some());
    let frame = maybe_frame.unwrap_or_default();
    let maybe_encoded = encode_frame(&frame);
    assert!(maybe_encoded.is_some());
    maybe_encoded.unwrap_or_default().into_iter().collect()
}

pub fn decode_payload(response_bytes: &[u8]) -> Vec<u8> {
    let decoded = decode_frame(response_bytes);
    assert!(decoded.is_ok());
    decoded.unwrap_or_default().payload.into_iter().collect()
}

pub fn key_store_status_request() -> Vec<u8> {
    encode_request(0x05, 0x00, &[])
}

pub fn put_key_request(
    key_id: u8,
    algorithm: KeyAlgorithm,
    origin: KeyOrigin,
    usage_mask: u8,
    export_policy: ExportPolicy,
    material: &[u8],
) -> Vec<u8> {
    let mut payload = vec![
        key_id,
        algorithm as u8,
        origin as u8,
        usage_mask,
        export_policy as u8,
        u8::try_from(material.len()).unwrap_or(0),
    ];
    payload.extend_from_slice(material);
    encode_request(0x89, 0x02, &payload)
}

pub fn list_keys_request() -> Vec<u8> {
    encode_request(0x8a, 0x00, &[])
}

pub fn metadata_request(key_id: u8) -> Vec<u8> {
    encode_request(0x8b, 0x00, &[key_id])
}

pub fn revoke_key_request(key_id: u8) -> Vec<u8> {
    encode_request(0x8c, 0x02, &[key_id, revoke_marker()])
}

pub fn destroy_key_request(key_id: u8) -> Vec<u8> {
    encode_request(0x8d, 0x02, &[key_id, 0xde, 0xad])
}
