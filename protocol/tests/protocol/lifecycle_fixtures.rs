#![allow(dead_code)]

use rp_hsm::protocol::{
    DeviceState, MessageKind, ProtocolEngine, ProtocolFrame, SessionState, decode_frame,
    developer_reset_marker, encode_frame, finalize_marker, reactivate_marker, recovery_marker,
    unlock_marker, zeroize_marker,
};

pub fn factory_engine() -> ProtocolEngine {
    ProtocolEngine::new(DeviceState::Factory, SessionState::Bootstrap)
}

pub fn operational_engine() -> ProtocolEngine {
    ProtocolEngine::new(DeviceState::Operational, SessionState::Administrator)
}

pub fn developer_engine() -> ProtocolEngine {
    ProtocolEngine::new_developer_mode()
}

pub fn encode_request(code: u8, flags: u8, payload: &[u8]) -> Vec<u8> {
    let maybe_frame = ProtocolFrame::new(MessageKind::Request, code, flags, payload);
    assert!(maybe_frame.is_some());
    let frame = maybe_frame.unwrap_or_default();
    let maybe_encoded = encode_frame(&frame);
    assert!(maybe_encoded.is_some());
    maybe_encoded.unwrap_or_default().into_iter().collect()
}

pub fn payload(response_bytes: &[u8]) -> Vec<u8> {
    let decoded = decode_frame(response_bytes);
    assert!(decoded.is_ok());
    decoded.unwrap_or_default().payload.into_iter().collect()
}

pub fn begin_provisioning(engine: &mut ProtocolEngine, owner_id: &[u8]) -> Vec<u8> {
    let request = encode_request(0x80, 0x02, owner_id);
    let response = engine.handle_bytes(&request);
    let maybe_encoded = encode_frame(&response);
    assert!(maybe_encoded.is_some());
    maybe_encoded.unwrap_or_default().into_iter().collect()
}

pub fn finalize_request_from_begin_payload(begin_payload: &[u8]) -> Vec<u8> {
    let payload = vec![
        begin_payload[1],
        begin_payload[2],
        begin_payload[3],
        begin_payload[4],
        finalize_marker(),
    ];
    encode_request(0x81, 0x02, &payload)
}

pub fn unlock_request() -> Vec<u8> {
    encode_request(0x83, 0x02, &[unlock_marker()])
}

pub fn recovery_request() -> Vec<u8> {
    encode_request(0x84, 0x02, &[recovery_marker()])
}

pub fn recover_to_provisioned_request() -> Vec<u8> {
    encode_request(0x85, 0x02, &[recovery_marker()])
}

pub fn reactivate_recovered_request(transition_id: [u8; 4]) -> Vec<u8> {
    encode_request(
        0x86,
        0x02,
        &[
            transition_id[0],
            transition_id[1],
            transition_id[2],
            transition_id[3],
            reactivate_marker(),
        ],
    )
}

pub fn zeroize_request() -> Vec<u8> {
    let marker = zeroize_marker();
    encode_request(0x87, 0x02, &marker)
}

pub fn developer_reset_request() -> Vec<u8> {
    let marker = developer_reset_marker();
    encode_request(0x88, 0x02, &marker)
}

pub fn lifecycle_status_request() -> Vec<u8> {
    encode_request(0x04, 0x00, &[])
}
