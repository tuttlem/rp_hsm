#![allow(dead_code)]

use ed25519_dalek::Signer;
use rp_hsm::protocol::{
    DeviceState, MessageKind, ProtocolEngine, ProtocolFrame, SessionState, StatusCode, encode_frame,
};
use sha2::{Digest, Sha256};

pub const UPDATE_SEED: [u8; 32] = *b"rp_hsm_update_anchor_seed_v1____";

pub fn request(code: u8, flags: u8, payload: &[u8]) -> std::vec::Vec<u8> {
    let frame = ProtocolFrame::new(MessageKind::Request, code, flags, payload).unwrap_or_default();
    encode_frame(&frame).unwrap_or_default().into_iter().collect()
}

pub fn begin_auth(engine: &mut ProtocolEngine, role: u8) -> [u8; 4] {
    let response = engine.handle_bytes(&request(0x06, 0x00, &[role]));
    assert_eq!(response.code, StatusCode::Success.as_u8());
    response.payload.as_slice()[0..4].try_into().unwrap_or([0; 4])
}

pub fn complete_auth(
    engine: &mut ProtocolEngine,
    challenge_id: [u8; 4],
    counter: u32,
    proof: &[u8],
) -> [u8; 4] {
    let mut payload = std::vec::Vec::from(challenge_id);
    payload.extend_from_slice(&counter.to_le_bytes());
    payload.push(u8::try_from(proof.len()).unwrap_or(0));
    payload.extend_from_slice(proof);
    let response = engine.handle_bytes(&request(0x07, 0x02, &payload));
    assert_eq!(response.code, StatusCode::Success.as_u8());
    response.payload.as_slice()[0..4].try_into().unwrap_or([0; 4])
}

pub fn authorized(session_id: [u8; 4], counter: u32, inner: &[u8]) -> std::vec::Vec<u8> {
    let mut payload = std::vec::Vec::from(session_id);
    payload.extend_from_slice(&counter.to_le_bytes());
    payload.extend_from_slice(inner);
    payload
}

pub fn provisioned_admin_engine() -> (ProtocolEngine, [u8; 4]) {
    let mut engine = ProtocolEngine::new(DeviceState::Operational, SessionState::Unauthenticated);
    let challenge = begin_auth(&mut engine, 0x03);
    let session = complete_auth(&mut engine, challenge, 1, b"ADMIN");
    (engine, session)
}

pub fn recovery_engine() -> (ProtocolEngine, [u8; 4]) {
    let mut engine = ProtocolEngine::new(DeviceState::Recovery, SessionState::Unauthenticated);
    let challenge = begin_auth(&mut engine, 0x04);
    let session = complete_auth(&mut engine, challenge, 1, b"RECVR");
    (engine, session)
}

pub fn manifest_payload(
    version: (u16, u16, u16, u16),
    image: &[u8],
    target_slot: u8,
) -> std::vec::Vec<u8> {
    let digest = Sha256::digest(image);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&UPDATE_SEED);
    let mut message = std::vec::Vec::new();
    message.push(1);
    message.extend_from_slice(&version.0.to_le_bytes());
    message.extend_from_slice(&version.1.to_le_bytes());
    message.extend_from_slice(&version.2.to_le_bytes());
    message.extend_from_slice(&version.3.to_le_bytes());
    message.extend_from_slice(&u32::try_from(image.len()).unwrap_or(0).to_le_bytes());
    message.extend_from_slice(digest.as_slice());
    message.push(target_slot);
    message.extend_from_slice(&0u16.to_le_bytes());
    let signature = signing_key.sign(&message);
    let mut payload = message;
    payload.push(0x01);
    payload.extend_from_slice(&64u16.to_le_bytes());
    payload.extend_from_slice(&signature.to_bytes());
    payload
}

pub fn begin_update(
    engine: &mut ProtocolEngine,
    session_id: [u8; 4],
    counter: u32,
    version: (u16, u16, u16, u16),
    image: &[u8],
) -> rp_hsm::protocol::ProtocolFrame {
    let inner = manifest_payload(version, image, 0x02);
    engine.handle_bytes(&request(0x99, 0x02, &authorized(session_id, counter, &inner)))
}
