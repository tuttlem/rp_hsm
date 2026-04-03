#![allow(dead_code)]

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{AeadInPlace, generic_array::GenericArray},
};
use ed25519_dalek::{Signer, Verifier};
use rp_hsm::protocol::{
    DeviceState, ExportPolicy, KeyAlgorithm, KeyOrigin, MessageKind, ProtocolEngine, ProtocolFrame,
    SessionState, StatusCode, USAGE_SIGN, USAGE_WRAP_IMPORT, decode_frame,
    ed25519_public_key_from_seed, encode_frame,
};

pub const ED25519_SEED: [u8; 32] = *b"0123456789abcdef0123456789abcdef";
pub const WRAP_KEY: [u8; 32] = *b"wrap-key-material-for-hsm-test!!";

pub fn request(code: u8, flags: u8, payload: &[u8]) -> std::vec::Vec<u8> {
    let frame = ProtocolFrame::new(MessageKind::Request, code, flags, payload).unwrap_or_default();
    encode_frame(&frame).unwrap_or_default().into_iter().collect()
}

pub fn decode_payload(response_bytes: &[u8]) -> std::vec::Vec<u8> {
    let decoded = decode_frame(response_bytes).unwrap_or_default();
    decoded.payload.into_iter().collect()
}

pub fn unauthenticated_operational_engine() -> ProtocolEngine {
    ProtocolEngine::new(DeviceState::Operational, SessionState::Unauthenticated)
}

pub fn developer_engine() -> ProtocolEngine {
    let mut engine = ProtocolEngine::new(DeviceState::Operational, SessionState::Developer);
    engine.set_developer_mode(true);
    engine
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

#[allow(clippy::too_many_arguments)]
pub fn put_key_request(
    session_id: [u8; 4],
    counter: u32,
    key_id: u8,
    algorithm: KeyAlgorithm,
    origin: KeyOrigin,
    usage_mask: u8,
    export_policy: ExportPolicy,
    material: &[u8],
) -> std::vec::Vec<u8> {
    let mut inner = std::vec::Vec::from([
        key_id,
        algorithm as u8,
        origin as u8,
        usage_mask,
        export_policy as u8,
        u8::try_from(material.len()).unwrap_or(0),
    ]);
    inner.extend_from_slice(material);
    request(0x89, 0x02, &authorized(session_id, counter, &inner))
}

pub fn install_signing_key(
    engine: &mut ProtocolEngine,
    session_id: [u8; 4],
    counter: u32,
    key_id: u8,
) {
    let response = engine.handle_bytes(&put_key_request(
        session_id,
        counter,
        key_id,
        KeyAlgorithm::Ed25519,
        KeyOrigin::Generated,
        USAGE_SIGN,
        ExportPolicy::NonExportable,
        &ED25519_SEED,
    ));
    assert_eq!(response.code, StatusCode::Success.as_u8());
}

pub fn install_wrap_key(
    engine: &mut ProtocolEngine,
    session_id: [u8; 4],
    counter: u32,
    key_id: u8,
) {
    let response = engine.handle_bytes(&put_key_request(
        session_id,
        counter,
        key_id,
        KeyAlgorithm::Aes256,
        KeyOrigin::Generated,
        USAGE_WRAP_IMPORT,
        ExportPolicy::NonExportable,
        &WRAP_KEY,
    ));
    assert_eq!(response.code, StatusCode::Success.as_u8());
}

pub fn sign_request(
    session_id: [u8; 4],
    counter: u32,
    key_id: u8,
    message: &[u8],
) -> std::vec::Vec<u8> {
    let mut inner = std::vec::Vec::from([
        key_id,
        KeyAlgorithm::Ed25519 as u8,
        u8::try_from(message.len() & 0xff).unwrap_or(0),
        u8::try_from((message.len() >> 8) & 0xff).unwrap_or(0),
    ]);
    inner.extend_from_slice(message);
    request(0x90, 0x02, &authorized(session_id, counter, &inner))
}

pub fn verify_request(
    algorithm: KeyAlgorithm,
    message: &[u8],
    public_key: &[u8],
    signature: &[u8],
) -> std::vec::Vec<u8> {
    let mut payload = std::vec::Vec::from([
        algorithm as u8,
        u8::try_from(message.len() & 0xff).unwrap_or(0),
        u8::try_from((message.len() >> 8) & 0xff).unwrap_or(0),
    ]);
    payload.extend_from_slice(message);
    payload.push(u8::try_from(public_key.len()).unwrap_or(0));
    payload.extend_from_slice(public_key);
    payload.extend_from_slice(&u16::try_from(signature.len()).unwrap_or(0).to_le_bytes());
    payload.extend_from_slice(signature);
    request(0x0b, 0x00, &payload)
}

pub fn random_request(session_id: [u8; 4], counter: u32, requested_len: u8) -> std::vec::Vec<u8> {
    request(0x91, 0x02, &authorized(session_id, counter, &[requested_len]))
}

pub fn wrapped_import_request(
    session_id: [u8; 4],
    counter: u32,
    wrapping_key_id: u8,
    target_usage_mask: u8,
    export_policy: ExportPolicy,
    plaintext: &[u8],
) -> std::vec::Vec<u8> {
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&WRAP_KEY));
    let nonce_bytes = *b"wrapnonce001";
    let mut buffer = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(
            GenericArray::from_slice(&nonce_bytes),
            b"rp_hsm.wrap.v1",
            &mut buffer,
        )
        .unwrap_or_default();

    let mut inner = std::vec::Vec::from([
        0x01,
        wrapping_key_id,
        KeyAlgorithm::Ed25519 as u8,
        target_usage_mask,
        export_policy as u8,
    ]);
    inner.extend_from_slice(&u16::try_from(buffer.len()).unwrap_or(0).to_le_bytes());
    inner.extend_from_slice(&buffer);
    inner.push(28);
    inner.extend_from_slice(&nonce_bytes);
    inner.extend_from_slice(tag.as_slice());
    request(0x92, 0x02, &authorized(session_id, counter, &inner))
}

pub fn verify_signature_with_seed(message: &[u8], signature: &[u8]) -> bool {
    let verifying_key = ed25519_public_key_from_seed(&ED25519_SEED).and_then(|bytes| {
        ed25519_dalek::VerifyingKey::from_bytes(&bytes).ok()
    });
    let signature = ed25519_dalek::Signature::from_slice(signature).ok();
    match (verifying_key, signature) {
        (Some(verifying_key), Some(signature)) => verifying_key.verify(message, &signature).is_ok(),
        _ => false,
    }
}

pub fn sign_message_with_seed(message: &[u8]) -> [u8; 64] {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&ED25519_SEED);
    signing_key.sign(message).to_bytes()
}
