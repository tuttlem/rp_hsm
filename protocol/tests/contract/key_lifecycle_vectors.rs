use rp_hsm::protocol::{StatusCode, decode_frame, encode_frame};

use crate::key_store_fixtures::{
    USAGE_SIGN, destroy_key_request, operational_engine, put_key_request, revoke_key_request,
};

#[test]
fn revoke_vector_returns_revoked_state() {
    let mut engine = operational_engine();
    let _ = engine.handle_bytes(&put_key_request(
        0x02,
        rp_hsm::protocol::KeyAlgorithm::P256,
        rp_hsm::protocol::KeyOrigin::Imported,
        USAGE_SIGN,
        rp_hsm::protocol::ExportPolicy::WrappedOnly,
        b"wrapped-p256",
    ));
    let response = engine.handle_bytes(&revoke_key_request(0x02));
    let maybe_encoded = encode_frame(&response);
    assert!(maybe_encoded.is_some());
    let decoded = decode_frame(&maybe_encoded.unwrap_or_default());
    assert!(decoded.is_ok());
    let decoded = decoded.unwrap_or_default();
    assert_eq!(decoded.code, StatusCode::Success.as_u8());
    assert_eq!(decoded.payload.as_slice(), &[0x02, 0x03, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00]);
}

#[test]
fn destroy_vector_returns_completion_flags() {
    let mut engine = operational_engine();
    let _ = engine.handle_bytes(&put_key_request(
        0x03,
        rp_hsm::protocol::KeyAlgorithm::Aes256,
        rp_hsm::protocol::KeyOrigin::Generated,
        USAGE_SIGN,
        rp_hsm::protocol::ExportPolicy::NonExportable,
        b"aes-material",
    ));
    let response = engine.handle_bytes(&destroy_key_request(0x03));
    let maybe_encoded = encode_frame(&response);
    assert!(maybe_encoded.is_some());
    let decoded = decode_frame(&maybe_encoded.unwrap_or_default());
    assert!(decoded.is_ok());
    let decoded = decoded.unwrap_or_default();
    assert_eq!(decoded.code, StatusCode::Success.as_u8());
    assert_eq!(decoded.payload.as_slice(), &[0x03, 0x05, 0x01, 0x01]);
}
