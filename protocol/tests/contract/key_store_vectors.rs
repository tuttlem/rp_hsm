use rp_hsm::protocol::{StatusCode, decode_frame, encode_frame};

use crate::key_store_fixtures::{
    USAGE_SIGN, key_store_status_request, list_keys_request, metadata_request, operational_engine,
    put_key_request,
};

#[test]
fn empty_store_status_vector_is_bounded() {
    let mut engine = operational_engine();
    let response = engine.handle_bytes(&key_store_status_request());
    let maybe_encoded = encode_frame(&response);
    assert!(maybe_encoded.is_some());
    let decoded = decode_frame(&maybe_encoded.unwrap_or_default());
    assert!(decoded.is_ok());
    let decoded = decoded.unwrap_or_default();
    assert_eq!(decoded.code, StatusCode::Success.as_u8());
    assert_eq!(decoded.payload.as_slice(), &[0x01, 0x00, 0x08, 0x00, 0x00]);
}

#[test]
fn put_and_metadata_vectors_return_non_secret_fields() {
    let mut engine = operational_engine();
    let put = engine.handle_bytes(&put_key_request(
        0x01,
        rp_hsm::protocol::KeyAlgorithm::Ed25519,
        rp_hsm::protocol::KeyOrigin::Generated,
        USAGE_SIGN,
        rp_hsm::protocol::ExportPolicy::NonExportable,
        b"seed-material",
    ));
    assert_eq!(put.code, StatusCode::Success.as_u8());
    assert_eq!(put.payload.as_slice(), &[0x01, 0x02, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]);

    let metadata = engine.handle_bytes(&metadata_request(0x01));
    let maybe_encoded = encode_frame(&metadata);
    assert!(maybe_encoded.is_some());
    let decoded = decode_frame(&maybe_encoded.unwrap_or_default());
    assert!(decoded.is_ok());
    let decoded = decoded.unwrap_or_default();
    assert_eq!(decoded.code, StatusCode::Success.as_u8());
    assert_eq!(
        decoded.payload.as_slice(),
        &[0x01, 0x01, 0x01, USAGE_SIGN, 0x01, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00]
    );
}

#[test]
fn list_keys_vector_reports_bounded_entries() {
    let mut engine = operational_engine();
    let _ = engine.handle_bytes(&put_key_request(
        0x01,
        rp_hsm::protocol::KeyAlgorithm::Ed25519,
        rp_hsm::protocol::KeyOrigin::Generated,
        USAGE_SIGN,
        rp_hsm::protocol::ExportPolicy::NonExportable,
        b"seed-material",
    ));
    let response = engine.handle_bytes(&list_keys_request());
    let maybe_encoded = encode_frame(&response);
    assert!(maybe_encoded.is_some());
    let decoded = decode_frame(&maybe_encoded.unwrap_or_default());
    assert!(decoded.is_ok());
    let decoded = decoded.unwrap_or_default();
    assert_eq!(decoded.code, StatusCode::Success.as_u8());
    assert_eq!(decoded.payload.as_slice(), &[0x01, 0x01, 0x01, 0x02, USAGE_SIGN, 0x01]);
}
