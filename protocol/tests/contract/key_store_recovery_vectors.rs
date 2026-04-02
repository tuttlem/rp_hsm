use rp_hsm::protocol::{StatusCode, decode_frame, encode_frame};

use crate::key_store_fixtures::{USAGE_SIGN, key_store_status_request, operational_engine, put_key_request};

#[test]
fn full_store_status_vector_is_reported() {
    let mut engine = operational_engine();
    for key_id in 1..=8 {
        let response = engine.handle_bytes(&put_key_request(
            key_id,
            rp_hsm::protocol::KeyAlgorithm::Ed25519,
            rp_hsm::protocol::KeyOrigin::Generated,
            USAGE_SIGN,
            rp_hsm::protocol::ExportPolicy::NonExportable,
            b"seed-material",
        ));
        assert_eq!(response.code, StatusCode::Success.as_u8());
    }
    let response = engine.handle_bytes(&key_store_status_request());
    let maybe_encoded = encode_frame(&response);
    assert!(maybe_encoded.is_some());
    let decoded = decode_frame(&maybe_encoded.unwrap_or_default());
    assert!(decoded.is_ok());
    let decoded = decoded.unwrap_or_default();
    assert_eq!(decoded.payload.as_slice(), &[0x05, 0x08, 0x00, 0x00, 0x00]);
}
