use rp_hsm::protocol::StatusCode;

use super::key_store_fixtures::{USAGE_SIGN, key_store_status_request, operational_engine, put_key_request};

#[test]
fn full_store_rejects_new_keys_without_eviction() {
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

    let full = engine.handle_bytes(&key_store_status_request());
    assert_eq!(full.payload.as_slice(), &[0x05, 0x08, 0x00, 0x00, 0x00]);

    let denied = engine.handle_bytes(&put_key_request(
        0x09,
        rp_hsm::protocol::KeyAlgorithm::Ed25519,
        rp_hsm::protocol::KeyOrigin::Generated,
        USAGE_SIGN,
        rp_hsm::protocol::ExportPolicy::NonExportable,
        b"seed-material",
    ));
    assert_eq!(denied.code, StatusCode::StateError.as_u8());
}
