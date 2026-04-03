use rp_hsm::protocol::{ExportPolicy, KeyAlgorithm, KeyOrigin, StatusCode};

use super::key_store_fixtures::{USAGE_EXPORT, USAGE_SIGN, destroy_key_request, operational_engine, put_key_request, revoke_key_request};

#[test]
fn revoked_and_destroyed_keys_cannot_be_used_or_exported() {
    let mut engine = operational_engine();
    let _ = engine.handle_bytes(&put_key_request(
        0x03,
        KeyAlgorithm::Ed25519,
        KeyOrigin::Generated,
        USAGE_SIGN,
        ExportPolicy::NonExportable,
        b"seed-material",
    ));

    assert!(engine
        .key_store()
        .assert_key_operation(0x03, USAGE_SIGN, false)
        .is_ok());
    assert_eq!(
        engine
            .key_store()
            .assert_key_operation(0x03, USAGE_EXPORT, true)
            .err(),
        Some(StatusCode::AuthorizationError)
    );

    let _ = engine.handle_bytes(&revoke_key_request(0x03));
    assert_eq!(
        engine
            .key_store()
            .assert_key_operation(0x03, USAGE_SIGN, false)
            .err(),
        Some(StatusCode::StateError)
    );

    let _ = engine.handle_bytes(&destroy_key_request(0x03));
    assert_eq!(
        engine
            .key_store()
            .assert_key_operation(0x03, USAGE_SIGN, false)
            .err(),
        Some(StatusCode::StateError)
    );
}
