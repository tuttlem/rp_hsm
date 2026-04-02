use rp_hsm::protocol::{ExportPolicy, StatusCode, USAGE_SIGN};

use super::crypto_fixtures::{
    begin_auth, complete_auth, install_wrap_key, request, unauthenticated_operational_engine,
    wrapped_import_request,
};

#[test]
fn wrapped_import_creates_managed_key_and_returns_metadata_only() {
    let mut engine = unauthenticated_operational_engine();
    let challenge = begin_auth(&mut engine, 0x06);
    let session = complete_auth(&mut engine, challenge, 1, b"KEYMG");
    install_wrap_key(&mut engine, session, 2, 0x07);

    let response = engine.handle_bytes(&wrapped_import_request(
        session,
        3,
        0x07,
        USAGE_SIGN,
        ExportPolicy::NonExportable,
        &super::crypto_fixtures::ED25519_SEED,
    ));
    assert_eq!(response.code, StatusCode::Success.as_u8());
    assert_eq!(response.payload.len(), 10);
    assert_eq!(response.payload[1], 0x02);
}

#[test]
fn malformed_or_forbidden_wrapped_import_is_denied() {
    let mut engine = unauthenticated_operational_engine();
    let challenge = begin_auth(&mut engine, 0x06);
    let session = complete_auth(&mut engine, challenge, 1, b"KEYMG");
    install_wrap_key(&mut engine, session, 2, 0x07);

    let malformed = engine.handle_bytes(&request(
        0x92,
        0x02,
        &super::crypto_fixtures::authorized(session, 3, &[0x01, 0x07, 0x01, USAGE_SIGN, 0x01, 0x02, 0x00, 0xaa, 0xbb, 0x01, 0xcc]),
    ));
    assert!(matches!(
        malformed.code,
        x if x == StatusCode::ValidationError.as_u8() || x == StatusCode::AuthorizationError.as_u8()
    ));

    let forbidden = engine.handle_bytes(&wrapped_import_request(
        session,
        4,
        0x07,
        USAGE_SIGN,
        ExportPolicy::WrappedOnly,
        &super::crypto_fixtures::ED25519_SEED,
    ));
    assert_eq!(forbidden.code, StatusCode::AuthorizationError.as_u8());
}
