use rp_hsm::protocol::StatusCode;

use super::crypto_fixtures::{begin_auth, complete_auth, install_wrap_key, request, unauthenticated_operational_engine, wrapped_import_request};

#[test]
fn excluded_high_risk_commands_fail_closed() {
    let mut engine = unauthenticated_operational_engine();
    let challenge = begin_auth(&mut engine, 0x06);
    let session = complete_auth(&mut engine, challenge, 1, b"KEYMG");
    let payload = super::crypto_fixtures::authorized(session, 2, &[]);

    for code in [0x93, 0x96] {
        let response = engine.handle_bytes(&request(code, 0x02, &payload));
        assert_ne!(response.code, StatusCode::Success.as_u8());
    }
}

#[test]
fn failed_wrapped_import_does_not_create_partial_key_state() {
    let mut engine = unauthenticated_operational_engine();
    let challenge = begin_auth(&mut engine, 0x06);
    let session = complete_auth(&mut engine, challenge, 1, b"KEYMG");
    install_wrap_key(&mut engine, session, 2, 0x07);

    let mut request_bytes = wrapped_import_request(
        session,
        3,
        0x07,
        rp_hsm::protocol::USAGE_SIGN,
        rp_hsm::protocol::ExportPolicy::NonExportable,
        &super::crypto_fixtures::ED25519_SEED,
    );
    let len = request_bytes.len();
    request_bytes[len - 1] ^= 0x55;
    let failed = engine.handle_bytes(&request_bytes);
    assert_eq!(failed.code, StatusCode::AuthorizationError.as_u8());

    let list = engine.handle_bytes(&request(
        0x8a,
        0x00,
        &super::crypto_fixtures::authorized(session, 4, &[]),
    ));
    assert_eq!(list.code, StatusCode::Success.as_u8());
    assert_eq!(list.payload.as_slice(), &[0x01, 0x07, 0x03, 0x02, rp_hsm::protocol::USAGE_WRAP_IMPORT, 0x01]);
}
