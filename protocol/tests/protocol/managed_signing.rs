use rp_hsm::protocol::{StatusCode, revoke_marker};

use super::crypto_fixtures::{
    begin_auth, complete_auth, install_signing_key, request, sign_request, unauthenticated_operational_engine,
    verify_signature_with_seed,
};

#[test]
fn managed_signing_succeeds_for_active_ed25519_key() {
    let mut engine = unauthenticated_operational_engine();
    let challenge = begin_auth(&mut engine, 0x06);
    let session = complete_auth(&mut engine, challenge, 1, b"KEYMG");
    install_signing_key(&mut engine, session, 2, 0x01);

    let response = engine.handle_bytes(&sign_request(session, 3, 0x01, b"sign me"));
    assert_eq!(response.code, StatusCode::Success.as_u8());
    assert_eq!(response.payload.as_slice()[0..2], [64, 0]);
    assert!(verify_signature_with_seed(
        b"sign me",
        &response.payload.as_slice()[2..]
    ));
}

#[test]
fn revoked_key_cannot_be_used_for_signing() {
    let mut engine = unauthenticated_operational_engine();
    let challenge = begin_auth(&mut engine, 0x06);
    let session = complete_auth(&mut engine, challenge, 1, b"KEYMG");
    install_signing_key(&mut engine, session, 2, 0x01);

    let revoke = engine.handle_bytes(&request(
        0x8c,
        0x02,
        &super::crypto_fixtures::authorized(session, 3, &[0x01, revoke_marker()]),
    ));
    assert_eq!(revoke.code, StatusCode::Success.as_u8());

    let denied = engine.handle_bytes(&sign_request(session, 4, 0x01, b"sign me"));
    assert_eq!(denied.code, StatusCode::AuthorizationError.as_u8());
    assert_eq!(denied.payload.as_slice(), &[0x04]);
}
