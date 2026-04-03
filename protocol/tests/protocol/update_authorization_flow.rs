use rp_hsm::protocol::{StatusCode, decode_frame};

use super::update_fixtures::{begin_update, complete_auth, manifest_payload, provisioned_admin_engine, request};

#[test]
fn unauthorized_update_begin_is_denied_and_signed_manifest_is_accepted() {
    let (mut engine, admin_session) = provisioned_admin_engine();
    let image = b"firmware-image-v2";

    let unauth = engine.handle_bytes(&request(0x99, 0x02, &manifest_payload((1, 0, 1, 0), image, 0x02)));
    assert_eq!(unauth.code, StatusCode::AuthorizationError.as_u8());

    let begin = begin_update(&mut engine, admin_session, 2, (1, 0, 1, 0), image);
    assert_eq!(begin.code, StatusCode::Success.as_u8());
    let decoded = decode_frame(&rp_hsm::protocol::encode_frame(&begin).unwrap_or_default()).unwrap_or_default();
    assert_eq!(decoded.payload[0], 0x02);

    let challenge = super::update_fixtures::begin_auth(&mut engine, 0x06);
    let recovery_session = complete_auth(&mut engine, challenge, 3, b"KEYMG");
    let wrong_role = engine.handle_bytes(&request(
        0x99,
        0x02,
        &super::update_fixtures::authorized(recovery_session, 4, &manifest_payload((1, 0, 2, 0), image, 0x02)),
    ));
    assert_eq!(wrong_role.code, StatusCode::AuthorizationError.as_u8());
}
