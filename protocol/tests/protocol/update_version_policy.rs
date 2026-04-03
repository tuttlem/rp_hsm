use rp_hsm::protocol::StatusCode;

use super::update_fixtures::{begin_update, provisioned_admin_engine};

#[test]
fn equal_and_lower_versions_are_denied_while_higher_version_is_allowed() {
    let (mut engine, session) = provisioned_admin_engine();
    let image = b"firmware-image-v2";

    let equal = begin_update(&mut engine, session, 2, (1, 0, 0, 0), image);
    assert_eq!(equal.code, StatusCode::AuthorizationError.as_u8());

    let lower_epoch = begin_update(&mut engine, session, 3, (0, 9, 9, 9), image);
    assert_eq!(lower_epoch.code, StatusCode::AuthorizationError.as_u8());

    let higher = begin_update(&mut engine, session, 4, (1, 0, 1, 0), image);
    assert_eq!(higher.code, StatusCode::Success.as_u8());
}
