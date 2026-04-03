use rp_hsm::protocol::{StatusCode, decode_frame, encode_frame};

use crate::lifecycle_fixtures::{operational_engine, unlock_request};

#[test]
fn lock_and_unlock_return_expected_state_vectors() {
    let mut engine = operational_engine();
    let lock = engine.handle_bytes(&crate::lifecycle_fixtures::encode_request(0x82, 0x02, &[0x44]));
    let maybe_lock = encode_frame(&lock);
    assert!(maybe_lock.is_some());
    let lock_frame = decode_frame(&maybe_lock.unwrap_or_default());
    assert!(lock_frame.is_ok());
    let lock_frame = lock_frame.unwrap_or_default();
    assert_eq!(lock_frame.code, StatusCode::Success.as_u8());
    assert_eq!(lock_frame.payload.as_slice(), &[0x04, 0x44]);

    let unlock = engine.handle_bytes(&unlock_request());
    let maybe_unlock = encode_frame(&unlock);
    assert!(maybe_unlock.is_some());
    let unlock_frame = decode_frame(&maybe_unlock.unwrap_or_default());
    assert!(unlock_frame.is_ok());
    let unlock_frame = unlock_frame.unwrap_or_default();
    assert_eq!(unlock_frame.code, StatusCode::Success.as_u8());
    assert_eq!(unlock_frame.payload.as_slice()[0], 0x03);
}
