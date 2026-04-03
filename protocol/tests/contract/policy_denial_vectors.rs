use rp_hsm::protocol::{DeviceState, MessageKind, ProtocolEngine, ProtocolFrame, SessionState, StatusCode, encode_frame};

#[test]
fn state_and_role_denials_use_bounded_policy_classes() {
    let mut provisioned = ProtocolEngine::new(DeviceState::Provisioned, SessionState::KeyManager);
    let sign = provisioned.handle_bytes(
        &encode_frame(&ProtocolFrame::new(
            MessageKind::Request,
            0x90,
            0x02,
            &[0, 0, 0, 0, 1, 0, 0, 0, 0x01, 0x01, 0x01, 0x00, 0x00],
        ).unwrap_or_default()).unwrap_or_default(),
    );
    assert_eq!(sign.code, StatusCode::StateError.as_u8());
    assert_eq!(sign.payload.as_slice(), &[0x02]);

    let mut unauth = ProtocolEngine::new(DeviceState::Operational, SessionState::Unauthenticated);
    let destroy = unauth.handle_bytes(
        &encode_frame(&ProtocolFrame::new(
            MessageKind::Request,
            0x8d,
            0x02,
            &[0, 0, 0, 0, 1, 0, 0, 0, 0x01, 0xde, 0xad],
        ).unwrap_or_default()).unwrap_or_default(),
    );
    assert_eq!(destroy.code, StatusCode::AuthorizationError.as_u8());
    assert_eq!(destroy.payload.as_slice(), &[0x03]);
}
