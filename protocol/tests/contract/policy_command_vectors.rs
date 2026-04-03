use rp_hsm::protocol::{CommandId, ProtectedActionClass, StatusCode, lookup_command};

#[test]
fn security_relevant_commands_have_reviewable_policy_metadata() {
    let Some(destroy) = lookup_command(CommandId::DestroyPersistentKey as u8) else {
        unreachable!("missing destroy command definition");
    };
    assert!(destroy.requires_key_context);
    assert_eq!(destroy.protected_action_class, ProtectedActionClass::DestructiveKey);

    let Some(zeroize) = lookup_command(CommandId::ExecuteZeroize as u8) else {
        unreachable!("missing zeroize command definition");
    };
    assert!(!zeroize.requires_key_context);
    assert_eq!(zeroize.protected_action_class, ProtectedActionClass::DestructiveAdmin);

    let Some(policy) = lookup_command(CommandId::DeveloperSetPolicy as u8) else {
        unreachable!("missing developer policy command definition");
    };
    assert!(!policy.requires_key_context);
    assert_eq!(policy.protected_action_class, ProtectedActionClass::None);
}

#[test]
fn bounded_role_denial_payload_fits_one_byte_class() {
    assert_eq!(StatusCode::AuthorizationError.as_u8(), 0x06);
}
