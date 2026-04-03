use rp_hsm::protocol::{CommandId, lookup_command};

#[test]
fn all_security_relevant_command_ids_resolve_to_one_policy_definition() {
    for command in [
        CommandId::BeginProvisioning,
        CommandId::FinalizeProvisioning,
        CommandId::LockDevice,
        CommandId::UnlockDevice,
        CommandId::EnterRecovery,
        CommandId::RecoverToProvisioned,
        CommandId::ReactivateRecoveredProvisioning,
        CommandId::ExecuteZeroize,
        CommandId::PutPersistentKey,
        CommandId::RevokePersistentKey,
        CommandId::DestroyPersistentKey,
        CommandId::DeveloperSetPolicy,
        CommandId::SignDetached,
        CommandId::GenerateRandom,
        CommandId::ImportWrappedKey,
    ] {
        assert!(
            lookup_command(command as u8).is_some(),
            "missing policy definition for {command:?}"
        );
    }
}
