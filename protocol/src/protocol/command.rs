use super::state::{AuthorityRole, DeviceState, SessionState};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandFamily {
    Discovery,
    Status,
    Lifecycle,
    KeyStore,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CommandId {
    GetProtocolVersion = 0x01,
    GetDeviceStatus = 0x02,
    GetCommandCatalog = 0x03,
    GetLifecycleStatus = 0x04,
    GetKeyStoreStatus = 0x05,
    BeginProvisioning = 0x80,
    FinalizeProvisioning = 0x81,
    LockDevice = 0x82,
    UnlockDevice = 0x83,
    EnterRecovery = 0x84,
    RecoverToProvisioned = 0x85,
    ReactivateRecoveredProvisioning = 0x86,
    ExecuteZeroize = 0x87,
    DeveloperResetLifecycle = 0x88,
    PutPersistentKey = 0x89,
    ListPersistentKeys = 0x8a,
    GetKeyMetadata = 0x8b,
    RevokePersistentKey = 0x8c,
    DestroyPersistentKey = 0x8d,
    DeveloperStoreFault = 0x8e,
    DeveloperReboot = 0x8f,
}

impl CommandId {
    #[must_use]
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::GetProtocolVersion),
            0x02 => Some(Self::GetDeviceStatus),
            0x03 => Some(Self::GetCommandCatalog),
            0x04 => Some(Self::GetLifecycleStatus),
            0x05 => Some(Self::GetKeyStoreStatus),
            0x80 => Some(Self::BeginProvisioning),
            0x81 => Some(Self::FinalizeProvisioning),
            0x82 => Some(Self::LockDevice),
            0x83 => Some(Self::UnlockDevice),
            0x84 => Some(Self::EnterRecovery),
            0x85 => Some(Self::RecoverToProvisioned),
            0x86 => Some(Self::ReactivateRecoveredProvisioning),
            0x87 => Some(Self::ExecuteZeroize),
            0x88 => Some(Self::DeveloperResetLifecycle),
            0x89 => Some(Self::PutPersistentKey),
            0x8a => Some(Self::ListPersistentKeys),
            0x8b => Some(Self::GetKeyMetadata),
            0x8c => Some(Self::RevokePersistentKey),
            0x8d => Some(Self::DestroyPersistentKey),
            0x8e => Some(Self::DeveloperStoreFault),
            0x8f => Some(Self::DeveloperReboot),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayPolicy {
    Repeatable,
    SingleUse,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdempotencyPolicy {
    Idempotent,
    NonIdempotent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommandDefinition {
    pub id: CommandId,
    pub family: CommandFamily,
    pub min_payload_len: usize,
    pub max_payload_len: usize,
    pub allowed_device_states: &'static [DeviceState],
    pub required_role: AuthorityRole,
    pub replay_policy: ReplayPolicy,
    pub idempotency_policy: IdempotencyPolicy,
    pub enabled: bool,
    pub developer_only: bool,
}

const ALL_STATES: &[DeviceState] = &[
    DeviceState::Factory,
    DeviceState::Provisioned,
    DeviceState::Operational,
    DeviceState::Locked,
    DeviceState::Recovery,
    DeviceState::Zeroized,
];
const FACTORY_OR_ZEROIZED: &[DeviceState] = &[DeviceState::Factory, DeviceState::Zeroized];
const PROVISIONED_ONLY: &[DeviceState] = &[DeviceState::Provisioned];
const OPERATIONAL_ONLY: &[DeviceState] = &[DeviceState::Operational];
const LOCKED_ONLY: &[DeviceState] = &[DeviceState::Locked];
const RECOVERY_ONLY: &[DeviceState] = &[DeviceState::Recovery];
const KEY_QUERY_STATES: &[DeviceState] = &[
    DeviceState::Operational,
    DeviceState::Locked,
    DeviceState::Recovery,
];
const ZEROIZE_ALLOWED: &[DeviceState] = &[
    DeviceState::Provisioned,
    DeviceState::Operational,
    DeviceState::Recovery,
];
const CATALOG_STATES: &[DeviceState] = ALL_STATES;

pub const GET_PROTOCOL_VERSION: CommandDefinition = CommandDefinition {
    id: CommandId::GetProtocolVersion,
    family: CommandFamily::Discovery,
    min_payload_len: 0,
    max_payload_len: 0,
    allowed_device_states: CATALOG_STATES,
    required_role: AuthorityRole::Public,
    replay_policy: ReplayPolicy::Repeatable,
    idempotency_policy: IdempotencyPolicy::Idempotent,
    enabled: true,
    developer_only: false,
};

pub const GET_DEVICE_STATUS: CommandDefinition = CommandDefinition {
    id: CommandId::GetDeviceStatus,
    family: CommandFamily::Status,
    min_payload_len: 1,
    max_payload_len: 1,
    allowed_device_states: CATALOG_STATES,
    required_role: AuthorityRole::Public,
    replay_policy: ReplayPolicy::Repeatable,
    idempotency_policy: IdempotencyPolicy::Idempotent,
    enabled: true,
    developer_only: false,
};

pub const GET_COMMAND_CATALOG: CommandDefinition = CommandDefinition {
    id: CommandId::GetCommandCatalog,
    family: CommandFamily::Discovery,
    min_payload_len: 1,
    max_payload_len: 1,
    allowed_device_states: CATALOG_STATES,
    required_role: AuthorityRole::Public,
    replay_policy: ReplayPolicy::Repeatable,
    idempotency_policy: IdempotencyPolicy::Idempotent,
    enabled: true,
    developer_only: false,
};

pub const GET_LIFECYCLE_STATUS: CommandDefinition = CommandDefinition {
    id: CommandId::GetLifecycleStatus,
    family: CommandFamily::Status,
    min_payload_len: 0,
    max_payload_len: 0,
    allowed_device_states: CATALOG_STATES,
    required_role: AuthorityRole::Public,
    replay_policy: ReplayPolicy::Repeatable,
    idempotency_policy: IdempotencyPolicy::Idempotent,
    enabled: true,
    developer_only: false,
};

pub const GET_KEY_STORE_STATUS: CommandDefinition = CommandDefinition {
    id: CommandId::GetKeyStoreStatus,
    family: CommandFamily::Status,
    min_payload_len: 0,
    max_payload_len: 0,
    allowed_device_states: CATALOG_STATES,
    required_role: AuthorityRole::Public,
    replay_policy: ReplayPolicy::Repeatable,
    idempotency_policy: IdempotencyPolicy::Idempotent,
    enabled: true,
    developer_only: false,
};

pub const BEGIN_PROVISIONING: CommandDefinition = CommandDefinition {
    id: CommandId::BeginProvisioning,
    family: CommandFamily::Lifecycle,
    min_payload_len: 1,
    max_payload_len: 16,
    allowed_device_states: FACTORY_OR_ZEROIZED,
    required_role: AuthorityRole::Bootstrap,
    replay_policy: ReplayPolicy::SingleUse,
    idempotency_policy: IdempotencyPolicy::NonIdempotent,
    enabled: true,
    developer_only: false,
};

pub const FINALIZE_PROVISIONING: CommandDefinition = CommandDefinition {
    id: CommandId::FinalizeProvisioning,
    family: CommandFamily::Lifecycle,
    min_payload_len: 5,
    max_payload_len: 5,
    allowed_device_states: PROVISIONED_ONLY,
    required_role: AuthorityRole::Bootstrap,
    replay_policy: ReplayPolicy::SingleUse,
    idempotency_policy: IdempotencyPolicy::NonIdempotent,
    enabled: true,
    developer_only: false,
};

pub const LOCK_DEVICE: CommandDefinition = CommandDefinition {
    id: CommandId::LockDevice,
    family: CommandFamily::Lifecycle,
    min_payload_len: 1,
    max_payload_len: 1,
    allowed_device_states: OPERATIONAL_ONLY,
    required_role: AuthorityRole::Administrator,
    replay_policy: ReplayPolicy::SingleUse,
    idempotency_policy: IdempotencyPolicy::NonIdempotent,
    enabled: true,
    developer_only: false,
};

pub const UNLOCK_DEVICE: CommandDefinition = CommandDefinition {
    id: CommandId::UnlockDevice,
    family: CommandFamily::Lifecycle,
    min_payload_len: 1,
    max_payload_len: 1,
    allowed_device_states: LOCKED_ONLY,
    required_role: AuthorityRole::Administrator,
    replay_policy: ReplayPolicy::SingleUse,
    idempotency_policy: IdempotencyPolicy::NonIdempotent,
    enabled: true,
    developer_only: false,
};

pub const ENTER_RECOVERY: CommandDefinition = CommandDefinition {
    id: CommandId::EnterRecovery,
    family: CommandFamily::Lifecycle,
    min_payload_len: 1,
    max_payload_len: 1,
    allowed_device_states: LOCKED_ONLY,
    required_role: AuthorityRole::Recovery,
    replay_policy: ReplayPolicy::SingleUse,
    idempotency_policy: IdempotencyPolicy::NonIdempotent,
    enabled: true,
    developer_only: false,
};

pub const RECOVER_TO_PROVISIONED: CommandDefinition = CommandDefinition {
    id: CommandId::RecoverToProvisioned,
    family: CommandFamily::Lifecycle,
    min_payload_len: 1,
    max_payload_len: 1,
    allowed_device_states: RECOVERY_ONLY,
    required_role: AuthorityRole::Recovery,
    replay_policy: ReplayPolicy::SingleUse,
    idempotency_policy: IdempotencyPolicy::NonIdempotent,
    enabled: true,
    developer_only: false,
};

pub const REACTIVATE_RECOVERED_PROVISIONING: CommandDefinition = CommandDefinition {
    id: CommandId::ReactivateRecoveredProvisioning,
    family: CommandFamily::Lifecycle,
    min_payload_len: 5,
    max_payload_len: 5,
    allowed_device_states: PROVISIONED_ONLY,
    required_role: AuthorityRole::Recovery,
    replay_policy: ReplayPolicy::SingleUse,
    idempotency_policy: IdempotencyPolicy::NonIdempotent,
    enabled: true,
    developer_only: false,
};

pub const EXECUTE_ZEROIZE: CommandDefinition = CommandDefinition {
    id: CommandId::ExecuteZeroize,
    family: CommandFamily::Lifecycle,
    min_payload_len: 2,
    max_payload_len: 2,
    allowed_device_states: ZEROIZE_ALLOWED,
    required_role: AuthorityRole::Administrator,
    replay_policy: ReplayPolicy::SingleUse,
    idempotency_policy: IdempotencyPolicy::NonIdempotent,
    enabled: true,
    developer_only: false,
};

pub const DEVELOPER_RESET_LIFECYCLE: CommandDefinition = CommandDefinition {
    id: CommandId::DeveloperResetLifecycle,
    family: CommandFamily::Lifecycle,
    min_payload_len: 3,
    max_payload_len: 3,
    allowed_device_states: CATALOG_STATES,
    required_role: AuthorityRole::Developer,
    replay_policy: ReplayPolicy::SingleUse,
    idempotency_policy: IdempotencyPolicy::NonIdempotent,
    enabled: true,
    developer_only: true,
};

pub const PUT_PERSISTENT_KEY: CommandDefinition = CommandDefinition {
    id: CommandId::PutPersistentKey,
    family: CommandFamily::KeyStore,
    min_payload_len: 7,
    max_payload_len: 30,
    allowed_device_states: OPERATIONAL_ONLY,
    required_role: AuthorityRole::Administrator,
    replay_policy: ReplayPolicy::SingleUse,
    idempotency_policy: IdempotencyPolicy::NonIdempotent,
    enabled: true,
    developer_only: false,
};

pub const LIST_PERSISTENT_KEYS: CommandDefinition = CommandDefinition {
    id: CommandId::ListPersistentKeys,
    family: CommandFamily::KeyStore,
    min_payload_len: 0,
    max_payload_len: 0,
    allowed_device_states: KEY_QUERY_STATES,
    required_role: AuthorityRole::KeyManager,
    replay_policy: ReplayPolicy::Repeatable,
    idempotency_policy: IdempotencyPolicy::Idempotent,
    enabled: true,
    developer_only: false,
};

pub const GET_KEY_METADATA: CommandDefinition = CommandDefinition {
    id: CommandId::GetKeyMetadata,
    family: CommandFamily::KeyStore,
    min_payload_len: 1,
    max_payload_len: 1,
    allowed_device_states: KEY_QUERY_STATES,
    required_role: AuthorityRole::KeyManager,
    replay_policy: ReplayPolicy::Repeatable,
    idempotency_policy: IdempotencyPolicy::Idempotent,
    enabled: true,
    developer_only: false,
};

pub const REVOKE_PERSISTENT_KEY: CommandDefinition = CommandDefinition {
    id: CommandId::RevokePersistentKey,
    family: CommandFamily::KeyStore,
    min_payload_len: 2,
    max_payload_len: 2,
    allowed_device_states: OPERATIONAL_ONLY,
    required_role: AuthorityRole::Administrator,
    replay_policy: ReplayPolicy::SingleUse,
    idempotency_policy: IdempotencyPolicy::NonIdempotent,
    enabled: true,
    developer_only: false,
};

pub const DESTROY_PERSISTENT_KEY: CommandDefinition = CommandDefinition {
    id: CommandId::DestroyPersistentKey,
    family: CommandFamily::KeyStore,
    min_payload_len: 3,
    max_payload_len: 3,
    allowed_device_states: KEY_QUERY_STATES,
    required_role: AuthorityRole::KeyManager,
    replay_policy: ReplayPolicy::SingleUse,
    idempotency_policy: IdempotencyPolicy::NonIdempotent,
    enabled: true,
    developer_only: false,
};

pub const DEVELOPER_STORE_FAULT: CommandDefinition = CommandDefinition {
    id: CommandId::DeveloperStoreFault,
    family: CommandFamily::KeyStore,
    min_payload_len: 1,
    max_payload_len: 1,
    allowed_device_states: CATALOG_STATES,
    required_role: AuthorityRole::Developer,
    replay_policy: ReplayPolicy::SingleUse,
    idempotency_policy: IdempotencyPolicy::NonIdempotent,
    enabled: true,
    developer_only: true,
};

pub const DEVELOPER_REBOOT: CommandDefinition = CommandDefinition {
    id: CommandId::DeveloperReboot,
    family: CommandFamily::Lifecycle,
    min_payload_len: 3,
    max_payload_len: 3,
    allowed_device_states: CATALOG_STATES,
    required_role: AuthorityRole::Developer,
    replay_policy: ReplayPolicy::SingleUse,
    idempotency_policy: IdempotencyPolicy::NonIdempotent,
    enabled: true,
    developer_only: true,
};

pub const PUBLIC_COMMANDS: &[CommandDefinition] = &[
    GET_PROTOCOL_VERSION,
    GET_DEVICE_STATUS,
    GET_COMMAND_CATALOG,
    GET_LIFECYCLE_STATUS,
    GET_KEY_STORE_STATUS,
];

pub const RESTRICTED_COMMANDS: &[CommandDefinition] = &[
    BEGIN_PROVISIONING,
    FINALIZE_PROVISIONING,
    LOCK_DEVICE,
    UNLOCK_DEVICE,
    ENTER_RECOVERY,
    RECOVER_TO_PROVISIONED,
    REACTIVATE_RECOVERED_PROVISIONING,
    EXECUTE_ZEROIZE,
    PUT_PERSISTENT_KEY,
    LIST_PERSISTENT_KEYS,
    GET_KEY_METADATA,
    REVOKE_PERSISTENT_KEY,
    DESTROY_PERSISTENT_KEY,
];

pub const DEVELOPER_COMMANDS: &[CommandDefinition] = &[
    DEVELOPER_RESET_LIFECYCLE,
    DEVELOPER_STORE_FAULT,
    DEVELOPER_REBOOT,
];

pub fn lookup_command(id: u8) -> Option<CommandDefinition> {
    CommandId::from_byte(id).map(definition_for)
}

#[must_use]
pub fn definition_for(id: CommandId) -> CommandDefinition {
    match id {
        CommandId::GetProtocolVersion => GET_PROTOCOL_VERSION,
        CommandId::GetDeviceStatus => GET_DEVICE_STATUS,
        CommandId::GetCommandCatalog => GET_COMMAND_CATALOG,
        CommandId::GetLifecycleStatus => GET_LIFECYCLE_STATUS,
        CommandId::GetKeyStoreStatus => GET_KEY_STORE_STATUS,
        CommandId::BeginProvisioning => BEGIN_PROVISIONING,
        CommandId::FinalizeProvisioning => FINALIZE_PROVISIONING,
        CommandId::LockDevice => LOCK_DEVICE,
        CommandId::UnlockDevice => UNLOCK_DEVICE,
        CommandId::EnterRecovery => ENTER_RECOVERY,
        CommandId::RecoverToProvisioned => RECOVER_TO_PROVISIONED,
        CommandId::ReactivateRecoveredProvisioning => REACTIVATE_RECOVERED_PROVISIONING,
        CommandId::ExecuteZeroize => EXECUTE_ZEROIZE,
        CommandId::DeveloperResetLifecycle => DEVELOPER_RESET_LIFECYCLE,
        CommandId::PutPersistentKey => PUT_PERSISTENT_KEY,
        CommandId::ListPersistentKeys => LIST_PERSISTENT_KEYS,
        CommandId::GetKeyMetadata => GET_KEY_METADATA,
        CommandId::RevokePersistentKey => REVOKE_PERSISTENT_KEY,
        CommandId::DestroyPersistentKey => DESTROY_PERSISTENT_KEY,
        CommandId::DeveloperStoreFault => DEVELOPER_STORE_FAULT,
        CommandId::DeveloperReboot => DEVELOPER_REBOOT,
    }
}

#[must_use]
pub fn get_public_catalog() -> &'static [CommandDefinition] {
    PUBLIC_COMMANDS
}

#[must_use]
pub fn get_visible_catalog(
    session_state: SessionState,
    include_restricted: bool,
    developer_mode: bool,
) -> &'static [CommandDefinition] {
    if include_restricted
        && matches!(
            session_state,
            SessionState::Bootstrap
                | SessionState::Administrator
                | SessionState::Recovery
                | SessionState::Developer
        )
    {
        if developer_mode && session_state == SessionState::Developer {
            &[
                GET_PROTOCOL_VERSION,
                GET_DEVICE_STATUS,
                GET_COMMAND_CATALOG,
                GET_LIFECYCLE_STATUS,
                GET_KEY_STORE_STATUS,
                BEGIN_PROVISIONING,
                FINALIZE_PROVISIONING,
                LOCK_DEVICE,
                UNLOCK_DEVICE,
                ENTER_RECOVERY,
                RECOVER_TO_PROVISIONED,
                REACTIVATE_RECOVERED_PROVISIONING,
                EXECUTE_ZEROIZE,
                PUT_PERSISTENT_KEY,
                LIST_PERSISTENT_KEYS,
                GET_KEY_METADATA,
                REVOKE_PERSISTENT_KEY,
                DESTROY_PERSISTENT_KEY,
                DEVELOPER_RESET_LIFECYCLE,
                DEVELOPER_STORE_FAULT,
                DEVELOPER_REBOOT,
            ]
        } else {
            &[
                GET_PROTOCOL_VERSION,
                GET_DEVICE_STATUS,
                GET_COMMAND_CATALOG,
                GET_LIFECYCLE_STATUS,
                GET_KEY_STORE_STATUS,
                BEGIN_PROVISIONING,
                FINALIZE_PROVISIONING,
                LOCK_DEVICE,
                UNLOCK_DEVICE,
                ENTER_RECOVERY,
                RECOVER_TO_PROVISIONED,
                REACTIVATE_RECOVERED_PROVISIONING,
                EXECUTE_ZEROIZE,
                PUT_PERSISTENT_KEY,
                LIST_PERSISTENT_KEYS,
                GET_KEY_METADATA,
                REVOKE_PERSISTENT_KEY,
                DESTROY_PERSISTENT_KEY,
            ]
        }
    } else {
        PUBLIC_COMMANDS
    }
}
