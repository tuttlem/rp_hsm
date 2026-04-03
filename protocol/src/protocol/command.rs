use super::state::{AuthorityRole, DeviceState, SessionState};

pub const AUTH_HEADER_LEN: usize = 8;
pub const MAX_AUTH_PROOF_LEN: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandFamily {
    Discovery,
    Status,
    Authentication,
    Lifecycle,
    KeyStore,
    Crypto,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CommandId {
    GetProtocolVersion = 0x01,
    GetDeviceStatus = 0x02,
    GetCommandCatalog = 0x03,
    GetLifecycleStatus = 0x04,
    GetKeyStoreStatus = 0x05,
    BeginAuthentication = 0x06,
    CompleteAuthentication = 0x07,
    GetSessionStatus = 0x08,
    InvalidateSession = 0x09,
    GetCryptoCapabilities = 0x0a,
    VerifyDetached = 0x0b,
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
    SignDetached = 0x90,
    GenerateRandom = 0x91,
    ImportWrappedKey = 0x92,
    ExportWrappedKey = 0x93,
    Encrypt = 0x94,
    Decrypt = 0x95,
    DeriveSharedSecret = 0x96,
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
            0x06 => Some(Self::BeginAuthentication),
            0x07 => Some(Self::CompleteAuthentication),
            0x08 => Some(Self::GetSessionStatus),
            0x09 => Some(Self::InvalidateSession),
            0x0a => Some(Self::GetCryptoCapabilities),
            0x0b => Some(Self::VerifyDetached),
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
            0x90 => Some(Self::SignDetached),
            0x91 => Some(Self::GenerateRandom),
            0x92 => Some(Self::ImportWrappedKey),
            0x93 => Some(Self::ExportWrappedKey),
            0x94 => Some(Self::Encrypt),
            0x95 => Some(Self::Decrypt),
            0x96 => Some(Self::DeriveSharedSecret),
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

pub const BEGIN_AUTHENTICATION: CommandDefinition = CommandDefinition {
    id: CommandId::BeginAuthentication,
    family: CommandFamily::Authentication,
    min_payload_len: 1,
    max_payload_len: 1,
    allowed_device_states: CATALOG_STATES,
    required_role: AuthorityRole::Public,
    replay_policy: ReplayPolicy::Repeatable,
    idempotency_policy: IdempotencyPolicy::NonIdempotent,
    enabled: true,
    developer_only: false,
};

pub const COMPLETE_AUTHENTICATION: CommandDefinition = CommandDefinition {
    id: CommandId::CompleteAuthentication,
    family: CommandFamily::Authentication,
    min_payload_len: 9,
    max_payload_len: 9 + MAX_AUTH_PROOF_LEN,
    allowed_device_states: CATALOG_STATES,
    required_role: AuthorityRole::Public,
    replay_policy: ReplayPolicy::SingleUse,
    idempotency_policy: IdempotencyPolicy::NonIdempotent,
    enabled: true,
    developer_only: false,
};

pub const GET_SESSION_STATUS: CommandDefinition = CommandDefinition {
    id: CommandId::GetSessionStatus,
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

pub const INVALIDATE_SESSION: CommandDefinition = CommandDefinition {
    id: CommandId::InvalidateSession,
    family: CommandFamily::Authentication,
    min_payload_len: AUTH_HEADER_LEN,
    max_payload_len: AUTH_HEADER_LEN,
    allowed_device_states: CATALOG_STATES,
    required_role: AuthorityRole::Public,
    replay_policy: ReplayPolicy::SingleUse,
    idempotency_policy: IdempotencyPolicy::NonIdempotent,
    enabled: true,
    developer_only: false,
};

pub const GET_CRYPTO_CAPABILITIES: CommandDefinition = CommandDefinition {
    id: CommandId::GetCryptoCapabilities,
    family: CommandFamily::Crypto,
    min_payload_len: 0,
    max_payload_len: 0,
    allowed_device_states: CATALOG_STATES,
    required_role: AuthorityRole::Public,
    replay_policy: ReplayPolicy::Repeatable,
    idempotency_policy: IdempotencyPolicy::Idempotent,
    enabled: true,
    developer_only: false,
};

pub const VERIFY_DETACHED: CommandDefinition = CommandDefinition {
    id: CommandId::VerifyDetached,
    family: CommandFamily::Crypto,
    min_payload_len: 1 + 2 + 1 + 1 + 2 + 1,
    max_payload_len: 231,
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
    min_payload_len: AUTH_HEADER_LEN + 1,
    max_payload_len: AUTH_HEADER_LEN + 16,
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
    min_payload_len: AUTH_HEADER_LEN + 5,
    max_payload_len: AUTH_HEADER_LEN + 5,
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
    min_payload_len: AUTH_HEADER_LEN + 1,
    max_payload_len: AUTH_HEADER_LEN + 1,
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
    min_payload_len: AUTH_HEADER_LEN + 1,
    max_payload_len: AUTH_HEADER_LEN + 1,
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
    min_payload_len: AUTH_HEADER_LEN + 1,
    max_payload_len: AUTH_HEADER_LEN + 1,
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
    min_payload_len: AUTH_HEADER_LEN + 1,
    max_payload_len: AUTH_HEADER_LEN + 1,
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
    min_payload_len: AUTH_HEADER_LEN + 5,
    max_payload_len: AUTH_HEADER_LEN + 5,
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
    min_payload_len: AUTH_HEADER_LEN + 2,
    max_payload_len: AUTH_HEADER_LEN + 2,
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
    min_payload_len: AUTH_HEADER_LEN + 7,
    max_payload_len: AUTH_HEADER_LEN + 38,
    allowed_device_states: OPERATIONAL_ONLY,
    required_role: AuthorityRole::KeyManager,
    replay_policy: ReplayPolicy::SingleUse,
    idempotency_policy: IdempotencyPolicy::NonIdempotent,
    enabled: true,
    developer_only: false,
};

pub const LIST_PERSISTENT_KEYS: CommandDefinition = CommandDefinition {
    id: CommandId::ListPersistentKeys,
    family: CommandFamily::KeyStore,
    min_payload_len: AUTH_HEADER_LEN,
    max_payload_len: AUTH_HEADER_LEN,
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
    min_payload_len: AUTH_HEADER_LEN + 1,
    max_payload_len: AUTH_HEADER_LEN + 1,
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
    min_payload_len: AUTH_HEADER_LEN + 2,
    max_payload_len: AUTH_HEADER_LEN + 2,
    allowed_device_states: OPERATIONAL_ONLY,
    required_role: AuthorityRole::KeyManager,
    replay_policy: ReplayPolicy::SingleUse,
    idempotency_policy: IdempotencyPolicy::NonIdempotent,
    enabled: true,
    developer_only: false,
};

pub const DESTROY_PERSISTENT_KEY: CommandDefinition = CommandDefinition {
    id: CommandId::DestroyPersistentKey,
    family: CommandFamily::KeyStore,
    min_payload_len: AUTH_HEADER_LEN + 3,
    max_payload_len: AUTH_HEADER_LEN + 3,
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

pub const SIGN_DETACHED: CommandDefinition = CommandDefinition {
    id: CommandId::SignDetached,
    family: CommandFamily::Crypto,
    min_payload_len: AUTH_HEADER_LEN + 1 + 1 + 2 + 1,
    max_payload_len: AUTH_HEADER_LEN + 1 + 1 + 2 + 128,
    allowed_device_states: OPERATIONAL_ONLY,
    required_role: AuthorityRole::KeyManager,
    replay_policy: ReplayPolicy::SingleUse,
    idempotency_policy: IdempotencyPolicy::NonIdempotent,
    enabled: true,
    developer_only: false,
};

pub const GENERATE_RANDOM: CommandDefinition = CommandDefinition {
    id: CommandId::GenerateRandom,
    family: CommandFamily::Crypto,
    min_payload_len: AUTH_HEADER_LEN + 1,
    max_payload_len: AUTH_HEADER_LEN + 1,
    allowed_device_states: OPERATIONAL_ONLY,
    required_role: AuthorityRole::Public,
    replay_policy: ReplayPolicy::SingleUse,
    idempotency_policy: IdempotencyPolicy::NonIdempotent,
    enabled: true,
    developer_only: false,
};

pub const IMPORT_WRAPPED_KEY: CommandDefinition = CommandDefinition {
    id: CommandId::ImportWrappedKey,
    family: CommandFamily::Crypto,
    min_payload_len: AUTH_HEADER_LEN + 1 + 1 + 1 + 1 + 1 + 2 + 1 + 1,
    max_payload_len: AUTH_HEADER_LEN + 73,
    allowed_device_states: OPERATIONAL_ONLY,
    required_role: AuthorityRole::KeyManager,
    replay_policy: ReplayPolicy::SingleUse,
    idempotency_policy: IdempotencyPolicy::NonIdempotent,
    enabled: true,
    developer_only: false,
};

pub const EXPORT_WRAPPED_KEY: CommandDefinition = CommandDefinition {
    id: CommandId::ExportWrappedKey,
    family: CommandFamily::Crypto,
    min_payload_len: AUTH_HEADER_LEN,
    max_payload_len: AUTH_HEADER_LEN,
    allowed_device_states: OPERATIONAL_ONLY,
    required_role: AuthorityRole::KeyManager,
    replay_policy: ReplayPolicy::SingleUse,
    idempotency_policy: IdempotencyPolicy::NonIdempotent,
    enabled: false,
    developer_only: false,
};

pub const ENCRYPT: CommandDefinition = CommandDefinition {
    id: CommandId::Encrypt,
    family: CommandFamily::Crypto,
    min_payload_len: AUTH_HEADER_LEN,
    max_payload_len: AUTH_HEADER_LEN,
    allowed_device_states: OPERATIONAL_ONLY,
    required_role: AuthorityRole::KeyManager,
    replay_policy: ReplayPolicy::SingleUse,
    idempotency_policy: IdempotencyPolicy::NonIdempotent,
    enabled: false,
    developer_only: false,
};

pub const DECRYPT: CommandDefinition = CommandDefinition {
    id: CommandId::Decrypt,
    family: CommandFamily::Crypto,
    min_payload_len: AUTH_HEADER_LEN,
    max_payload_len: AUTH_HEADER_LEN,
    allowed_device_states: OPERATIONAL_ONLY,
    required_role: AuthorityRole::KeyManager,
    replay_policy: ReplayPolicy::SingleUse,
    idempotency_policy: IdempotencyPolicy::NonIdempotent,
    enabled: false,
    developer_only: false,
};

pub const DERIVE_SHARED_SECRET: CommandDefinition = CommandDefinition {
    id: CommandId::DeriveSharedSecret,
    family: CommandFamily::Crypto,
    min_payload_len: AUTH_HEADER_LEN,
    max_payload_len: AUTH_HEADER_LEN,
    allowed_device_states: OPERATIONAL_ONLY,
    required_role: AuthorityRole::KeyManager,
    replay_policy: ReplayPolicy::SingleUse,
    idempotency_policy: IdempotencyPolicy::NonIdempotent,
    enabled: false,
    developer_only: false,
};

pub const PUBLIC_COMMANDS: &[CommandDefinition] = &[
    GET_PROTOCOL_VERSION,
    GET_DEVICE_STATUS,
    GET_COMMAND_CATALOG,
    GET_LIFECYCLE_STATUS,
    GET_KEY_STORE_STATUS,
    BEGIN_AUTHENTICATION,
    COMPLETE_AUTHENTICATION,
    GET_SESSION_STATUS,
    GET_CRYPTO_CAPABILITIES,
    VERIFY_DETACHED,
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
        CommandId::BeginAuthentication => BEGIN_AUTHENTICATION,
        CommandId::CompleteAuthentication => COMPLETE_AUTHENTICATION,
        CommandId::GetSessionStatus => GET_SESSION_STATUS,
        CommandId::InvalidateSession => INVALIDATE_SESSION,
        CommandId::GetCryptoCapabilities => GET_CRYPTO_CAPABILITIES,
        CommandId::VerifyDetached => VERIFY_DETACHED,
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
        CommandId::SignDetached => SIGN_DETACHED,
        CommandId::GenerateRandom => GENERATE_RANDOM,
        CommandId::ImportWrappedKey => IMPORT_WRAPPED_KEY,
        CommandId::ExportWrappedKey => EXPORT_WRAPPED_KEY,
        CommandId::Encrypt => ENCRYPT,
        CommandId::Decrypt => DECRYPT,
        CommandId::DeriveSharedSecret => DERIVE_SHARED_SECRET,
    }
}

#[must_use]
pub fn get_public_catalog() -> &'static [CommandDefinition] {
    PUBLIC_COMMANDS
}

fn public_and(extra: &'static [CommandDefinition]) -> &'static [CommandDefinition] {
    extra
}

#[must_use]
pub fn get_visible_catalog(
    session_state: SessionState,
    include_restricted: bool,
    developer_mode: bool,
) -> &'static [CommandDefinition] {
    if !include_restricted {
        return PUBLIC_COMMANDS;
    }

    match session_state {
        SessionState::Unauthenticated => PUBLIC_COMMANDS,
        SessionState::Bootstrap => public_and(&[
            GET_PROTOCOL_VERSION,
            GET_DEVICE_STATUS,
            GET_COMMAND_CATALOG,
            GET_LIFECYCLE_STATUS,
            GET_KEY_STORE_STATUS,
            BEGIN_AUTHENTICATION,
            COMPLETE_AUTHENTICATION,
            GET_SESSION_STATUS,
            GET_CRYPTO_CAPABILITIES,
            VERIFY_DETACHED,
            INVALIDATE_SESSION,
            BEGIN_PROVISIONING,
            FINALIZE_PROVISIONING,
        ]),
        SessionState::Administrator => public_and(&[
            GET_PROTOCOL_VERSION,
            GET_DEVICE_STATUS,
            GET_COMMAND_CATALOG,
            GET_LIFECYCLE_STATUS,
            GET_KEY_STORE_STATUS,
            BEGIN_AUTHENTICATION,
            COMPLETE_AUTHENTICATION,
            GET_SESSION_STATUS,
            GET_CRYPTO_CAPABILITIES,
            VERIFY_DETACHED,
            INVALIDATE_SESSION,
            LOCK_DEVICE,
            UNLOCK_DEVICE,
            EXECUTE_ZEROIZE,
            GENERATE_RANDOM,
        ]),
        SessionState::Recovery => public_and(&[
            GET_PROTOCOL_VERSION,
            GET_DEVICE_STATUS,
            GET_COMMAND_CATALOG,
            GET_LIFECYCLE_STATUS,
            GET_KEY_STORE_STATUS,
            BEGIN_AUTHENTICATION,
            COMPLETE_AUTHENTICATION,
            GET_SESSION_STATUS,
            GET_CRYPTO_CAPABILITIES,
            VERIFY_DETACHED,
            INVALIDATE_SESSION,
            ENTER_RECOVERY,
            RECOVER_TO_PROVISIONED,
            REACTIVATE_RECOVERED_PROVISIONING,
        ]),
        SessionState::Developer => {
            if developer_mode {
                &[
                    GET_PROTOCOL_VERSION,
                    GET_DEVICE_STATUS,
                    GET_COMMAND_CATALOG,
                    GET_LIFECYCLE_STATUS,
                    GET_KEY_STORE_STATUS,
                    BEGIN_AUTHENTICATION,
                    COMPLETE_AUTHENTICATION,
                    GET_SESSION_STATUS,
                    GET_CRYPTO_CAPABILITIES,
                    VERIFY_DETACHED,
                    DEVELOPER_RESET_LIFECYCLE,
                    DEVELOPER_STORE_FAULT,
                    DEVELOPER_REBOOT,
                ]
            } else {
                PUBLIC_COMMANDS
            }
        }
        SessionState::KeyManager => public_and(&[
            GET_PROTOCOL_VERSION,
            GET_DEVICE_STATUS,
            GET_COMMAND_CATALOG,
            GET_LIFECYCLE_STATUS,
            GET_KEY_STORE_STATUS,
            BEGIN_AUTHENTICATION,
            COMPLETE_AUTHENTICATION,
            GET_SESSION_STATUS,
            GET_CRYPTO_CAPABILITIES,
            VERIFY_DETACHED,
            INVALIDATE_SESSION,
            PUT_PERSISTENT_KEY,
            LIST_PERSISTENT_KEYS,
            GET_KEY_METADATA,
            REVOKE_PERSISTENT_KEY,
            DESTROY_PERSISTENT_KEY,
            SIGN_DETACHED,
            GENERATE_RANDOM,
            IMPORT_WRAPPED_KEY,
        ]),
    }
}
