use super::state::{DeviceState, SessionState};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandFamily {
    Discovery,
    Status,
    Provisioning,
    Administration,
    KeyManagement,
    CryptographicOperations,
    Audit,
    FirmwareUpdate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CommandId {
    GetProtocolVersion = 0x01,
    GetDeviceStatus = 0x02,
    GetCommandCatalog = 0x03,
    ProvisionDevice = 0x80,
    FactoryReset = 0x81,
}

impl CommandId {
    #[must_use]
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::GetProtocolVersion),
            0x02 => Some(Self::GetDeviceStatus),
            0x03 => Some(Self::GetCommandCatalog),
            0x80 => Some(Self::ProvisionDevice),
            0x81 => Some(Self::FactoryReset),
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
    pub required_session_state: SessionState,
    pub replay_policy: ReplayPolicy,
    pub idempotency_policy: IdempotencyPolicy,
    pub enabled: bool,
}

const ANY_NON_FAILED: &[DeviceState] = &[
    DeviceState::Ready,
    DeviceState::Operational,
    DeviceState::Locked,
];
const STATUS_STATES: &[DeviceState] = &[
    DeviceState::Ready,
    DeviceState::Operational,
    DeviceState::Locked,
];
const OPERATIONAL_ONLY: &[DeviceState] = &[DeviceState::Operational];

pub const GET_PROTOCOL_VERSION: CommandDefinition = CommandDefinition {
    id: CommandId::GetProtocolVersion,
    family: CommandFamily::Discovery,
    min_payload_len: 0,
    max_payload_len: 0,
    allowed_device_states: ANY_NON_FAILED,
    required_session_state: SessionState::Unauthenticated,
    replay_policy: ReplayPolicy::Repeatable,
    idempotency_policy: IdempotencyPolicy::Idempotent,
    enabled: true,
};

pub const GET_DEVICE_STATUS: CommandDefinition = CommandDefinition {
    id: CommandId::GetDeviceStatus,
    family: CommandFamily::Status,
    min_payload_len: 1,
    max_payload_len: 1,
    allowed_device_states: STATUS_STATES,
    required_session_state: SessionState::Unauthenticated,
    replay_policy: ReplayPolicy::Repeatable,
    idempotency_policy: IdempotencyPolicy::Idempotent,
    enabled: true,
};

pub const GET_COMMAND_CATALOG: CommandDefinition = CommandDefinition {
    id: CommandId::GetCommandCatalog,
    family: CommandFamily::Discovery,
    min_payload_len: 1,
    max_payload_len: 1,
    allowed_device_states: OPERATIONAL_ONLY,
    required_session_state: SessionState::Unauthenticated,
    replay_policy: ReplayPolicy::Repeatable,
    idempotency_policy: IdempotencyPolicy::Idempotent,
    enabled: true,
};

pub const PROVISION_DEVICE: CommandDefinition = CommandDefinition {
    id: CommandId::ProvisionDevice,
    family: CommandFamily::Provisioning,
    min_payload_len: 0,
    max_payload_len: 0,
    allowed_device_states: OPERATIONAL_ONLY,
    required_session_state: SessionState::Administrator,
    replay_policy: ReplayPolicy::SingleUse,
    idempotency_policy: IdempotencyPolicy::NonIdempotent,
    enabled: false,
};

pub const FACTORY_RESET: CommandDefinition = CommandDefinition {
    id: CommandId::FactoryReset,
    family: CommandFamily::Administration,
    min_payload_len: 0,
    max_payload_len: 0,
    allowed_device_states: OPERATIONAL_ONLY,
    required_session_state: SessionState::Administrator,
    replay_policy: ReplayPolicy::SingleUse,
    idempotency_policy: IdempotencyPolicy::NonIdempotent,
    enabled: false,
};

pub const PUBLIC_COMMANDS: &[CommandDefinition] = &[
    GET_PROTOCOL_VERSION,
    GET_DEVICE_STATUS,
    GET_COMMAND_CATALOG,
];

pub const RESERVED_COMMANDS: &[CommandDefinition] = &[PROVISION_DEVICE, FACTORY_RESET];

pub fn lookup_command(id: u8) -> Option<CommandDefinition> {
    CommandId::from_byte(id).map(definition_for)
}

#[must_use]
pub fn definition_for(id: CommandId) -> CommandDefinition {
    match id {
        CommandId::GetProtocolVersion => GET_PROTOCOL_VERSION,
        CommandId::GetDeviceStatus => GET_DEVICE_STATUS,
        CommandId::GetCommandCatalog => GET_COMMAND_CATALOG,
        CommandId::ProvisionDevice => PROVISION_DEVICE,
        CommandId::FactoryReset => FACTORY_RESET,
    }
}

#[must_use]
pub fn get_public_catalog() -> &'static [CommandDefinition] {
    PUBLIC_COMMANDS
}

#[must_use]
pub fn get_visible_catalog(session_state: SessionState, include_restricted: bool) -> &'static [CommandDefinition] {
    if include_restricted && session_state == SessionState::Administrator {
        &[
            GET_PROTOCOL_VERSION,
            GET_DEVICE_STATUS,
            GET_COMMAND_CATALOG,
            PROVISION_DEVICE,
            FACTORY_RESET,
        ]
    } else {
        PUBLIC_COMMANDS
    }
}
