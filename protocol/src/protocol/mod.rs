pub mod codec;
pub mod command;
pub mod frame;
pub mod parser;
pub mod state;

pub use codec::{DecodeError, StatusCode, decode_frame, encode_frame, status_response};
pub use command::{
    CommandDefinition, CommandFamily, CommandId, IdempotencyPolicy, ReplayPolicy, get_public_catalog,
};
pub use frame::{
    FLAG_INCLUDE_RESTRICTED, FLAG_REPLAY_SENSITIVE, FLAG_RESPONSE_REQUIRED, HEADER_LEN,
    MAX_FRAME_LEN, MAX_PAYLOAD_LEN, MessageKind, PROTOCOL_VERSION, ProtocolFrame,
    RESERVED_FLAG_MASK,
};
pub use parser::{
    DeveloperStoreFaultAction, FirmwareAction, ProtocolEngine, clear_transient_buffer,
};
pub use state::{
    AuthorityRole, DEVELOPER_RESET_COMPLETION_FLAGS, DeveloperResetOutcome, DeviceState,
    ExportPolicy, KeyAlgorithm, KeyDestroyResult, KeyLifecycleState, KeyListEntry,
    KeyMetadata, KeyMetadataView, KeyOrigin, KeyRecordResult, KeyStoreRecord, KeyStoreSnapshot,
    KeyStoreState, KeyStoreStatus, LifecycleStatus, LockResult, MAX_KEY_JOURNAL_RECORDS,
    MAX_KEY_LIST_ENTRIES, MAX_KEY_MATERIAL_LEN, MAX_PERSISTENT_KEYS, PersistentKeyStore,
    ProvisioningRecord, ProvisioningSnapshot, PutPersistentKeyRequest, RECORD_VERSION,
    RecoveryPolicy, RecoveryResult, SessionState, SessionTracker, StateRevision,
    TransitionIntent, TransitionResult, TransitionType, ZEROIZE_COMPLETION_FLAGS,
    ZeroizeOutcome, developer_mode_session, developer_reset_marker, finalize_marker,
    recovery_marker, reactivate_marker, revoke_marker, unlock_marker, zeroize_marker,
};
