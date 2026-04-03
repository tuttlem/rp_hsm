pub mod codec;
pub mod command;
pub mod frame;
pub mod parser;
pub mod state;

pub use codec::{
    DecodeError, StatusCode, decode_frame, encode_frame, encode_policy_profile_payload,
    policy_status_response, status_response,
};
pub use command::{
    AUTH_HEADER_LEN, CommandDefinition, CommandFamily, CommandId, IdempotencyPolicy,
    MAX_AUTH_PROOF_LEN, ReplayPolicy, get_public_catalog, lookup_command,
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
    AccessFailureCounter, AuthSnapshot, AuthenticationChallenge, AuthorityRole,
    ApprovalTargetBinding, ApprovalTicket, ApprovalTicketState, CredentialKind, CredentialRecord,
    CryptoCapabilities, CryptoPersistentState, CryptoServiceFlags,
    DEVELOPER_RESET_COMPLETION_FLAGS, DenialClass, DeveloperResetOutcome, DeviceState,
    ExportPolicy, KeyAlgorithm, KeyDestroyResult, KeyLifecycleState, KeyListEntry, KeyMetadata,
    KeyMetadataView, KeyOrigin, KeyRecordResult, KeyStoreRecord, KeyStoreSnapshot,
    KeyStoreState, KeyStoreStatus, LifecycleStatus, LockResult, MAX_APPROVAL_TICKETS,
    MAX_KEY_JOURNAL_RECORDS, MAX_KEY_LIST_ENTRIES, MAX_KEY_MATERIAL_LEN, MAX_PERSISTENT_KEYS,
    MAX_RANDOM_OUTPUT_LEN, MAX_SIGNATURE_LEN, POLICY_PROFILE_VERSION, PersistentKeyStore,
    PolicyDecision, PolicyProfile, ProtectedActionClass, P256_PUBLIC_KEY_LEN, P256_SIGNATURE_LEN,
    SIGNATURE_ALGORITHM_FLAGS, USAGE_SIGN, USAGE_WRAP_IMPORT, VERIFY_ALGORITHM_FLAGS,
    ProvisioningRecord, ProvisioningSnapshot, PutPersistentKeyRequest, RECORD_VERSION,
    RecoveryPolicy, RecoveryResult, SessionLifecycleState, SessionRecord, SessionState,
    SessionStatus, SessionTracker, StateRevision, TransitionIntent, TransitionResult,
    TransitionType, ZEROIZE_COMPLETION_FLAGS, ZeroizeOutcome, developer_mode_session,
    developer_reset_marker, ed25519_public_key_from_seed, finalize_marker, recovery_marker,
    reactivate_marker, revoke_marker, unlock_marker, zeroize_marker,
};
