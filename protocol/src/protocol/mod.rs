pub mod codec;
pub mod command;
pub mod frame;
pub mod parser;
pub mod state;

pub use codec::{
    DecodeError, StatusCode, decode_audit_page_request, decode_begin_firmware_update_request,
    decode_firmware_chunk_request, decode_frame, encode_audit_page_payload, encode_firmware_abort_payload,
    encode_firmware_activation_payload, encode_firmware_chunk_progress_payload,
    encode_firmware_finalize_payload, encode_firmware_recovery_payload,
    encode_firmware_update_begin_payload, encode_firmware_update_status_payload, encode_frame,
    encode_health_status_payload, encode_policy_profile_payload, policy_status_response,
    status_response,
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
    AcceptedFirmwareState, AccessFailureCounter, AlgorithmProfile, ApprovalTargetBinding,
    ApprovalTicket, ApprovalTicketState, AuditEvent, AuditEventClass, AuditEventCode,
    AuditJournal, AuditResultClass, AuditRetrievalCursor, AuditStoreSnapshot, AuditStoreState,
    AuthSnapshot, AuthenticationChallenge, AuthorityRole, BeginFirmwareUpdateRequest,
    BootSlotId, BootSlotMetadata, BootSlotState, ALGORITHM_OP_DECRYPT,
    ALGORITHM_OP_ENCRYPT, ALGORITHM_OP_GENERATE, CHACHA20POLY1305_KEY_LEN,
    CHACHA20POLY1305_NONCE_LEN, CHACHA20POLY1305_TAG_LEN, CredentialKind, CredentialRecord,
    CryptoCapabilities, CryptoPersistentState, CryptoServiceFlags,
    DEVELOPER_RESET_COMPLETION_FLAGS, DenialClass, DecryptRequest, DecryptResponse,
    DeveloperResetOutcome, DeviceState, EncryptRequest, EncryptResponse, ExportPolicy,
    FirmwareAbortResult, FirmwareActivationResult, FirmwareChunkProgress, FirmwareChunkRequest,
    FirmwareFinalizeResult, FirmwarePackageManifest, FirmwareRecoveryResult,
    FirmwareUpdateBeginResult, FirmwareUpdateStatus, FirmwareVersion, GenerateKeyRequest,
    HealthStatusView, KeyAlgorithm, KeyDestroyResult, KeyLifecycleState, KeyListEntry,
    KeyMetadata, KeyMetadataView, KeyOrigin, KeyRecordResult, KeyStoreRecord, KeyStoreSnapshot,
    KeyStoreState, KeyStoreStatus, LifecycleStatus, LockResult, MAX_APPROVAL_TICKETS,
    MAX_AUDIT_DETAIL_LEN, MAX_AUDIT_EVENTS, MAX_CIPHERTEXT_LEN, MAX_FIRMWARE_CHUNK_LEN,
    MAX_ENCRYPT_HEADER_LEN, MAX_FIRMWARE_IMAGE_SIZE, MAX_FIRMWARE_SIGNATURE_LEN,
    MAX_KEY_JOURNAL_RECORDS, MAX_KEY_LIST_ENTRIES, MAX_KEY_MATERIAL_LEN, MAX_PERSISTENT_KEYS,
    MAX_RANDOM_OUTPUT_LEN, MAX_SIGNATURE_LEN, P256_PUBLIC_KEY_LEN, P256_SIGNATURE_LEN,
    POLICY_PROFILE_VERSION, PersistentKeyStore, PolicyDecision, PolicyProfile,
    ProtectedActionClass, ProvisioningRecord, ProvisioningSnapshot, RECORD_VERSION,
    RecoveryPolicy, RecoveryResult, RecoveryState, REVIEWED_ALGORITHM_PROFILES,
    SIGNATURE_ALGORITHM_FLAGS,
    SessionLifecycleState, SessionRecord, SessionState, SessionStatus, SessionTracker,
    StateRevision, TransitionIntent, TransitionResult, TransitionType, TrustedBootState,
    UPDATE_MANIFEST_VERSION, UPDATE_SERVICE_VERSION, UPDATE_SIGNATURE_ALGORITHM_ED25519,
    USAGE_DECRYPT, USAGE_ENCRYPT, USAGE_SIGN, USAGE_VERIFY, USAGE_WRAP_IMPORT,
    UpdateRecoveryReason, UpdateResultClass, UpdateTransferPhase, UpdateTransferState,
    VERIFY_ALGORITHM_FLAGS, X25519_ENVELOPE_HEADER_LEN, X25519_PUBLIC_KEY_LEN,
    ZEROIZE_COMPLETION_FLAGS, ZeroizeOutcome, default_boot_slots, developer_mode_session,
    developer_reset_marker, ed25519_public_key_from_seed, finalize_marker,
    firmware_version_allowed, recovery_marker, reactivate_marker, revoke_marker,
    unlock_marker, update_status_view, x25519_public_key_from_secret, zeroize_marker,
};
