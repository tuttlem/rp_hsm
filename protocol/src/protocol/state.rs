use heapless::Vec;
use rand_chacha::ChaCha8Rng;
use rand_core::{RngCore, SeedableRng};

use super::codec::StatusCode;
use super::command::{CommandDefinition, CommandId, ReplayPolicy};

pub const RECORD_VERSION: u8 = 1;
pub const MAX_OWNER_ID_LEN: usize = 16;
pub const MAX_AUTH_SNAPSHOT_LEN: usize = 16;
pub const MAX_ROLE_VERIFIER_LEN: usize = 8;
pub const MAX_CHALLENGE_NONCE_LEN: usize = 8;
pub const MAX_FAILURE_COUNTERS: usize = 4;
pub const ZEROIZE_COMPLETION_FLAGS: u8 = 0x0f;
pub const DEVELOPER_RESET_COMPLETION_FLAGS: u8 = 0x07;
pub const MAX_PERSISTENT_KEYS: usize = 8;
pub const MAX_KEY_MATERIAL_LEN: usize = 32;
pub const MAX_KEY_LIST_ENTRIES: usize = MAX_PERSISTENT_KEYS;
pub const MAX_KEY_JOURNAL_RECORDS: usize = 24;
pub const MAX_CRYPTO_MESSAGE_LEN: usize = 128;
pub const MAX_SIGNATURE_LEN: usize = 64;
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;
pub const ED25519_SIGNATURE_LEN: usize = 64;
pub const P256_PUBLIC_KEY_LEN: usize = 33;
pub const P256_SIGNATURE_LEN: usize = 64;
pub const MAX_RANDOM_OUTPUT_LEN: usize = 64;
pub const MAX_WRAPPED_CIPHERTEXT_LEN: usize = 32;
pub const MAX_WRAPPED_TAG_LEN: usize = 28;
pub const CRYPTO_SERVICE_VERSION: u8 = 1;
pub const SERVICE_FLAG_SIGN: u8 = 0x01;
pub const SERVICE_FLAG_VERIFY: u8 = 0x02;
pub const SERVICE_FLAG_RANDOM: u8 = 0x04;
pub const SERVICE_FLAG_WRAPPED_IMPORT: u8 = 0x08;
pub const SIGNATURE_ALGORITHM_FLAGS: u8 = 0x01;
pub const VERIFY_ALGORITHM_FLAGS: u8 = 0x03;
pub const USAGE_SIGN: u8 = 0x01;
pub const USAGE_WRAP_IMPORT: u8 = 0x20;
pub const POLICY_PROFILE_VERSION: u8 = 1;
pub const PROTECTED_ACTION_EXECUTE_ZEROIZE: u16 = 0x0001;
pub const PROTECTED_ACTION_DESTROY_KEY: u16 = 0x0002;
pub const PROTECTED_ACTION_RECOVERY_TRANSITION: u16 = 0x0004;
pub const MAX_APPROVAL_TICKETS: usize = 3;
pub const APPROVAL_TICKET_EXPIRY_TICKS: u16 = 8;
pub const MAX_AUDIT_DETAIL_LEN: usize = 12;
pub const MAX_AUDIT_EVENTS: usize = 32;
pub const MAX_AUDIT_PAGE_EVENTS: usize = 4;
pub const UPDATE_MANIFEST_VERSION: u8 = 1;
pub const UPDATE_SIGNATURE_ALGORITHM_ED25519: u8 = 0x01;
pub const MAX_FIRMWARE_SIGNATURE_LEN: usize = 64;
pub const MAX_FIRMWARE_IMAGE_SIZE: usize = 1024;
pub const MAX_FIRMWARE_CHUNK_LEN: usize = 128;
pub const UPDATE_SERVICE_VERSION: u8 = 1;
pub const PROTECTED_ACTION_FIRMWARE_UPDATE: u16 = 0x0008;

const FINALIZE_MARKER: u8 = 0xa5;
const REACTIVATE_MARKER: u8 = 0xa6;
const UNLOCK_MARKER: u8 = 0x5a;
const RECOVERY_MARKER: u8 = 0xc3;
const REVOKE_MARKER: u8 = 0x52;
const ZEROIZE_MARKER: [u8; 2] = [0xde, 0xad];
const DEVELOPER_RESET_MARKER: [u8; 3] = [0x44, 0x45, 0x56];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DeviceState {
    Factory = 0x01,
    Provisioned = 0x02,
    Operational = 0x03,
    Locked = 0x04,
    Recovery = 0x05,
    Zeroized = 0x06,
}

impl DeviceState {
    #[must_use]
    pub const fn owner_present(self) -> bool {
        matches!(
            self,
            Self::Provisioned | Self::Operational | Self::Locked | Self::Recovery
        )
    }

    #[must_use]
    pub const fn recovery_required(self) -> bool {
        matches!(self, Self::Recovery)
    }

    #[must_use]
    pub const fn is_operational(self) -> bool {
        matches!(self, Self::Operational)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionState {
    Unauthenticated = 0x01,
    Bootstrap = 0x02,
    Administrator = 0x03,
    Recovery = 0x04,
    Developer = 0x05,
    KeyManager = 0x06,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthorityRole {
    Public = 0x01,
    Bootstrap = 0x02,
    Administrator = 0x03,
    Recovery = 0x04,
    Developer = 0x05,
    KeyManager = 0x06,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DenialClass {
    None = 0x00,
    CommandUnavailable = 0x01,
    StateDenied = 0x02,
    RoleDenied = 0x03,
    KeyPolicyDenied = 0x04,
    ApprovalMissing = 0x05,
    ApprovalStale = 0x06,
    InternalPolicyError = 0x07,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ProtectedActionClass {
    None = 0x00,
    DestructiveAdmin = 0x01,
    DestructiveKey = 0x02,
    RecoveryTransition = 0x03,
    FirmwareUpdate = 0x04,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ApprovalTargetBinding {
    Device = 0x01,
    KeyId = 0x02,
    TransitionId = 0x03,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ApprovalTicketState {
    Pending = 0x01,
    Confirmed = 0x02,
    Consumed = 0x03,
    Invalidated = 0x04,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyProfile {
    pub profile_version: u8,
    pub policy_revision: u32,
    pub dual_control_enabled: bool,
    pub protected_action_mask: u16,
    pub developer_commands_visible: bool,
}

impl Default for PolicyProfile {
    fn default() -> Self {
        Self {
            profile_version: POLICY_PROFILE_VERSION,
            policy_revision: 1,
            dual_control_enabled: false,
            protected_action_mask: PROTECTED_ACTION_EXECUTE_ZEROIZE
                | PROTECTED_ACTION_DESTROY_KEY
                | PROTECTED_ACTION_RECOVERY_TRANSITION
                | PROTECTED_ACTION_FIRMWARE_UPDATE,
            developer_commands_visible: false,
        }
    }
}

impl PolicyProfile {
    #[must_use]
    pub fn protects(self, action: ProtectedActionClass) -> bool {
        let bit = match action {
            ProtectedActionClass::None => return false,
            ProtectedActionClass::DestructiveAdmin => PROTECTED_ACTION_EXECUTE_ZEROIZE,
            ProtectedActionClass::DestructiveKey => PROTECTED_ACTION_DESTROY_KEY,
            ProtectedActionClass::RecoveryTransition => PROTECTED_ACTION_RECOVERY_TRANSITION,
            ProtectedActionClass::FirmwareUpdate => PROTECTED_ACTION_FIRMWARE_UPDATE,
        };
        self.protected_action_mask & bit != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FirmwareVersion {
    pub security_epoch: u16,
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}

impl FirmwareVersion {
    #[must_use]
    pub const fn new(security_epoch: u16, major: u16, minor: u16, patch: u16) -> Self {
        Self {
            security_epoch,
            major,
            minor,
            patch,
        }
    }
}

impl Default for FirmwareVersion {
    fn default() -> Self {
        Self::new(1, 0, 0, 0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BootSlotId {
    A = 0x01,
    B = 0x02,
}

impl BootSlotId {
    #[must_use]
    pub const fn other(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }

    #[must_use]
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::A),
            0x02 => Some(Self::B),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum BootSlotState {
    Empty = 0x01,
    ActiveTrusted = 0x02,
    StagedTransfer = 0x03,
    StagedValidated = 0x04,
    Invalid = 0x05,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum UpdateTransferPhase {
    Empty = 0x00,
    ManifestAccepted = 0x01,
    Transferring = 0x02,
    Transferred = 0x03,
    Validating = 0x04,
    ActivationPending = 0x05,
    Aborted = 0x06,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TrustedBootState {
    ActiveTrusted = 0x01,
    StagedPending = 0x02,
    StagedValidating = 0x03,
    RecoveryRequired = 0x04,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum UpdateResultClass {
    None = 0x00,
    Begun = 0x01,
    Aborted = 0x02,
    Finalized = 0x03,
    Activated = 0x04,
    RollbackDenied = 0x05,
    SignatureRejected = 0x06,
    DigestMismatch = 0x07,
    Interrupted = 0x08,
    Recovered = 0x09,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum UpdateRecoveryReason {
    None = 0x00,
    InterruptedTransfer = 0x01,
    AmbiguousActivation = 0x02,
    MetadataCorrupted = 0x03,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirmwarePackageManifest {
    pub manifest_version: u8,
    pub image_version: FirmwareVersion,
    pub image_size_bytes: u32,
    pub image_digest_sha256: [u8; 32],
    pub target_slot_hint: BootSlotId,
    pub policy_flags: u16,
    pub signature_algorithm: u8,
    pub signature_bytes: Vec<u8, MAX_FIRMWARE_SIGNATURE_LEN>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct BootSlotMetadata {
    pub slot_id: BootSlotId,
    pub slot_state: BootSlotState,
    pub stored_version: FirmwareVersion,
    pub version_present: bool,
    pub stored_digest: [u8; 32],
    pub digest_present: bool,
    pub bootable: bool,
    pub trusted: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AcceptedFirmwareState {
    pub active_slot: BootSlotId,
    pub active_version: FirmwareVersion,
    pub minimum_accepted_version: FirmwareVersion,
    pub trusted_boot_state: TrustedBootState,
    pub last_update_result: UpdateResultClass,
    pub recovery_required: bool,
    pub revision_counter: u32,
}

impl Default for AcceptedFirmwareState {
    fn default() -> Self {
        Self {
            active_slot: BootSlotId::A,
            active_version: FirmwareVersion::default(),
            minimum_accepted_version: FirmwareVersion::default(),
            trusted_boot_state: TrustedBootState::ActiveTrusted,
            last_update_result: UpdateResultClass::None,
            recovery_required: false,
            revision_counter: 1,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateTransferState {
    pub phase: UpdateTransferPhase,
    pub session_id: u32,
    pub manifest: Option<FirmwarePackageManifest>,
    pub bytes_received: u32,
    pub expected_size: u32,
    pub staged_image: Vec<u8, MAX_FIRMWARE_IMAGE_SIZE>,
    pub started_revision: u32,
    pub policy_revision: u32,
}

impl Default for UpdateTransferState {
    fn default() -> Self {
        Self {
            phase: UpdateTransferPhase::Empty,
            session_id: 0,
            manifest: None,
            bytes_received: 0,
            expected_size: 0,
            staged_image: Vec::new(),
            started_revision: 0,
            policy_revision: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryState {
    pub reason: UpdateRecoveryReason,
    pub last_trusted_slot: BootSlotId,
    pub staged_slot: BootSlotId,
    pub staged_slot_present: bool,
    pub authorization_required: bool,
}

impl Default for RecoveryState {
    fn default() -> Self {
        Self {
            reason: UpdateRecoveryReason::None,
            last_trusted_slot: BootSlotId::A,
            staged_slot: BootSlotId::B,
            staged_slot_present: false,
            authorization_required: true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FirmwareUpdateStatus {
    pub active_slot: BootSlotId,
    pub active_version: FirmwareVersion,
    pub minimum_accepted_version: FirmwareVersion,
    pub transfer_phase: UpdateTransferPhase,
    pub staged_slot_state: BootSlotState,
    pub recovery_required: bool,
    pub last_update_result: UpdateResultClass,
    pub policy_revision: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FirmwareUpdateBeginResult {
    pub target_slot: BootSlotId,
    pub update_session_id: u32,
    pub expected_size: u32,
    pub policy_revision: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FirmwareChunkProgress {
    pub bytes_received: u32,
    pub remaining_bytes: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FirmwareFinalizeResult {
    pub staged_slot: BootSlotId,
    pub validated_version: FirmwareVersion,
    pub activation_pending: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FirmwareActivationResult {
    pub next_boot_slot: BootSlotId,
    pub next_version: FirmwareVersion,
    pub reboot_required: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FirmwareAbortResult {
    pub transfer_state_cleared: bool,
    pub staged_slot_invalidated: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FirmwareRecoveryResult {
    pub restored_slot: BootSlotId,
    pub restored_version: FirmwareVersion,
    pub recovery_required: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BeginFirmwareUpdateRequest {
    pub manifest: FirmwarePackageManifest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirmwareChunkRequest {
    pub update_session_id: u32,
    pub chunk_offset: u32,
    pub chunk: Vec<u8, MAX_FIRMWARE_CHUNK_LEN>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApprovalTicket {
    pub ticket_id: u32,
    pub approval_class: ProtectedActionClass,
    pub target_binding: ApprovalTargetBinding,
    pub target_id: u32,
    pub initiator_role: AuthorityRole,
    pub confirmer_role: AuthorityRole,
    pub initiator_session_id: u32,
    pub policy_revision: u32,
    pub device_revision: u32,
    pub expires_at_tick: u32,
    pub state: ApprovalTicketState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyDecision {
    pub decision: bool,
    pub denial_class: DenialClass,
    pub approval_ticket_id: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuditEventClass {
    Administrative = 0x01,
    SecurityDenial = 0x02,
    LifecycleTransition = 0x03,
    PersistenceAnomaly = 0x04,
    ObservabilityAccess = 0x05,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuditResultClass {
    Success = 0x01,
    Denied = 0x02,
    FailedClosed = 0x03,
    Degraded = 0x04,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuditEventCode {
    CommandCompleted = 0x01,
    CommandDenied = 0x02,
    AuthenticationFailed = 0x03,
    SessionInvalidated = 0x04,
    HealthStatusViewed = 0x05,
    HealthStatusDenied = 0x06,
    AuditPageViewed = 0x07,
    AuditPageDenied = 0x08,
    RetentionOverflow = 0x09,
    PersistenceFault = 0x0a,
    DeveloperPolicyChanged = 0x0b,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuditStoreState {
    Empty = 0x01,
    Ready = 0x02,
    Full = 0x03,
    Degraded = 0x04,
    Locked = 0x05,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEvent {
    pub sequence_id: u32,
    pub event_class: AuditEventClass,
    pub event_code: AuditEventCode,
    pub device_revision: u32,
    pub lifecycle_state: DeviceState,
    pub actor_role: AuthorityRole,
    pub session_kind: SessionState,
    pub result_class: AuditResultClass,
    pub detail_len: u8,
    pub detail: Vec<u8, MAX_AUDIT_DETAIL_LEN>,
    pub integrity_tag: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditRetrievalCursor {
    pub start_sequence: u32,
    pub max_events: u8,
    pub next_sequence: Option<u32>,
    pub truncated: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HealthStatusView {
    pub device_state: DeviceState,
    pub key_store_state: KeyStoreState,
    pub session_state: SessionState,
    pub policy_revision: u32,
    pub audit_store_state: AuditStoreState,
    pub audit_events_retained: u16,
    pub audit_overflow_detected: bool,
    pub rollback_detected: bool,
    pub corruption_detected: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditJournal {
    pub events: Vec<AuditEvent, MAX_AUDIT_EVENTS>,
    pub next_sequence_id: u32,
    pub overflow_count: u32,
    pub corruption_detected: bool,
    pub retrieval_locked: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditStoreSnapshot {
    pub events: Vec<AuditEvent, MAX_AUDIT_EVENTS>,
    pub next_sequence_id: u32,
    pub overflow_count: u32,
    pub corruption_detected: bool,
    pub retrieval_locked: bool,
}

impl PolicyDecision {
    #[must_use]
    pub const fn allow() -> Self {
        Self {
            decision: true,
            denial_class: DenialClass::None,
            approval_ticket_id: None,
        }
    }

    #[must_use]
    pub const fn deny(denial_class: DenialClass) -> Self {
        Self {
            decision: false,
            denial_class,
            approval_ticket_id: None,
        }
    }

    #[must_use]
    pub const fn deny_with_ticket(denial_class: DenialClass, ticket_id: u32) -> Self {
        Self {
            decision: false,
            denial_class,
            approval_ticket_id: Some(ticket_id),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TransitionType {
    Provisioning = 0x01,
    Activation = 0x02,
    Lock = 0x03,
    Unlock = 0x04,
    EnterRecovery = 0x05,
    RecoverToProvisioned = 0x06,
    ReactivateRecoveredProvisioning = 0x07,
    Zeroize = 0x08,
    DeveloperReset = 0x09,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthorizationMode {
    None = 0x00,
    DeveloperMode = 0x01,
    BootstrapProof = 0x02,
    AdministratorProof = 0x03,
    RecoveryProof = 0x04,
    KeyManagerProof = 0x05,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CredentialKind {
    Marker = 0x01,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CryptoServiceFlags(pub u8);

impl CryptoServiceFlags {
    #[must_use]
    pub const fn reviewed_v1() -> Self {
        Self(
            SERVICE_FLAG_SIGN
                | SERVICE_FLAG_VERIFY
                | SERVICE_FLAG_RANDOM
                | SERVICE_FLAG_WRAPPED_IMPORT,
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CryptoCapabilities {
    pub service_version: u8,
    pub operation_flags: CryptoServiceFlags,
    pub sign_algorithm_flags: u8,
    pub verify_algorithm_flags: u8,
    pub max_message_len: u16,
    pub max_signature_len: u16,
    pub max_random_len: u8,
    pub wrapped_import_enabled: bool,
}

impl Default for CryptoCapabilities {
    fn default() -> Self {
        Self {
            service_version: CRYPTO_SERVICE_VERSION,
            operation_flags: CryptoServiceFlags::reviewed_v1(),
            sign_algorithm_flags: SIGNATURE_ALGORITHM_FLAGS,
            verify_algorithm_flags: VERIFY_ALGORITHM_FLAGS,
            max_message_len: u16::try_from(MAX_CRYPTO_MESSAGE_LEN).unwrap_or(0),
            max_signature_len: u16::try_from(MAX_SIGNATURE_LEN).unwrap_or(0),
            max_random_len: u8::try_from(MAX_RANDOM_OUTPUT_LEN).unwrap_or(0),
            wrapped_import_enabled: true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CryptoPersistentState {
    pub policy_version: u8,
    pub wrapped_import_count: u32,
    pub last_wrapped_import_revision: u32,
}

impl Default for CryptoPersistentState {
    fn default() -> Self {
        Self {
            policy_version: CRYPTO_SERVICE_VERSION,
            wrapped_import_count: 0,
            last_wrapped_import_revision: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CryptoRuntimeState {
    pub capabilities: CryptoCapabilities,
    pub persistent: CryptoPersistentState,
    pub rng_seed: [u8; 32],
    pub rng_counter: u64,
    pub rng_healthy: bool,
}

impl Default for CryptoRuntimeState {
    fn default() -> Self {
        Self {
            capabilities: CryptoCapabilities::default(),
            persistent: CryptoPersistentState::default(),
            rng_seed: *b"rp2350-hsm-dev-seed-crypto-v1!!!",
            rng_counter: 0,
            rng_healthy: true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum SessionLifecycleState {
    Inactive = 0x00,
    Pending = 0x01,
    Active = 0x02,
    Expired = 0x03,
    Invalidated = 0x04,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialRecord {
    pub role: AuthorityRole,
    pub credential_kind: CredentialKind,
    pub verifier_bytes: Vec<u8, MAX_ROLE_VERIFIER_LEN>,
    pub enabled: bool,
    pub session_timeout_ticks: u16,
    pub max_failures: u8,
    pub lockout_ticks: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticationChallenge {
    pub challenge_id: u32,
    pub requested_role: AuthorityRole,
    pub nonce: Vec<u8, MAX_CHALLENGE_NONCE_LEN>,
    pub expires_at_tick: u32,
    pub request_counter_floor: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionRecord {
    pub session_id: u32,
    pub role: AuthorityRole,
    pub state: SessionLifecycleState,
    pub issued_at_revision: u32,
    pub expires_at_tick: u32,
    pub last_counter: u32,
    pub last_activity_tick: u32,
    pub authorization_mode: AuthorizationMode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccessFailureCounter {
    pub role: AuthorityRole,
    pub consecutive_failures: u8,
    pub locked_until_tick: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionStatus {
    pub session_present: bool,
    pub active_role: AuthorityRole,
    pub expires_in_ticks: u16,
    pub lockout_active: bool,
    pub lockout_role: AuthorityRole,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthSnapshot {
    pub credentials: Vec<CredentialRecord, MAX_FAILURE_COUNTERS>,
    pub failure_counters: Vec<AccessFailureCounter, MAX_FAILURE_COUNTERS>,
    pub next_challenge_id: u32,
    pub next_session_id: u32,
}

impl Default for AuthSnapshot {
    fn default() -> Self {
        let mut credentials = Vec::<CredentialRecord, MAX_FAILURE_COUNTERS>::new();
        let _ = credentials.push(CredentialRecord::new(
            AuthorityRole::Bootstrap,
            b"BOOT",
            8,
            3,
            5,
        ));
        let _ = credentials.push(CredentialRecord::new(
            AuthorityRole::Administrator,
            b"ADMIN",
            8,
            3,
            5,
        ));
        let _ = credentials.push(CredentialRecord::new(
            AuthorityRole::Recovery,
            b"RECVR",
            8,
            3,
            5,
        ));
        let _ = credentials.push(CredentialRecord::new(
            AuthorityRole::KeyManager,
            b"KEYMG",
            8,
            3,
            5,
        ));

        let mut failure_counters = Vec::<AccessFailureCounter, MAX_FAILURE_COUNTERS>::new();
        let _ = failure_counters.push(AccessFailureCounter::new(AuthorityRole::Bootstrap));
        let _ = failure_counters.push(AccessFailureCounter::new(AuthorityRole::Administrator));
        let _ = failure_counters.push(AccessFailureCounter::new(AuthorityRole::Recovery));
        let _ = failure_counters.push(AccessFailureCounter::new(AuthorityRole::KeyManager));

        Self {
            credentials,
            failure_counters,
            next_challenge_id: 1,
            next_session_id: 1,
        }
    }
}

impl CredentialRecord {
    #[must_use]
    pub fn new(
        role: AuthorityRole,
        verifier: &[u8],
        session_timeout_ticks: u16,
        max_failures: u8,
        lockout_ticks: u16,
    ) -> Self {
        let mut verifier_bytes = Vec::<u8, MAX_ROLE_VERIFIER_LEN>::new();
        let _ = verifier_bytes.extend_from_slice(verifier);
        Self {
            role,
            credential_kind: CredentialKind::Marker,
            verifier_bytes,
            enabled: true,
            session_timeout_ticks,
            max_failures,
            lockout_ticks,
        }
    }

    #[must_use]
    pub fn allows_state(&self, device_state: DeviceState) -> bool {
        match self.role {
            AuthorityRole::Bootstrap => matches!(device_state, DeviceState::Factory | DeviceState::Zeroized),
            AuthorityRole::Administrator => matches!(device_state, DeviceState::Operational | DeviceState::Locked),
            AuthorityRole::Recovery => matches!(device_state, DeviceState::Locked | DeviceState::Recovery),
            AuthorityRole::KeyManager => matches!(device_state, DeviceState::Operational),
            AuthorityRole::Public | AuthorityRole::Developer => false,
        }
    }
}

impl AccessFailureCounter {
    #[must_use]
    pub const fn new(role: AuthorityRole) -> Self {
        Self {
            role,
            consecutive_failures: 0,
            locked_until_tick: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerBinding {
    pub owner_id: Vec<u8, MAX_OWNER_ID_LEN>,
    pub provisioning_epoch: u32,
    pub authorization_mode: AuthorizationMode,
    pub transfer_allowed: bool,
    pub binding_digest: u32,
}

impl Default for OwnerBinding {
    fn default() -> Self {
        Self {
            owner_id: Vec::new(),
            provisioning_epoch: 0,
            authorization_mode: AuthorizationMode::None,
            transfer_allowed: false,
            binding_digest: 0,
        }
    }
}

impl OwnerBinding {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.owner_id.is_empty()
    }

    pub fn clear(&mut self) {
        for byte in &mut self.owner_id {
            *byte = 0;
        }
        self.owner_id.clear();
        self.provisioning_epoch = 0;
        self.authorization_mode = AuthorizationMode::None;
        self.transfer_allowed = false;
        self.binding_digest = 0;
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitionIntent {
    pub transition_id: u32,
    pub transition_type: TransitionType,
    pub source_state: DeviceState,
    pub target_state: DeviceState,
    pub command_code: u8,
    pub authorization_snapshot: Vec<u8, MAX_AUTH_SNAPSHOT_LEN>,
    pub created_revision: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvisioningSnapshot {
    pub record_version: u8,
    pub lifecycle_state: LifecycleState,
    pub pending_transition: Option<TransitionIntent>,
    pub owner_binding: OwnerBinding,
    pub recovery_policy: RecoveryPolicy,
    pub revision_counter: u32,
    pub integrity_tag: u32,
    pub next_transition_id: u32,
}

impl TransitionIntent {
    #[must_use]
    pub fn new(
        transition_id: u32,
        transition_type: TransitionType,
        source_state: DeviceState,
        target_state: DeviceState,
        command_code: u8,
        snapshot: &[u8],
        created_revision: u32,
    ) -> Option<Self> {
        let mut authorization_snapshot = Vec::new();
        authorization_snapshot.extend_from_slice(snapshot).ok()?;
        Some(Self {
            transition_id,
            transition_type,
            source_state,
            target_state,
            command_code,
            authorization_snapshot,
            created_revision,
        })
    }

    pub fn clear(&mut self) {
        for byte in &mut self.authorization_snapshot {
            *byte = 0;
        }
        self.authorization_snapshot.clear();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryPolicy {
    pub recovery_enabled: bool,
    pub required_authority: AuthorityRole,
    pub max_attempts: u8,
}

impl Default for RecoveryPolicy {
    fn default() -> Self {
        Self {
            recovery_enabled: true,
            required_authority: AuthorityRole::Recovery,
            max_attempts: 3,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LifecycleState {
    pub state_code: DeviceState,
    pub entered_revision: u32,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZeroizeOutcome {
    pub result_state: DeviceState,
    pub owner_binding_cleared: bool,
    pub secret_storage_cleared: bool,
    pub transient_buffers_cleared: bool,
    pub requires_reprovisioning: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeveloperResetOutcome {
    pub result_state: DeviceState,
    pub owner_binding_cleared: bool,
    pub pending_transition_cleared: bool,
    pub transient_buffers_cleared: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LifecycleStatus {
    pub state: DeviceState,
    pub owner_present: bool,
    pub recovery_required: bool,
    pub pending_transition_present: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransitionResult {
    pub state: DeviceState,
    pub transition_id: u32,
    pub revision_counter: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateRevision {
    pub state: DeviceState,
    pub revision_counter: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LockResult {
    pub state: DeviceState,
    pub reason_code: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryResult {
    pub state: DeviceState,
    pub recovery_required: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyLifecycleState {
    Pending = 0x01,
    Active = 0x02,
    Revoked = 0x03,
    PendingDestroy = 0x04,
    Destroyed = 0x05,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyAlgorithm {
    Ed25519 = 0x01,
    P256 = 0x02,
    Aes256 = 0x03,
}

impl KeyAlgorithm {
    #[must_use]
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::Ed25519),
            0x02 => Some(Self::P256),
            0x03 => Some(Self::Aes256),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyOrigin {
    Generated = 0x01,
    Imported = 0x02,
}

impl KeyOrigin {
    #[must_use]
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::Generated),
            0x02 => Some(Self::Imported),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ExportPolicy {
    NonExportable = 0x01,
    WrappedOnly = 0x02,
}

impl ExportPolicy {
    #[must_use]
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::NonExportable),
            0x02 => Some(Self::WrappedOnly),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MaterialEncoding {
    Internal = 0x01,
    WrappedImport = 0x02,
    Destroyed = 0x03,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyStoreState {
    Empty = 0x01,
    Ready = 0x02,
    Degraded = 0x03,
    RecoveryRequired = 0x04,
    Full = 0x05,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyMetadata {
    pub algorithm: KeyAlgorithm,
    pub origin: KeyOrigin,
    pub usage_mask: u8,
    pub export_policy: ExportPolicy,
    pub created_revision: u32,
    pub last_state_change_revision: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyMaterialEnvelope {
    pub encoding: MaterialEncoding,
    pub material_len: u8,
    pub material_bytes: Vec<u8, MAX_KEY_MATERIAL_LEN>,
    pub destroyed_marker: bool,
}

impl Default for KeyMaterialEnvelope {
    fn default() -> Self {
        Self {
            encoding: MaterialEncoding::Internal,
            material_len: 0,
            material_bytes: Vec::new(),
            destroyed_marker: false,
        }
    }
}

impl KeyMaterialEnvelope {
    #[must_use]
    pub fn try_from_bytes(origin: KeyOrigin, bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() || bytes.len() > MAX_KEY_MATERIAL_LEN {
            return None;
        }

        let mut material_bytes = Vec::new();
        material_bytes.extend_from_slice(bytes).ok()?;
        let material_len = u8::try_from(bytes.len()).ok()?;
        Some(Self {
            encoding: if origin == KeyOrigin::Imported {
                MaterialEncoding::WrappedImport
            } else {
                MaterialEncoding::Internal
            },
            material_len,
            material_bytes,
            destroyed_marker: false,
        })
    }

    pub fn clear(&mut self) {
        for byte in &mut self.material_bytes {
            *byte = 0;
        }
        self.material_bytes.clear();
        self.material_len = 0;
        self.encoding = MaterialEncoding::Destroyed;
        self.destroyed_marker = true;
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyStoreRecord {
    pub record_version: u8,
    pub slot_id: u8,
    pub key_id: u8,
    pub record_revision: u32,
    pub store_epoch: u32,
    pub lifecycle_state: KeyLifecycleState,
    pub metadata: KeyMetadata,
    pub material: KeyMaterialEnvelope,
    pub complete: bool,
    pub integrity_tag: u32,
}

impl KeyStoreRecord {
    #[must_use]
    pub fn new(
        slot_id: u8,
        key_id: u8,
        record_revision: u32,
        store_epoch: u32,
        lifecycle_state: KeyLifecycleState,
        metadata: KeyMetadata,
        material: KeyMaterialEnvelope,
    ) -> Self {
        let mut record = Self {
            record_version: RECORD_VERSION,
            slot_id,
            key_id,
            record_revision,
            store_epoch,
            lifecycle_state,
            metadata,
            material,
            complete: true,
            integrity_tag: 0,
        };
        record.refresh_integrity();
        record
    }

    #[must_use]
    pub fn verify_integrity(&self) -> bool {
        self.complete && self.integrity_tag == self.compute_integrity_tag()
    }

    pub fn invalidate_material(&mut self) {
        self.material.clear();
        self.refresh_integrity();
    }

    pub fn refresh_integrity(&mut self) {
        self.integrity_tag = self.compute_integrity_tag();
    }

    fn compute_integrity_tag(&self) -> u32 {
        let mut tag = u32::from(self.record_version)
            ^ u32::from(self.slot_id)
            ^ u32::from(self.key_id)
            ^ self.record_revision.rotate_left(7)
            ^ self.store_epoch.rotate_left(13)
            ^ u32::from(self.lifecycle_state as u8)
            ^ u32::from(self.metadata.algorithm as u8) << 8
            ^ u32::from(self.metadata.origin as u8) << 16
            ^ u32::from(self.metadata.export_policy as u8) << 24
            ^ u32::from(self.metadata.usage_mask);
        for &byte in &self.material.material_bytes {
            tag = tag.rotate_left(3) ^ u32::from(byte);
        }
        if self.material.destroyed_marker {
            tag ^= 0xfeed_cafe;
        }
        if self.complete {
            tag ^= 0x1357_9bdf;
        }
        tag
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FreshnessAnchor {
    pub accepted_store_epoch: u32,
    pub accepted_device_revision: u32,
    pub store_revision: u32,
    pub integrity_tag: u32,
}

impl FreshnessAnchor {
    #[must_use]
    pub fn new(device_revision: u32) -> Self {
        let mut anchor = Self {
            accepted_store_epoch: 0,
            accepted_device_revision: device_revision,
            store_revision: 0,
            integrity_tag: 0,
        };
        anchor.refresh_integrity();
        anchor
    }

    #[must_use]
    pub fn verify_integrity(&self) -> bool {
        self.integrity_tag == self.compute_integrity_tag()
    }

    pub fn refresh_integrity(&mut self) {
        self.integrity_tag = self.compute_integrity_tag();
    }

    fn compute_integrity_tag(&self) -> u32 {
        self.accepted_store_epoch.rotate_left(5)
            ^ self.accepted_device_revision.rotate_left(11)
            ^ self.store_revision.rotate_left(17)
            ^ 0x2468_ace0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyStoreStatus {
    pub store_state: KeyStoreState,
    pub key_count: u8,
    pub free_slots: u8,
    pub rollback_detected: bool,
    pub corruption_detected: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyRecordResult {
    pub key_id: u8,
    pub lifecycle_state: KeyLifecycleState,
    pub record_revision: u32,
    pub store_revision: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyMetadataView {
    pub key_id: u8,
    pub algorithm: KeyAlgorithm,
    pub origin: KeyOrigin,
    pub usage_mask: u8,
    pub export_policy: ExportPolicy,
    pub lifecycle_state: KeyLifecycleState,
    pub record_revision: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyListEntry {
    pub key_id: u8,
    pub algorithm: KeyAlgorithm,
    pub lifecycle_state: KeyLifecycleState,
    pub usage_mask: u8,
    pub export_policy: ExportPolicy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyDestroyResult {
    pub key_id: u8,
    pub lifecycle_state: KeyLifecycleState,
    pub material_cleared: bool,
    pub tombstone_committed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PutPersistentKeyRequest {
    pub key_id: u8,
    pub algorithm: KeyAlgorithm,
    pub origin: KeyOrigin,
    pub usage_mask: u8,
    pub export_policy: ExportPolicy,
    pub material: KeyMaterialEnvelope,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignRequest {
    pub key_id: u8,
    pub algorithm: KeyAlgorithm,
    pub message: Vec<u8, MAX_CRYPTO_MESSAGE_LEN>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyRequest {
    pub algorithm: KeyAlgorithm,
    pub message: Vec<u8, MAX_CRYPTO_MESSAGE_LEN>,
    pub public_key: Vec<u8, P256_PUBLIC_KEY_LEN>,
    pub signature: Vec<u8, MAX_SIGNATURE_LEN>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RandomRequest {
    pub requested_len: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportWrappedKeyRequest {
    pub wrap_format_version: u8,
    pub wrapping_key_id: u8,
    pub target_algorithm: KeyAlgorithm,
    pub target_usage_mask: u8,
    pub target_export_policy: ExportPolicy,
    pub ciphertext: Vec<u8, MAX_WRAPPED_CIPHERTEXT_LEN>,
    pub integrity_tag: Vec<u8, MAX_WRAPPED_TAG_LEN>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistentKeyStore {
    pub journal: Vec<KeyStoreRecord, MAX_KEY_JOURNAL_RECORDS>,
    pub anchor: FreshnessAnchor,
    pub store_state: KeyStoreState,
    pub rollback_detected: bool,
    pub corruption_detected: bool,
    current_device_revision: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyStoreSnapshot {
    pub journal: Vec<KeyStoreRecord, MAX_KEY_JOURNAL_RECORDS>,
    pub anchor: FreshnessAnchor,
}

impl BootSlotMetadata {
    #[must_use]
    pub const fn new(slot_id: BootSlotId, slot_state: BootSlotState) -> Self {
        Self {
            slot_id,
            slot_state,
            stored_version: FirmwareVersion {
                security_epoch: 0,
                major: 0,
                minor: 0,
                patch: 0,
            },
            version_present: false,
            stored_digest: [0; 32],
            digest_present: false,
            bootable: false,
            trusted: false,
        }
    }
}

impl AuditEvent {
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sequence_id: u32,
        event_class: AuditEventClass,
        event_code: AuditEventCode,
        device_revision: u32,
        lifecycle_state: DeviceState,
        actor_role: AuthorityRole,
        session_kind: SessionState,
        result_class: AuditResultClass,
        detail: &[u8],
    ) -> Self {
        let mut bounded_detail = Vec::<u8, MAX_AUDIT_DETAIL_LEN>::new();
        let copy_len = detail.len().min(MAX_AUDIT_DETAIL_LEN);
        let _ = bounded_detail.extend_from_slice(&detail[..copy_len]);
        let detail_len = u8::try_from(bounded_detail.len()).unwrap_or(0);
        let mut event = Self {
            sequence_id,
            event_class,
            event_code,
            device_revision,
            lifecycle_state,
            actor_role,
            session_kind,
            result_class,
            detail_len,
            detail: bounded_detail,
            integrity_tag: 0,
        };
        event.refresh_integrity();
        event
    }

    #[must_use]
    pub fn verify_integrity(&self) -> bool {
        self.integrity_tag == self.compute_integrity_tag()
    }

    pub fn refresh_integrity(&mut self) {
        self.integrity_tag = self.compute_integrity_tag();
    }

    fn compute_integrity_tag(&self) -> u32 {
        let mut tag = self.sequence_id.rotate_left(5)
            ^ (self.event_class as u32)
            ^ ((self.event_code as u32) << 8)
            ^ self.device_revision.rotate_left(11)
            ^ ((self.lifecycle_state as u32) << 16)
            ^ ((self.actor_role as u32) << 20)
            ^ ((self.session_kind as u32) << 24)
            ^ ((self.result_class as u32) << 28);
        for &byte in &self.detail {
            tag = tag.rotate_left(3) ^ u32::from(byte);
        }
        tag ^ 0x0a7d_17e1
    }
}

impl Default for AuditJournal {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditJournal {
    #[must_use]
    pub fn new() -> Self {
        Self {
            events: Vec::new(),
            next_sequence_id: 1,
            overflow_count: 0,
            corruption_detected: false,
            retrieval_locked: false,
        }
    }

    pub fn clear(&mut self) {
        self.events.clear();
        self.next_sequence_id = 1;
        self.overflow_count = 0;
        self.corruption_detected = false;
        self.retrieval_locked = false;
    }

    #[must_use]
    pub fn snapshot(&self) -> AuditStoreSnapshot {
        AuditStoreSnapshot {
            events: self.events.clone(),
            next_sequence_id: self.next_sequence_id,
            overflow_count: self.overflow_count,
            corruption_detected: self.corruption_detected,
            retrieval_locked: self.retrieval_locked,
        }
    }

    pub fn restore_snapshot(&mut self, snapshot: AuditStoreSnapshot) {
        self.events = snapshot.events;
        self.next_sequence_id = snapshot.next_sequence_id;
        self.overflow_count = snapshot.overflow_count;
        self.corruption_detected = snapshot.corruption_detected;
        self.retrieval_locked = snapshot.retrieval_locked;
    }

    pub fn reconcile_after_boot(&mut self) {
        let mut previous = None;
        self.corruption_detected = false;
        for event in &self.events {
            if !event.verify_integrity() {
                self.corruption_detected = true;
                self.retrieval_locked = true;
                return;
            }
            if let Some(prev) = previous
                && event.sequence_id <= prev
            {
                self.corruption_detected = true;
                self.retrieval_locked = true;
                return;
            }
            previous = Some(event.sequence_id);
        }
        self.retrieval_locked = self.corruption_detected;
        if let Some(last) = self.events.last() {
            self.next_sequence_id = last.sequence_id.saturating_add(1);
        } else {
            self.next_sequence_id = 1;
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &mut self,
        event_class: AuditEventClass,
        event_code: AuditEventCode,
        device_revision: u32,
        lifecycle_state: DeviceState,
        actor_role: AuthorityRole,
        session_kind: SessionState,
        result_class: AuditResultClass,
        detail: &[u8],
    ) {
        let event = AuditEvent::new(
            self.next_sequence_id,
            event_class,
            event_code,
            device_revision,
            lifecycle_state,
            actor_role,
            session_kind,
            result_class,
            detail,
        );
        self.next_sequence_id = self.next_sequence_id.saturating_add(1);
        if self.events.len() == MAX_AUDIT_EVENTS {
            let _ = self.events.remove(0);
            self.overflow_count = self.overflow_count.saturating_add(1);
        }
        let _ = self.events.push(event);
    }

    #[must_use]
    pub fn store_state(&self) -> AuditStoreState {
        if self.retrieval_locked {
            AuditStoreState::Locked
        } else if self.corruption_detected {
            AuditStoreState::Degraded
        } else if self.events.is_empty() {
            AuditStoreState::Empty
        } else if self.events.len() == MAX_AUDIT_EVENTS {
            AuditStoreState::Full
        } else {
            AuditStoreState::Ready
        }
    }

    #[must_use]
    pub fn events_retained(&self) -> u16 {
        u16::try_from(self.events.len()).unwrap_or(0)
    }

    #[must_use]
    pub fn overflow_detected(&self) -> bool {
        self.overflow_count != 0
    }

    /// # Errors
    ///
    /// Returns `StatusCode::StateError` when retrieval is locked because the
    /// retained audit history can no longer be trusted.
    pub fn page(
        &self,
        start_sequence: u32,
        max_events: u8,
    ) -> Result<(Vec<AuditEvent, MAX_AUDIT_PAGE_EVENTS>, AuditRetrievalCursor), StatusCode> {
        if self.retrieval_locked {
            return Err(StatusCode::StateError);
        }
        let bounded_max = usize::from(max_events.clamp(1, u8::try_from(MAX_AUDIT_PAGE_EVENTS).unwrap_or(1)));
        let mut page = Vec::<AuditEvent, MAX_AUDIT_PAGE_EVENTS>::new();
        let mut next_sequence = None;
        let mut started = false;
        for event in &self.events {
            if !started {
                if start_sequence == 0 || event.sequence_id >= start_sequence {
                    started = true;
                } else {
                    continue;
                }
            }
            if page.len() < bounded_max {
                let _ = page.push(event.clone());
            } else {
                next_sequence = Some(event.sequence_id);
                break;
            }
        }
        let cursor = AuditRetrievalCursor {
            start_sequence,
            max_events: u8::try_from(bounded_max).unwrap_or(1),
            next_sequence,
            truncated: next_sequence.is_some(),
        };
        Ok((page, cursor))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvisioningRecord {
    pub record_version: u8,
    pub lifecycle_state: LifecycleState,
    pub pending_transition: Option<TransitionIntent>,
    pub owner_binding: OwnerBinding,
    pub recovery_policy: RecoveryPolicy,
    pub revision_counter: u32,
    pub integrity_tag: u32,
    next_transition_id: u32,
}

impl ProvisioningRecord {
    #[must_use]
    pub fn new(state: DeviceState) -> Self {
        let mut record = Self {
            record_version: RECORD_VERSION,
            lifecycle_state: LifecycleState {
                state_code: state,
                entered_revision: 0,
            },
            pending_transition: None,
            owner_binding: OwnerBinding::default(),
            recovery_policy: RecoveryPolicy::default(),
            revision_counter: 0,
            integrity_tag: 0,
            next_transition_id: 1,
        };
        record.refresh_integrity();
        record
    }

    #[must_use]
    pub fn status(&self) -> LifecycleStatus {
        LifecycleStatus {
            state: self.lifecycle_state.state_code,
            owner_present: !self.owner_binding.is_empty(),
            recovery_required: self.lifecycle_state.state_code.recovery_required(),
            pending_transition_present: self.pending_transition.is_some(),
        }
    }

    #[must_use]
    pub fn current_state(&self) -> DeviceState {
        self.lifecycle_state.state_code
    }

    #[must_use]
    pub fn revision_counter(&self) -> u32 {
        self.revision_counter
    }

    #[must_use]
    pub fn verify_integrity(&self) -> bool {
        self.integrity_tag == self.compute_integrity_tag()
    }

    #[must_use]
    pub fn snapshot(&self) -> ProvisioningSnapshot {
        ProvisioningSnapshot {
            record_version: self.record_version,
            lifecycle_state: self.lifecycle_state,
            pending_transition: self.pending_transition.clone(),
            owner_binding: self.owner_binding.clone(),
            recovery_policy: self.recovery_policy,
            revision_counter: self.revision_counter,
            integrity_tag: self.integrity_tag,
            next_transition_id: self.next_transition_id,
        }
    }

    pub fn restore_snapshot(&mut self, snapshot: ProvisioningSnapshot) {
        self.record_version = snapshot.record_version;
        self.lifecycle_state = snapshot.lifecycle_state;
        self.pending_transition = snapshot.pending_transition;
        self.owner_binding = snapshot.owner_binding;
        self.recovery_policy = snapshot.recovery_policy;
        self.revision_counter = snapshot.revision_counter;
        self.integrity_tag = snapshot.integrity_tag;
        self.next_transition_id = snapshot.next_transition_id;
    }

    pub fn reconcile_after_boot(&mut self) {
        if !self.verify_integrity() {
            self.pending_transition = None;
            self.lifecycle_state.state_code = DeviceState::Recovery;
            self.owner_binding.clear();
            self.commit_state(DeviceState::Recovery);
            return;
        }

        let Some(pending) = self.pending_transition.take() else {
            return;
        };

        let fallback = match pending.target_state {
            DeviceState::Operational => DeviceState::Provisioned,
            _ => DeviceState::Recovery,
        };
        Self::clear_transition_snapshot(&pending);
        self.commit_state(fallback);
    }

    /// # Errors
    ///
    /// Returns `StatusCode::ValidationError` for invalid owner identifiers,
    /// `StatusCode::StateError` for invalid source state, and
    /// `StatusCode::InternalError` if the bounded transition record cannot be
    /// constructed.
    pub fn begin_provisioning(
        &mut self,
        owner_id: &[u8],
        command_code: u8,
    ) -> Result<TransitionResult, StatusCode> {
        if !matches!(
            self.lifecycle_state.state_code,
            DeviceState::Factory | DeviceState::Zeroized
        ) {
            return Err(StatusCode::StateError);
        }

        if owner_id.is_empty() || owner_id.len() > MAX_OWNER_ID_LEN {
            return Err(StatusCode::ValidationError);
        }

        let mut owner_binding = OwnerBinding::default();
        owner_binding
            .owner_id
            .extend_from_slice(owner_id)
            .map_err(|()| StatusCode::ValidationError)?;
        owner_binding.provisioning_epoch = self.revision_counter.saturating_add(1);
        owner_binding.authorization_mode = AuthorizationMode::BootstrapProof;
        owner_binding.transfer_allowed = false;
        owner_binding.binding_digest = hash_owner_id(owner_id);
        self.owner_binding = owner_binding;

        let transition_id = self.next_transition_id();
        let Some(intent) = TransitionIntent::new(
            transition_id,
            TransitionType::Activation,
            DeviceState::Provisioned,
            DeviceState::Operational,
            command_code,
            owner_id,
            self.revision_counter.saturating_add(1),
        ) else {
            return Err(StatusCode::InternalError);
        };

        self.pending_transition = Some(intent);
        self.commit_state(DeviceState::Provisioned);
        Ok(TransitionResult {
            state: self.lifecycle_state.state_code,
            transition_id,
            revision_counter: self.revision_counter,
        })
    }

    /// # Errors
    ///
    /// Returns `StatusCode::StateError` when the device is not in the
    /// provisioned state and `StatusCode::ReplayError` when the transition
    /// identifier does not match the pending activation.
    pub fn finalize_provisioning(
        &mut self,
        transition_id: u32,
    ) -> Result<StateRevision, StatusCode> {
        if self.lifecycle_state.state_code != DeviceState::Provisioned {
            return Err(StatusCode::StateError);
        }

        let Some(pending) = self.pending_transition.take() else {
            return Err(StatusCode::StateError);
        };

        if pending.transition_id != transition_id {
            self.pending_transition = Some(pending);
            return Err(StatusCode::ReplayError);
        }

        if pending.target_state != DeviceState::Operational {
            self.pending_transition = Some(pending);
            return Err(StatusCode::StateError);
        }

        Self::clear_transition_snapshot(&pending);
        self.commit_state(DeviceState::Operational);
        Ok(StateRevision {
            state: self.lifecycle_state.state_code,
            revision_counter: self.revision_counter,
        })
    }

    /// # Errors
    ///
    /// Returns `StatusCode::StateError` when the device is not operational.
    pub fn lock_device(&mut self, reason_code: u8) -> Result<LockResult, StatusCode> {
        if self.lifecycle_state.state_code != DeviceState::Operational {
            return Err(StatusCode::StateError);
        }

        self.commit_state(DeviceState::Locked);
        Ok(LockResult {
            state: self.lifecycle_state.state_code,
            reason_code,
        })
    }

    /// # Errors
    ///
    /// Returns `StatusCode::StateError` when the device is not locked.
    pub fn unlock_device(&mut self) -> Result<StateRevision, StatusCode> {
        if self.lifecycle_state.state_code != DeviceState::Locked {
            return Err(StatusCode::StateError);
        }

        self.commit_state(DeviceState::Operational);
        Ok(StateRevision {
            state: self.lifecycle_state.state_code,
            revision_counter: self.revision_counter,
        })
    }

    /// # Errors
    ///
    /// Returns `StatusCode::StateError` when recovery is requested from the
    /// wrong state or recovery has been disabled.
    pub fn enter_recovery(&mut self) -> Result<RecoveryResult, StatusCode> {
        if self.lifecycle_state.state_code != DeviceState::Locked {
            return Err(StatusCode::StateError);
        }

        if !self.recovery_policy.recovery_enabled {
            return Err(StatusCode::StateError);
        }

        self.commit_state(DeviceState::Recovery);
        Ok(RecoveryResult {
            state: self.lifecycle_state.state_code,
            recovery_required: true,
        })
    }

    /// # Errors
    ///
    /// Returns `StatusCode::StateError` when the device is not in recovery.
    pub fn recover_to_provisioned(&mut self) -> Result<TransitionResult, StatusCode> {
        if self.lifecycle_state.state_code != DeviceState::Recovery {
            return Err(StatusCode::StateError);
        }

        let transition_id = self.next_transition_id();
        let Some(intent) = TransitionIntent::new(
            transition_id,
            TransitionType::ReactivateRecoveredProvisioning,
            DeviceState::Provisioned,
            DeviceState::Operational,
            0x86,
            &[REACTIVATE_MARKER],
            self.revision_counter.saturating_add(1),
        ) else {
            return Err(StatusCode::InternalError);
        };

        self.pending_transition = Some(intent);
        self.commit_state(DeviceState::Provisioned);
        Ok(TransitionResult {
            state: self.lifecycle_state.state_code,
            transition_id,
            revision_counter: self.revision_counter,
        })
    }

    /// # Errors
    ///
    /// Returns `StatusCode::StateError` when the device is not in the
    /// recovery-originated provisioned state and `StatusCode::ReplayError`
    /// when the transition identifier does not match the pending reactivation.
    pub fn reactivate_recovered_provisioning(
        &mut self,
        transition_id: u32,
    ) -> Result<StateRevision, StatusCode> {
        if self.lifecycle_state.state_code != DeviceState::Provisioned {
            return Err(StatusCode::StateError);
        }

        let Some(pending) = self.pending_transition.take() else {
            return Err(StatusCode::StateError);
        };

        if pending.transition_id != transition_id {
            self.pending_transition = Some(pending);
            return Err(StatusCode::ReplayError);
        }

        if pending.transition_type != TransitionType::ReactivateRecoveredProvisioning
            || pending.target_state != DeviceState::Operational
        {
            self.pending_transition = Some(pending);
            return Err(StatusCode::StateError);
        }

        Self::clear_transition_snapshot(&pending);
        self.commit_state(DeviceState::Operational);
        Ok(StateRevision {
            state: self.lifecycle_state.state_code,
            revision_counter: self.revision_counter,
        })
    }

    /// # Errors
    ///
    /// Returns `StatusCode::StateError` when zeroize is requested from a state
    /// where destructive reset is not allowed.
    pub fn execute_zeroize(&mut self) -> Result<ZeroizeOutcome, StatusCode> {
        if !matches!(
            self.lifecycle_state.state_code,
            DeviceState::Provisioned | DeviceState::Operational | DeviceState::Recovery
        ) {
            return Err(StatusCode::StateError);
        }

        self.clear_pending_transition();
        self.owner_binding.clear();
        self.commit_state(DeviceState::Zeroized);
        Ok(ZeroizeOutcome {
            result_state: self.lifecycle_state.state_code,
            owner_binding_cleared: self.owner_binding.is_empty(),
            secret_storage_cleared: true,
            transient_buffers_cleared: true,
            requires_reprovisioning: true,
        })
    }

    pub fn developer_reset(&mut self) -> DeveloperResetOutcome {
        self.clear_pending_transition();
        self.owner_binding.clear();
        self.commit_state(DeviceState::Factory);
        DeveloperResetOutcome {
            result_state: self.lifecycle_state.state_code,
            owner_binding_cleared: self.owner_binding.is_empty(),
            pending_transition_cleared: self.pending_transition.is_none(),
            transient_buffers_cleared: true,
        }
    }

    fn next_transition_id(&mut self) -> u32 {
        let id = self.next_transition_id;
        self.next_transition_id = self.next_transition_id.saturating_add(1);
        id
    }

    fn clear_pending_transition(&mut self) {
        if let Some(mut pending) = self.pending_transition.take() {
            pending.clear();
        }
    }

    fn clear_transition_snapshot(pending: &TransitionIntent) {
        let mut cleared = pending.clone();
        cleared.clear();
    }

    fn commit_state(&mut self, state: DeviceState) {
        self.revision_counter = self.revision_counter.saturating_add(1);
        self.lifecycle_state.state_code = state;
        self.lifecycle_state.entered_revision = self.revision_counter;
        self.refresh_integrity();
    }

    fn refresh_integrity(&mut self) {
        self.integrity_tag = self.compute_integrity_tag();
    }

    fn compute_integrity_tag(&self) -> u32 {
        let mut tag = u32::from(self.record_version)
            ^ (self.lifecycle_state.state_code as u32)
            ^ self.revision_counter.rotate_left(7)
            ^ self.next_transition_id.rotate_left(3);
        tag ^= self.owner_binding.binding_digest.rotate_left(11);
        tag ^= u32::from(self.owner_binding.authorization_mode as u8) << 16;
        if let Some(pending) = &self.pending_transition {
            tag ^= pending.transition_id.rotate_left(5);
            tag ^= u32::from(pending.command_code);
            tag ^= pending.target_state as u32;
        }
        tag
    }
}

impl PersistentKeyStore {
    #[must_use]
    pub fn new(device_revision: u32) -> Self {
        Self {
            journal: Vec::new(),
            anchor: FreshnessAnchor::new(device_revision),
            store_state: KeyStoreState::Empty,
            rollback_detected: false,
            corruption_detected: false,
            current_device_revision: device_revision,
        }
    }

    pub fn sync_device_revision(&mut self, device_revision: u32) {
        self.current_device_revision = device_revision;
        if self.journal.is_empty() && self.store_state != KeyStoreState::RecoveryRequired {
            self.anchor.accepted_device_revision = device_revision;
            self.anchor.refresh_integrity();
        }
    }

    pub fn clear_all(&mut self) {
        for record in &mut self.journal {
            record.invalidate_material();
        }
        self.journal.clear();
        self.anchor = FreshnessAnchor::new(self.current_device_revision);
        self.store_state = KeyStoreState::Empty;
        self.rollback_detected = false;
        self.corruption_detected = false;
    }

    pub fn restore_snapshot(&mut self, snapshot: KeyStoreSnapshot) {
        self.journal = snapshot.journal;
        self.anchor = snapshot.anchor;
    }

    #[must_use]
    pub fn snapshot(&self) -> KeyStoreSnapshot {
        KeyStoreSnapshot {
            journal: self.journal.clone(),
            anchor: self.anchor,
        }
    }

    pub fn reconcile_after_boot(&mut self) {
        self.rollback_detected = false;
        self.corruption_detected = false;

        if self.journal.is_empty() {
            self.store_state = KeyStoreState::Empty;
            self.anchor.accepted_device_revision = self.current_device_revision;
            self.anchor.refresh_integrity();
            return;
        }

        if !self.anchor.verify_integrity() {
            self.corruption_detected = true;
            self.store_state = KeyStoreState::RecoveryRequired;
            return;
        }

        let mut highest_epoch = 0;
        let mut seen = [None::<(u32, u32)>; MAX_PERSISTENT_KEYS];
        for record in &self.journal {
            if !record.verify_integrity() {
                self.corruption_detected = true;
                continue;
            }

            if record.store_epoch > highest_epoch {
                highest_epoch = record.store_epoch;
            }

            if record.key_id == 0 || usize::from(record.key_id) > MAX_PERSISTENT_KEYS {
                self.corruption_detected = true;
                continue;
            }
            let slot = usize::from(record.key_id - 1);

            if let Some((revision, tag)) = seen[slot]
                && revision == record.record_revision
                && tag != record.integrity_tag
            {
                self.corruption_detected = true;
            } else {
                seen[slot] = Some((record.record_revision, record.integrity_tag));
            }
        }

        if highest_epoch > self.anchor.accepted_store_epoch
            || self.anchor.accepted_device_revision < self.current_device_revision
        {
            self.rollback_detected = true;
        }

        self.refresh_store_state();
    }

    #[must_use]
    pub fn status(&self) -> KeyStoreStatus {
        let key_count = u8::try_from(self.active_key_count()).unwrap_or(0);
        let free_slots = u8::try_from(MAX_PERSISTENT_KEYS.saturating_sub(self.live_record_count()))
            .unwrap_or(0);
        KeyStoreStatus {
            store_state: self.store_state,
            key_count,
            free_slots,
            rollback_detected: self.rollback_detected,
            corruption_detected: self.corruption_detected,
        }
    }

    /// # Errors
    ///
    /// Returns `StatusCode::ValidationError` for malformed metadata or
    /// material and `StatusCode::StateError` when the store is full or not
    /// ready to accept writes.
    pub fn put_persistent_key(
        &mut self,
        request: &PutPersistentKeyRequest,
    ) -> Result<KeyRecordResult, StatusCode> {
        self.ensure_ready_for_write()?;
        Self::validate_put_request(request)?;

        if self.find_latest_record(request.key_id).is_some() {
            return Err(StatusCode::StateError);
        }

        let slot_id = self.next_slot_id()?;
        let store_epoch = self.anchor.accepted_store_epoch.saturating_add(1);
        let record_revision = 1;
        let metadata = KeyMetadata {
            algorithm: request.algorithm,
            origin: request.origin,
            usage_mask: request.usage_mask,
            export_policy: request.export_policy,
            created_revision: self.anchor.store_revision.saturating_add(1),
            last_state_change_revision: self.anchor.store_revision.saturating_add(1),
        };
        let mut record = KeyStoreRecord::new(
            slot_id,
            request.key_id,
            record_revision,
            store_epoch,
            KeyLifecycleState::Active,
            metadata,
            request.material.clone(),
        );
        record.refresh_integrity();
        self.push_record(record)?;
        self.commit_anchor(store_epoch);

        Ok(KeyRecordResult {
            key_id: request.key_id,
            lifecycle_state: KeyLifecycleState::Active,
            record_revision,
            store_revision: self.anchor.store_revision,
        })
    }

    /// # Errors
    ///
    /// Returns `StatusCode::StateError` when the store is non-ready or the key
    /// cannot transition to revoked.
    pub fn revoke_key(&mut self, key_id: u8) -> Result<KeyRecordResult, StatusCode> {
        self.ensure_ready_for_write()?;
        let latest = self.latest_live_record(key_id)?;
        if latest.lifecycle_state != KeyLifecycleState::Active {
            return Err(StatusCode::StateError);
        }

        let store_epoch = self.anchor.accepted_store_epoch.saturating_add(1);
        let record_revision = latest.record_revision.saturating_add(1);
        let mut metadata = latest.metadata.clone();
        metadata.last_state_change_revision = self.anchor.store_revision.saturating_add(1);
        let record = KeyStoreRecord::new(
            self.next_slot_id()?,
            key_id,
            record_revision,
            store_epoch,
            KeyLifecycleState::Revoked,
            metadata,
            latest.material.clone(),
        );
        self.push_record(record)?;
        self.commit_anchor(store_epoch);

        Ok(KeyRecordResult {
            key_id,
            lifecycle_state: KeyLifecycleState::Revoked,
            record_revision,
            store_revision: self.anchor.store_revision,
        })
    }

    /// # Errors
    ///
    /// Returns `StatusCode::StateError` when the key cannot transition to a
    /// destroyed state.
    pub fn destroy_key(&mut self, key_id: u8) -> Result<KeyDestroyResult, StatusCode> {
        self.ensure_ready_for_write()?;
        let latest = self.latest_live_record(key_id)?;
        if matches!(latest.lifecycle_state, KeyLifecycleState::Destroyed | KeyLifecycleState::PendingDestroy) {
            return Err(StatusCode::StateError);
        }

        let store_epoch = self.anchor.accepted_store_epoch.saturating_add(1);
        let record_revision = latest.record_revision.saturating_add(1);
        let mut metadata = latest.metadata.clone();
        metadata.last_state_change_revision = self.anchor.store_revision.saturating_add(1);
        let mut material = latest.material.clone();
        material.clear();
        let record = KeyStoreRecord::new(
            self.next_slot_id()?,
            key_id,
            record_revision,
            store_epoch,
            KeyLifecycleState::Destroyed,
            metadata,
            material,
        );
        self.push_record(record)?;
        self.commit_anchor(store_epoch);

        Ok(KeyDestroyResult {
            key_id,
            lifecycle_state: KeyLifecycleState::Destroyed,
            material_cleared: true,
            tombstone_committed: true,
        })
    }

    /// # Errors
    ///
    /// Returns `StatusCode::StateError` when the store is non-ready or the key
    /// is unavailable.
    pub fn get_key_metadata(&self, key_id: u8) -> Result<KeyMetadataView, StatusCode> {
        self.ensure_ready_for_read()?;
        let record = self.latest_live_record(key_id)?;
        Ok(KeyMetadataView {
            key_id,
            algorithm: record.metadata.algorithm,
            origin: record.metadata.origin,
            usage_mask: record.metadata.usage_mask,
            export_policy: record.metadata.export_policy,
            lifecycle_state: record.lifecycle_state,
            record_revision: record.record_revision,
        })
    }

    /// # Errors
    ///
    /// Returns `StatusCode::StateError` when the store is non-ready.
    pub fn list_keys(&self) -> Result<Vec<KeyListEntry, MAX_KEY_LIST_ENTRIES>, StatusCode> {
        self.ensure_ready_for_read()?;
        let mut entries = Vec::new();
        for key_id in 1..=MAX_PERSISTENT_KEYS {
            if let Some(record) = self.find_latest_record(u8::try_from(key_id).unwrap_or(0)) {
                let _ = entries.push(KeyListEntry {
                    key_id: record.key_id,
                    algorithm: record.metadata.algorithm,
                    lifecycle_state: record.lifecycle_state,
                    usage_mask: record.metadata.usage_mask,
                    export_policy: record.metadata.export_policy,
                });
            }
        }
        Ok(entries)
    }

    /// # Errors
    ///
    /// Returns `StatusCode::StateError` when the key is not active or the store
    /// is not ready, and `StatusCode::AuthorizationError` when export is
    /// disallowed.
    pub fn assert_key_operation(
        &self,
        key_id: u8,
        usage_mask: u8,
        export_requested: bool,
    ) -> Result<(), StatusCode> {
        self.ensure_ready_for_read()?;
        let record = self.latest_live_record(key_id)?;
        if record.lifecycle_state != KeyLifecycleState::Active {
            return Err(StatusCode::StateError);
        }

        if record.metadata.usage_mask & usage_mask == 0 {
            return Err(StatusCode::AuthorizationError);
        }

        if export_requested && record.metadata.export_policy == ExportPolicy::NonExportable {
            return Err(StatusCode::AuthorizationError);
        }

        Ok(())
    }

    /// # Errors
    ///
    /// Returns `StatusCode::StateError` when the key is unavailable and
    /// `StatusCode::AuthorizationError` when algorithm or usage policy does not match.
    pub fn export_key_material_for_operation(
        &self,
        key_id: u8,
        required_algorithm: KeyAlgorithm,
        usage_mask: u8,
        export_requested: bool,
    ) -> Result<[u8; MAX_KEY_MATERIAL_LEN], StatusCode> {
        self.assert_key_operation(key_id, usage_mask, export_requested)?;
        let record = self.latest_live_record(key_id)?;
        if record.metadata.algorithm != required_algorithm {
            return Err(StatusCode::AuthorizationError);
        }
        if usize::from(record.material.material_len) != record.material.material_bytes.len()
            || record.material.material_len == 0
        {
            return Err(StatusCode::StateError);
        }

        let mut material = [0u8; MAX_KEY_MATERIAL_LEN];
        let material_len = usize::from(record.material.material_len);
        material[..material_len].copy_from_slice(record.material.material_bytes.as_slice());
        Ok(material)
    }

    /// # Errors
    ///
    /// Returns `StatusCode::StateError` when no destination slot remains or the
    /// store is not ready for write.
    pub fn import_wrapped_key(
        &mut self,
        algorithm: KeyAlgorithm,
        usage_mask: u8,
        export_policy: ExportPolicy,
        plaintext_key: &[u8],
    ) -> Result<KeyRecordResult, StatusCode> {
        self.ensure_ready_for_write()?;
        let key_id = self.next_import_key_id()?;
        let material = KeyMaterialEnvelope::try_from_bytes(KeyOrigin::Imported, plaintext_key)
            .ok_or(StatusCode::ValidationError)?;
        let request = PutPersistentKeyRequest {
            key_id,
            algorithm,
            origin: KeyOrigin::Imported,
            usage_mask,
            export_policy,
            material,
        };
        self.put_persistent_key(&request)
    }

    fn validate_put_request(request: &PutPersistentKeyRequest) -> Result<(), StatusCode> {
        if request.key_id == 0 {
            return Err(StatusCode::ValidationError);
        }
        if request.usage_mask == 0 || request.material.material_len == 0 {
            return Err(StatusCode::ValidationError);
        }
        Ok(())
    }

    fn latest_live_record(&self, key_id: u8) -> Result<&KeyStoreRecord, StatusCode> {
        self.find_latest_record(key_id).ok_or(StatusCode::StateError)
    }

    fn find_latest_record(&self, key_id: u8) -> Option<&KeyStoreRecord> {
        self.journal
            .iter()
            .filter(|record| record.key_id == key_id && record.verify_integrity())
            .max_by_key(|record| (record.record_revision, record.store_epoch))
    }

    fn next_slot_id(&self) -> Result<u8, StatusCode> {
        if self.live_record_count() >= MAX_PERSISTENT_KEYS {
            return Err(StatusCode::StateError);
        }
        u8::try_from(self.journal.len()).map_err(|_| StatusCode::StateError)
    }

    fn next_import_key_id(&self) -> Result<u8, StatusCode> {
        for key_id in 1..=u8::try_from(MAX_PERSISTENT_KEYS).unwrap_or(0) {
            match self.find_latest_record(key_id) {
                None => return Ok(key_id),
                Some(record) if record.lifecycle_state == KeyLifecycleState::Destroyed => {
                    return Ok(key_id)
                }
                Some(_) => {}
            }
        }
        Err(StatusCode::StateError)
    }

    fn push_record(&mut self, record: KeyStoreRecord) -> Result<(), StatusCode> {
        self.journal.push(record).map_err(|_| StatusCode::StateError)
    }

    fn commit_anchor(&mut self, store_epoch: u32) {
        self.anchor.accepted_store_epoch = store_epoch;
        self.anchor.accepted_device_revision = self.current_device_revision;
        self.anchor.store_revision = self.anchor.store_revision.saturating_add(1);
        self.anchor.refresh_integrity();
        self.rollback_detected = false;
        self.corruption_detected = false;
        self.refresh_store_state();
    }

    fn ensure_ready_for_write(&self) -> Result<(), StatusCode> {
        if matches!(self.store_state, KeyStoreState::Degraded | KeyStoreState::RecoveryRequired) {
            return Err(StatusCode::StateError);
        }
        Ok(())
    }

    fn ensure_ready_for_read(&self) -> Result<(), StatusCode> {
        if !matches!(
            self.store_state,
            KeyStoreState::Ready | KeyStoreState::Empty | KeyStoreState::Full
        ) {
            return Err(StatusCode::StateError);
        }
        Ok(())
    }

    fn active_key_count(&self) -> usize {
        let mut count = 0;
        for key_id in 1..=MAX_PERSISTENT_KEYS {
            let key_id = u8::try_from(key_id).unwrap_or(0);
            if self
                .find_latest_record(key_id)
                .is_some_and(|record| record.lifecycle_state != KeyLifecycleState::Destroyed)
            {
                count += 1;
            }
        }
        count
    }

    fn live_record_count(&self) -> usize {
        self.active_key_count()
    }

    fn refresh_store_state(&mut self) {
        if self.rollback_detected {
            self.store_state = KeyStoreState::RecoveryRequired;
            return;
        }
        if self.corruption_detected {
            self.store_state = KeyStoreState::Degraded;
            return;
        }
        let live = self.live_record_count();
        self.store_state = if live == 0 {
            KeyStoreState::Empty
        } else if live >= MAX_PERSISTENT_KEYS {
            KeyStoreState::Full
        } else {
            KeyStoreState::Ready
        };
    }
}

impl CryptoRuntimeState {
    #[must_use]
    pub fn capabilities(&self) -> CryptoCapabilities {
        self.capabilities
    }

    pub fn restore_persistent_state(&mut self, state: CryptoPersistentState) {
        self.persistent = state;
    }

    #[must_use]
    pub fn persistent_state(&self) -> CryptoPersistentState {
        self.persistent
    }

    pub fn seed_rng(&mut self, seed: [u8; 32]) {
        self.rng_seed = seed;
        self.rng_counter = 0;
        self.rng_healthy = true;
    }

    pub fn set_rng_health(&mut self, healthy: bool) {
        self.rng_healthy = healthy;
    }

    /// # Errors
    ///
    /// Returns `StatusCode::StateError` when the RNG backend is marked unhealthy
    /// and `StatusCode::ValidationError` when the requested output size is out of range.
    pub fn generate_random_bytes(
        &mut self,
        requested_len: usize,
    ) -> Result<Vec<u8, MAX_RANDOM_OUTPUT_LEN>, StatusCode> {
        if requested_len == 0 || requested_len > MAX_RANDOM_OUTPUT_LEN {
            return Err(StatusCode::ValidationError);
        }
        if !self.rng_healthy {
            return Err(StatusCode::StateError);
        }

        let mut derived_seed = self.rng_seed;
        let counter = self.rng_counter.to_le_bytes();
        for (idx, byte) in counter.iter().enumerate() {
            derived_seed[idx] ^= *byte;
            derived_seed[idx + 8] ^= byte.rotate_left(1);
        }
        let mut rng = ChaCha8Rng::from_seed(derived_seed);
        let mut output = [0u8; MAX_RANDOM_OUTPUT_LEN];
        rng.fill_bytes(&mut output[..requested_len]);
        self.rng_counter = self.rng_counter.saturating_add(1);

        let mut bytes = Vec::<u8, MAX_RANDOM_OUTPUT_LEN>::new();
        bytes
            .extend_from_slice(&output[..requested_len])
            .map_err(|()| StatusCode::InternalError)?;
        clear_secret_array(&mut output);
        clear_secret_array(&mut derived_seed);
        Ok(bytes)
    }

    pub fn note_wrapped_import(&mut self, store_revision: u32) {
        self.persistent.wrapped_import_count = self.persistent.wrapped_import_count.saturating_add(1);
        self.persistent.last_wrapped_import_revision = store_revision;
    }
}

#[must_use]
pub fn ed25519_public_key_from_seed(seed: &[u8]) -> Option<[u8; ED25519_PUBLIC_KEY_LEN]> {
    if seed.len() != MAX_KEY_MATERIAL_LEN {
        return None;
    }
    let signing_key = ed25519_dalek::SigningKey::from_bytes(seed.try_into().ok()?);
    Some(signing_key.verifying_key().to_bytes())
}

pub fn clear_secret_array<const N: usize>(buffer: &mut [u8; N]) {
    for byte in buffer {
        *byte = 0;
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionTracker {
    pub last_request_fingerprint: Option<u32>,
}

impl SessionTracker {
    pub fn record(&mut self, fingerprint: u32) {
        self.last_request_fingerprint = Some(fingerprint);
    }
}

#[must_use]
pub fn fingerprint_frame(code: u8, payload: &[u8]) -> u32 {
    let mut hash = u32::from(code);
    for &byte in payload {
        hash = hash.rotate_left(5) ^ u32::from(byte);
    }
    hash
}

#[must_use]
pub const fn developer_mode_session() -> SessionState {
    SessionState::Developer
}

#[must_use]
pub const fn role_to_session_state(role: AuthorityRole) -> SessionState {
    match role {
        AuthorityRole::Public => SessionState::Unauthenticated,
        AuthorityRole::Bootstrap => SessionState::Bootstrap,
        AuthorityRole::Administrator => SessionState::Administrator,
        AuthorityRole::Recovery => SessionState::Recovery,
        AuthorityRole::Developer => SessionState::Developer,
        AuthorityRole::KeyManager => SessionState::KeyManager,
    }
}

#[must_use]
pub const fn role_to_authorization_mode(role: AuthorityRole) -> AuthorizationMode {
    match role {
        AuthorityRole::Public => AuthorizationMode::None,
        AuthorityRole::Bootstrap => AuthorizationMode::BootstrapProof,
        AuthorityRole::Administrator => AuthorizationMode::AdministratorProof,
        AuthorityRole::Recovery => AuthorizationMode::RecoveryProof,
        AuthorityRole::Developer => AuthorizationMode::DeveloperMode,
        AuthorityRole::KeyManager => AuthorizationMode::KeyManagerProof,
    }
}

#[must_use]
pub fn current_session_state(
    active_session: Option<SessionRecord>,
    developer_mode: bool,
) -> SessionState {
    if let Some(session) = active_session
        && session.state == SessionLifecycleState::Active
    {
        return role_to_session_state(session.role);
    }
    if developer_mode {
        SessionState::Developer
    } else {
        SessionState::Unauthenticated
    }
}

#[must_use]
pub fn current_session_status(
    active_session: Option<SessionRecord>,
    developer_mode: bool,
    current_tick: u32,
    failure_counters: &[AccessFailureCounter],
) -> SessionStatus {
    let (session_present, active_role, expires_in_ticks) =
        if let Some(session) = active_session.filter(|session| session.state == SessionLifecycleState::Active)
        {
            (
                true,
                session.role,
                u16::try_from(session.expires_at_tick.saturating_sub(current_tick))
                    .unwrap_or(u16::MAX),
            )
        } else {
            (
                false,
                if developer_mode {
                    AuthorityRole::Developer
                } else {
                    AuthorityRole::Public
                },
                0,
            )
        };

    let mut lockout_active = false;
    let mut lockout_role = AuthorityRole::Public;
    for counter in failure_counters {
        if current_tick < counter.locked_until_tick {
            lockout_active = true;
            lockout_role = counter.role;
            break;
        }
    }

    SessionStatus {
        session_present,
        active_role,
        expires_in_ticks,
        lockout_active,
        lockout_role,
    }
}

#[must_use]
pub fn issue_challenge_nonce(
    role: AuthorityRole,
    challenge_id: u32,
    revision: u32,
) -> Vec<u8, MAX_CHALLENGE_NONCE_LEN> {
    let mut nonce = Vec::<u8, MAX_CHALLENGE_NONCE_LEN>::new();
    let _ = nonce.push(role as u8);
    let _ = nonce.extend_from_slice(&challenge_id.to_le_bytes());
    let _ = nonce.extend_from_slice(&revision.to_le_bytes()[..3]);
    nonce
}

pub fn clear_challenge(challenge: &mut Option<AuthenticationChallenge>) {
    if let Some(challenge) = challenge.as_mut() {
        for byte in &mut challenge.nonce {
            *byte = 0;
        }
        challenge.nonce.clear();
    }
    *challenge = None;
}

pub fn clear_active_session(active_session: &mut Option<SessionRecord>) {
    *active_session = None;
}

pub fn clear_failure_counters(failure_counters: &mut Vec<AccessFailureCounter, MAX_FAILURE_COUNTERS>) {
    for counter in failure_counters {
        counter.consecutive_failures = 0;
        counter.locked_until_tick = 0;
    }
}

#[must_use]
pub fn find_credential(
    snapshot: &AuthSnapshot,
    role: AuthorityRole,
) -> Option<&CredentialRecord> {
    snapshot.credentials.iter().find(|credential| credential.role == role)
}

pub fn find_failure_counter_mut(
    snapshot: &mut AuthSnapshot,
    role: AuthorityRole,
) -> Option<&mut AccessFailureCounter> {
    snapshot
        .failure_counters
        .iter_mut()
        .find(|counter| counter.role == role)
}

pub fn record_auth_failure(
    snapshot: &mut AuthSnapshot,
    role: AuthorityRole,
    current_tick: u32,
) {
    let Some(max_failures) = snapshot
        .credentials
        .iter()
        .find(|credential| credential.role == role)
        .map(|credential| credential.max_failures)
    else {
        return;
    };
    let lockout_ticks = snapshot
        .credentials
        .iter()
        .find(|credential| credential.role == role)
        .map_or(0, |credential| credential.lockout_ticks);
    if let Some(counter) = find_failure_counter_mut(snapshot, role) {
        counter.consecutive_failures = counter.consecutive_failures.saturating_add(1);
        if counter.consecutive_failures >= max_failures {
            counter.locked_until_tick = current_tick.saturating_add(u32::from(lockout_ticks));
        }
    }
}

pub fn clear_auth_failures(snapshot: &mut AuthSnapshot, role: AuthorityRole) {
    if let Some(counter) = find_failure_counter_mut(snapshot, role) {
        counter.consecutive_failures = 0;
        counter.locked_until_tick = 0;
    }
}

#[must_use]
pub fn role_locked_out(snapshot: &AuthSnapshot, role: AuthorityRole, current_tick: u32) -> bool {
    snapshot
        .failure_counters
        .iter()
        .find(|counter| counter.role == role)
        .is_some_and(|counter| current_tick < counter.locked_until_tick)
}

#[must_use]
pub fn verify_marker_proof(
    credential: &CredentialRecord,
    proof_bytes: &[u8],
) -> bool {
    credential.verifier_bytes.as_slice() == proof_bytes
}


#[must_use]
pub fn is_allowed_transition(source: DeviceState, target: DeviceState) -> bool {
    matches!(
        (source, target),
        (DeviceState::Factory | DeviceState::Zeroized, DeviceState::Provisioned)
            | (DeviceState::Provisioned, DeviceState::Operational | DeviceState::Zeroized)
            | (DeviceState::Operational, DeviceState::Locked | DeviceState::Zeroized)
            | (DeviceState::Locked, DeviceState::Operational | DeviceState::Recovery)
            | (DeviceState::Recovery, DeviceState::Provisioned | DeviceState::Zeroized)
            | (_, DeviceState::Factory)
    )
}

/// # Errors
///
/// Returns a `StatusCode` when a command is not allowed in the current device
/// or session state.
pub fn ensure_command_allowed(
    definition: CommandDefinition,
    device_state: DeviceState,
    session_state: SessionState,
    developer_mode: bool,
) -> Result<(), StatusCode> {
    let decision = evaluate_command_policy(
        definition,
        device_state,
        session_state,
        developer_mode,
        PolicyProfile::default(),
    );
    if decision.decision {
        Ok(())
    } else {
        Err(status_for_denial_class(decision.denial_class))
    }
}

#[must_use]
pub fn evaluate_command_policy(
    definition: CommandDefinition,
    device_state: DeviceState,
    session_state: SessionState,
    developer_mode: bool,
    profile: PolicyProfile,
) -> PolicyDecision {
    if !definition.enabled {
        return PolicyDecision::deny(DenialClass::CommandUnavailable);
    }

    if definition.developer_only && !developer_mode {
        return PolicyDecision::deny(DenialClass::CommandUnavailable);
    }

    if !definition.allowed_device_states.contains(&device_state) {
        return PolicyDecision::deny(DenialClass::StateDenied);
    }

    let allowed = match definition.required_role {
        AuthorityRole::Public => true,
        AuthorityRole::Bootstrap => {
            matches!(session_state, SessionState::Bootstrap | SessionState::Developer)
        }
        AuthorityRole::Administrator => {
            matches!(session_state, SessionState::Administrator | SessionState::Developer)
                || (definition.id == CommandId::GetFirmwareUpdateStatus
                    && matches!(session_state, SessionState::Recovery))
        }
        AuthorityRole::Recovery => {
            matches!(session_state, SessionState::Recovery | SessionState::Developer)
        }
        AuthorityRole::Developer => developer_mode,
        AuthorityRole::KeyManager => {
            matches!(session_state, SessionState::KeyManager | SessionState::Developer)
        }
    };

    if !allowed {
        return PolicyDecision::deny(DenialClass::RoleDenied);
    }

    if definition.developer_only && !profile.developer_commands_visible && !developer_mode {
        return PolicyDecision::deny(DenialClass::CommandUnavailable);
    }

    PolicyDecision::allow()
}

#[must_use]
pub fn evaluate_key_policy(
    metadata: KeyMetadataView,
    required_algorithm: Option<KeyAlgorithm>,
    required_usage_mask: u8,
    export_requested: bool,
    allowed_lifecycle_states: &[KeyLifecycleState],
) -> PolicyDecision {
    if !allowed_lifecycle_states.contains(&metadata.lifecycle_state) {
        return PolicyDecision::deny(DenialClass::KeyPolicyDenied);
    }

    if required_usage_mask != 0 && metadata.usage_mask & required_usage_mask == 0 {
        return PolicyDecision::deny(DenialClass::KeyPolicyDenied);
    }

    if export_requested && metadata.export_policy == ExportPolicy::NonExportable {
        return PolicyDecision::deny(DenialClass::KeyPolicyDenied);
    }

    if let Some(required_algorithm) = required_algorithm
        && metadata.algorithm != required_algorithm
    {
        return PolicyDecision::deny(DenialClass::KeyPolicyDenied);
    }

    PolicyDecision::allow()
}

/// Returns whether a candidate firmware version satisfies the accepted-version floor
/// and monotonic update policy.
///
/// # Errors
///
/// Returns [`DenialClass::KeyPolicyDenied`] when the candidate is below the minimum
/// accepted version or does not advance beyond the current active version.
pub fn firmware_version_allowed(
    candidate: FirmwareVersion,
    accepted: AcceptedFirmwareState,
) -> Result<(), DenialClass> {
    if candidate < accepted.minimum_accepted_version {
        return Err(DenialClass::KeyPolicyDenied);
    }
    if candidate <= accepted.active_version {
        return Err(DenialClass::KeyPolicyDenied);
    }
    Ok(())
}

#[must_use]
pub fn default_boot_slots(
    accepted: AcceptedFirmwareState,
) -> [BootSlotMetadata; 2] {
    let mut active = BootSlotMetadata::new(accepted.active_slot, BootSlotState::ActiveTrusted);
    active.stored_version = accepted.active_version;
    active.version_present = true;
    active.bootable = true;
    active.trusted = true;
    let inactive = BootSlotMetadata::new(accepted.active_slot.other(), BootSlotState::Empty);
    if accepted.active_slot == BootSlotId::A {
        [active, inactive]
    } else {
        [inactive, active]
    }
}

#[must_use]
pub fn update_status_view(
    accepted: AcceptedFirmwareState,
    transfer: &UpdateTransferState,
    slots: &[BootSlotMetadata; 2],
    policy_revision: u32,
) -> FirmwareUpdateStatus {
    let staged_index = usize::from(accepted.active_slot == BootSlotId::A);
    FirmwareUpdateStatus {
        active_slot: accepted.active_slot,
        active_version: accepted.active_version,
        minimum_accepted_version: accepted.minimum_accepted_version,
        transfer_phase: transfer.phase,
        staged_slot_state: slots[staged_index].slot_state,
        recovery_required: accepted.recovery_required,
        last_update_result: accepted.last_update_result,
        policy_revision,
    }
}

pub fn reconcile_update_boot(
    accepted: &mut AcceptedFirmwareState,
    transfer: &mut UpdateTransferState,
    slots: &mut [BootSlotMetadata; 2],
    recovery: &mut RecoveryState,
) {
    match transfer.phase {
        UpdateTransferPhase::Empty | UpdateTransferPhase::Aborted => {}
        UpdateTransferPhase::ManifestAccepted
        | UpdateTransferPhase::Transferring
        | UpdateTransferPhase::Transferred
        | UpdateTransferPhase::Validating => {
            transfer.phase = UpdateTransferPhase::Aborted;
            transfer.session_id = 0;
            transfer.manifest = None;
            transfer.bytes_received = 0;
            transfer.expected_size = 0;
            transfer.staged_image.clear();
            let staged_index = usize::from(accepted.active_slot == BootSlotId::A);
            slots[staged_index].slot_state = BootSlotState::Invalid;
            slots[staged_index].bootable = false;
            slots[staged_index].trusted = false;
            accepted.last_update_result = UpdateResultClass::Interrupted;
            accepted.trusted_boot_state = TrustedBootState::ActiveTrusted;
        }
        UpdateTransferPhase::ActivationPending => {
            accepted.recovery_required = true;
            accepted.last_update_result = UpdateResultClass::Interrupted;
            accepted.trusted_boot_state = TrustedBootState::RecoveryRequired;
            recovery.reason = UpdateRecoveryReason::AmbiguousActivation;
            recovery.last_trusted_slot = accepted.active_slot;
            recovery.staged_slot = accepted.active_slot.other();
            recovery.staged_slot_present = true;
        }
    }
}

#[must_use]
pub const fn status_for_denial_class(denial_class: DenialClass) -> StatusCode {
    match denial_class {
        DenialClass::None => StatusCode::Success,
        DenialClass::CommandUnavailable => StatusCode::CommandError,
        DenialClass::StateDenied => StatusCode::StateError,
        DenialClass::RoleDenied
        | DenialClass::KeyPolicyDenied
        | DenialClass::ApprovalMissing
        | DenialClass::ApprovalStale => StatusCode::AuthorizationError,
        DenialClass::InternalPolicyError => StatusCode::InternalError,
    }
}

#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn new_approval_ticket(
    ticket_id: u32,
    approval_class: ProtectedActionClass,
    target_binding: ApprovalTargetBinding,
    target_id: u32,
    initiator_role: AuthorityRole,
    confirmer_role: AuthorityRole,
    initiator_session_id: u32,
    policy_revision: u32,
    device_revision: u32,
    current_tick: u32,
) -> ApprovalTicket {
    ApprovalTicket {
        ticket_id,
        approval_class,
        target_binding,
        target_id,
        initiator_role,
        confirmer_role,
        initiator_session_id,
        policy_revision,
        device_revision,
        expires_at_tick: current_tick.saturating_add(u32::from(APPROVAL_TICKET_EXPIRY_TICKS)),
        state: ApprovalTicketState::Pending,
    }
}

pub fn clear_approval_tickets(
    tickets: &mut Vec<ApprovalTicket, MAX_APPROVAL_TICKETS>,
) {
    tickets.clear();
}

pub fn invalidate_approval_tickets(
    tickets: &mut Vec<ApprovalTicket, MAX_APPROVAL_TICKETS>,
) {
    for ticket in tickets.iter_mut() {
        ticket.state = ApprovalTicketState::Invalidated;
    }
}

pub fn retain_active_approval_tickets(
    tickets: &mut Vec<ApprovalTicket, MAX_APPROVAL_TICKETS>,
) {
    let mut retained = Vec::<ApprovalTicket, MAX_APPROVAL_TICKETS>::new();
    for ticket in tickets.iter().copied() {
        if matches!(
            ticket.state,
            ApprovalTicketState::Pending | ApprovalTicketState::Confirmed
        ) {
            let _ = retained.push(ticket);
        }
    }
    *tickets = retained;
}

/// # Errors
///
/// Returns a `StatusCode` when a replay-sensitive command is repeated with the
/// same tracked fingerprint.
pub fn enforce_replay_policy(
    definition: CommandDefinition,
    tracker: &mut SessionTracker,
    fingerprint: u32,
) -> Result<(), StatusCode> {
    if definition.replay_policy == ReplayPolicy::SingleUse
        && tracker.last_request_fingerprint == Some(fingerprint)
    {
        return Err(StatusCode::ReplayError);
    }

    tracker.record(fingerprint);
    Ok(())
}

/// # Errors
///
/// Returns `StatusCode::ValidationError` when the owner identifier is empty or
/// exceeds the bounded storage length.
pub fn validate_owner_id(owner_id: &[u8]) -> Result<(), StatusCode> {
    if owner_id.is_empty() || owner_id.len() > MAX_OWNER_ID_LEN {
        return Err(StatusCode::ValidationError);
    }
    Ok(())
}

/// # Errors
///
/// Returns `StatusCode::ValidationError` when the expected one-byte marker is
/// not present.
pub fn expect_single_marker(payload: &[u8], marker: u8) -> Result<(), StatusCode> {
    if payload == [marker] {
        Ok(())
    } else {
        Err(StatusCode::ValidationError)
    }
}

/// # Errors
///
/// Returns `StatusCode::ValidationError` when the provided marker bytes do not
/// match the expected destructive confirmation token.
pub fn expect_marker_bytes(payload: &[u8], marker: &[u8]) -> Result<(), StatusCode> {
    if payload == marker {
        Ok(())
    } else {
        Err(StatusCode::ValidationError)
    }
}

#[must_use]
pub const fn finalize_marker() -> u8 {
    FINALIZE_MARKER
}

#[must_use]
pub const fn reactivate_marker() -> u8 {
    REACTIVATE_MARKER
}

#[must_use]
pub const fn revoke_marker() -> u8 {
    REVOKE_MARKER
}

#[must_use]
pub const fn unlock_marker() -> u8 {
    UNLOCK_MARKER
}

#[must_use]
pub const fn recovery_marker() -> u8 {
    RECOVERY_MARKER
}

#[must_use]
pub const fn zeroize_marker() -> [u8; 2] {
    ZEROIZE_MARKER
}

#[must_use]
pub const fn developer_reset_marker() -> [u8; 3] {
    DEVELOPER_RESET_MARKER
}

#[must_use]
pub fn hash_owner_id(owner_id: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5_u32;
    for &byte in owner_id {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}
