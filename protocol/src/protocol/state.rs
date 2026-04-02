use heapless::Vec;

use super::codec::StatusCode;
use super::command::{CommandDefinition, ReplayPolicy};

pub const RECORD_VERSION: u8 = 1;
pub const MAX_OWNER_ID_LEN: usize = 16;
pub const MAX_AUTH_SNAPSHOT_LEN: usize = 16;
pub const MAX_ROLE_VERIFIER_LEN: usize = 8;
pub const MAX_CHALLENGE_NONCE_LEN: usize = 8;
pub const MAX_FAILURE_COUNTERS: usize = 4;
pub const ZEROIZE_COMPLETION_FLAGS: u8 = 0x0f;
pub const DEVELOPER_RESET_COMPLETION_FLAGS: u8 = 0x07;
pub const MAX_PERSISTENT_KEYS: usize = 8;
pub const MAX_KEY_MATERIAL_LEN: usize = 24;
pub const MAX_KEY_LIST_ENTRIES: usize = MAX_PERSISTENT_KEYS;
pub const MAX_KEY_JOURNAL_RECORDS: usize = 24;

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
    if !definition.allowed_device_states.contains(&device_state) {
        return Err(StatusCode::StateError);
    }

    if definition.developer_only && !developer_mode {
        return Err(StatusCode::CommandError);
    }

    match definition.required_role {
        AuthorityRole::Public => {}
        AuthorityRole::Bootstrap => {
            if !matches!(session_state, SessionState::Bootstrap | SessionState::Developer) {
                return Err(StatusCode::AuthorizationError);
            }
        }
        AuthorityRole::Administrator => {
            if !matches!(session_state, SessionState::Administrator | SessionState::Developer) {
                return Err(StatusCode::AuthorizationError);
            }
        }
        AuthorityRole::Recovery => {
            if !matches!(session_state, SessionState::Recovery | SessionState::Developer) {
                return Err(StatusCode::AuthorizationError);
            }
        }
        AuthorityRole::Developer => {
            if !developer_mode {
                return Err(StatusCode::AuthorizationError);
            }
        }
        AuthorityRole::KeyManager => {
            if !matches!(
                session_state,
                SessionState::KeyManager
                    | SessionState::Administrator
                    | SessionState::Recovery
                    | SessionState::Developer
            ) {
                return Err(StatusCode::AuthorizationError);
            }
        }
    }

    if !definition.enabled {
        return Err(StatusCode::StateError);
    }

    Ok(())
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
