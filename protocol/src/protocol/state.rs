use heapless::Vec;

use super::codec::StatusCode;
use super::command::{CommandDefinition, ReplayPolicy};

pub const RECORD_VERSION: u8 = 1;
pub const MAX_OWNER_ID_LEN: usize = 16;
pub const MAX_AUTH_SNAPSHOT_LEN: usize = 16;
pub const ZEROIZE_COMPLETION_FLAGS: u8 = 0x0f;
pub const DEVELOPER_RESET_COMPLETION_FLAGS: u8 = 0x07;

const FINALIZE_MARKER: u8 = 0xa5;
const REACTIVATE_MARKER: u8 = 0xa6;
const UNLOCK_MARKER: u8 = 0x5a;
const RECOVERY_MARKER: u8 = 0xc3;
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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AuthorityRole {
    Public = 0x01,
    Bootstrap = 0x02,
    Administrator = 0x03,
    Recovery = 0x04,
    Developer = 0x05,
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
    pub fn verify_integrity(&self) -> bool {
        self.integrity_tag == self.compute_integrity_tag()
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
            if !(developer_mode && session_state == SessionState::Developer) {
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
