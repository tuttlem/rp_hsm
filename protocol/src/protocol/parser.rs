use aes_gcm::{
    Aes256Gcm,
    aead::{AeadInPlace as AesAeadInPlace, generic_array::GenericArray as AesGenericArray},
};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::generic_array::GenericArray,
};
use ed25519_dalek::{Signer, Verifier};
use hmac::{Hmac, Mac};
use hkdf::Hkdf;
use heapless::Vec;
use p256::ecdh::diffie_hellman;
use p256::ecdsa::{
    Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
};
use p256::{PublicKey as P256PublicKey, SecretKey as P256SecretKey};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

use super::codec::{
    DecodeError, StatusCode, clear_bytes, decode_audit_page_request,
    decode_authentication_role, decode_authorized_payload,
    decode_begin_firmware_update_request, decode_complete_authentication_request,
    decode_decrypt_request, decode_derive_request, decode_encrypt_request,
    decode_export_wrapped_key_request, decode_firmware_chunk_request, decode_frame,
    decode_generate_key_request, decode_import_wrapped_key_request, decode_key_id_request,
    decode_key_marker_request, decode_put_persistent_key_request, decode_random_request,
    decode_sign_request, decode_transition_request, decode_verify_mac_request,
    decode_verify_request, decode_mac_request,
    encode_algorithm_profiles_payload, encode_audit_page_payload, encode_auth_challenge_payload,
    encode_auth_session_payload, encode_crypto_capabilities_payload, encode_decrypt_response_payload,
    encode_developer_reset_payload, encode_device_status_payload, encode_encrypt_response_payload,
    encode_firmware_abort_payload, encode_firmware_activation_payload,
    encode_firmware_chunk_progress_payload, encode_firmware_finalize_payload,
    encode_firmware_recovery_payload, encode_firmware_update_begin_payload,
    encode_firmware_update_status_payload, encode_health_status_payload,
    encode_key_destroy_payload, encode_key_list_payload, encode_key_metadata_payload,
    encode_key_record_result_payload, encode_key_store_status_payload,
    encode_lifecycle_status_payload, encode_lock_result_payload, encode_policy_denial_payload,
    encode_policy_profile_payload, encode_random_payload, encode_recovery_result_payload,
    encode_session_status_payload, encode_signature_payload, encode_state_revision_payload,
    encode_wrapped_key_export_payload, encode_mac_payload, encode_derive_response_payload,
    encode_transition_result_payload, encode_verify_result_payload, encode_zeroize_payload,
    policy_status_response, protocol_version_response, status_response,
};
use super::command::{CommandId, get_visible_catalog, lookup_command};
use super::frame::{
    FLAG_INCLUDE_RESTRICTED, FLAG_REPLAY_SENSITIVE, MessageKind, PROTOCOL_VERSION, ProtocolFrame,
};
use super::state::{
    ApprovalTargetBinding, ApprovalTicket, ApprovalTicketState, AuditEventClass, AuditEventCode,
    AuditJournal, AuditResultClass, AuditStoreSnapshot, AuthSnapshot, AuthenticationChallenge,
    AuthorityRole, BootSlotId, BootSlotMetadata, BootSlotState, CryptoPersistentState,
    CryptoRuntimeState, DecryptResponse, DenialClass, DeviceState, EncryptResponse,
    FirmwareAbortResult, FirmwareActivationResult, FirmwareChunkProgress,
    FirmwareFinalizeResult, FirmwarePackageManifest, FirmwareRecoveryResult,
    FirmwareUpdateBeginResult, FirmwareVersion, KeyAlgorithm, KeyLifecycleState,
    PersistentKeyStore, PolicyProfile, ProtectedActionClass, ProvisioningRecord,
    ProvisioningSnapshot, RecoveryState, SessionLifecycleState, SessionRecord, SessionState,
    SessionTracker, TrustedBootState, UPDATE_MANIFEST_VERSION, X25519_ENVELOPE_HEADER_LEN,
    X25519_PUBLIC_KEY_LEN,
    UPDATE_SIGNATURE_ALGORITHM_ED25519, UpdateRecoveryReason, UpdateResultClass,
    UpdateTransferPhase, UpdateTransferState, USAGE_DECRYPT, USAGE_ENCRYPT, USAGE_SIGN,
    USAGE_WRAP_IMPORT, USAGE_DERIVE, USAGE_MAC,
    AcceptedFirmwareState, clear_active_session, default_boot_slots,
    clear_approval_tickets, clear_auth_failures, clear_challenge, clear_failure_counters,
    clear_secret_array, current_session_state, current_session_status, developer_mode_session,
    developer_reset_marker, ed25519_public_key_from_seed, enforce_replay_policy,
    evaluate_command_policy, evaluate_key_policy, expect_marker_bytes, expect_single_marker,
    finalize_marker, find_credential, fingerprint_frame, firmware_version_allowed,
    invalidate_approval_tickets, issue_challenge_nonce, new_approval_ticket, reactivate_marker,
    reconcile_update_boot, record_auth_failure, recovery_marker, retain_active_approval_tickets,
    revoke_marker, role_locked_out, role_to_authorization_mode, status_for_denial_class,
    unlock_marker, update_status_view, zeroize_marker, MAX_APPROVAL_TICKETS,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeveloperStoreFaultAction {
    CorruptPersistedStore = 0x01,
    RollbackPersistedStore = 0x02,
    CorruptPersistedAudit = 0x03,
    RollbackPersistedAudit = 0x04,
    AmbiguousFirmwareActivation = 0x05,
    RollbackFirmwareVersion = 0x06,
}

impl DeveloperStoreFaultAction {
    #[must_use]
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::CorruptPersistedStore),
            0x02 => Some(Self::RollbackPersistedStore),
            0x03 => Some(Self::CorruptPersistedAudit),
            0x04 => Some(Self::RollbackPersistedAudit),
            0x05 => Some(Self::AmbiguousFirmwareActivation),
            0x06 => Some(Self::RollbackFirmwareVersion),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FirmwareAction {
    DeveloperStoreFault(DeveloperStoreFaultAction),
    DeveloperReboot,
}

const UPDATE_TRUST_ANCHOR_SEED: &[u8; 32] = b"rp_hsm_update_anchor_seed_v1____";
const ASYMMETRIC_ENCRYPT_INFO: &[u8] = b"rp_hsm.asym_encrypt.v1";
const DERIVE_INFO_PREFIX: &[u8] = b"rp_hsm.derive.v1";
const WRAP_EXPORT_AAD: &[u8] = b"rp_hsm.wrap.v1";
type HmacSha256 = Hmac<Sha256>;

pub struct ProtocolEngine {
    record: ProvisioningRecord,
    key_store: PersistentKeyStore,
    auth_snapshot: AuthSnapshot,
    crypto_state: CryptoRuntimeState,
    audit_journal: AuditJournal,
    policy_profile: PolicyProfile,
    accepted_firmware: AcceptedFirmwareState,
    boot_slots: [BootSlotMetadata; 2],
    update_transfer: UpdateTransferState,
    recovery_state: RecoveryState,
    approval_tickets: Vec<ApprovalTicket, MAX_APPROVAL_TICKETS>,
    next_approval_ticket_id: u32,
    active_challenge: Option<AuthenticationChallenge>,
    active_session: Option<SessionRecord>,
    session_state: SessionState,
    session_tracker: SessionTracker,
    request_tick: u32,
    legacy_session_mode: bool,
    developer_mode: bool,
    pending_firmware_action: Option<FirmwareAction>,
}

impl ProtocolEngine {
    #[must_use]
    pub fn new(device_state: DeviceState, session_state: SessionState) -> Self {
        let record = ProvisioningRecord::new(device_state);
        Self {
            key_store: PersistentKeyStore::new(record.revision_counter()),
            record,
            auth_snapshot: AuthSnapshot::default(),
            crypto_state: CryptoRuntimeState::default(),
            audit_journal: AuditJournal::new(),
            policy_profile: PolicyProfile::default(),
            accepted_firmware: AcceptedFirmwareState::default(),
            boot_slots: default_boot_slots(AcceptedFirmwareState::default()),
            update_transfer: UpdateTransferState::default(),
            recovery_state: RecoveryState::default(),
            approval_tickets: Vec::new(),
            next_approval_ticket_id: 1,
            active_challenge: None,
            active_session: None,
            session_state,
            session_tracker: SessionTracker {
                last_request_fingerprint: None,
            },
            request_tick: 0,
            legacy_session_mode: matches!(
                session_state,
                SessionState::Bootstrap
                    | SessionState::Administrator
                    | SessionState::Recovery
                    | SessionState::KeyManager
            ),
            developer_mode: false,
            pending_firmware_action: None,
        }
    }

    #[must_use]
    pub fn new_developer_mode() -> Self {
        let mut engine = Self::new(DeviceState::Factory, developer_mode_session());
        engine.developer_mode = true;
        engine.policy_profile.developer_commands_visible = true;
        engine
    }

    pub fn set_device_state(&mut self, device_state: DeviceState) {
        self.record = ProvisioningRecord::new(device_state);
        self.key_store = PersistentKeyStore::new(self.record.revision_counter());
        clear_challenge(&mut self.active_challenge);
        clear_active_session(&mut self.active_session);
        clear_approval_tickets(&mut self.approval_tickets);
        self.refresh_session_state();
        self.pending_firmware_action = None;
    }

    pub fn set_session_state(&mut self, session_state: SessionState) {
        self.session_state = session_state;
        self.legacy_session_mode = matches!(
            session_state,
            SessionState::Bootstrap
                | SessionState::Administrator
                | SessionState::Recovery
                | SessionState::KeyManager
        );
    }

    pub fn set_developer_mode(&mut self, developer_mode: bool) {
        self.developer_mode = developer_mode;
        self.policy_profile.developer_commands_visible = developer_mode;
        self.refresh_session_state();
    }

    pub fn reconcile_boot(&mut self) {
        self.record.reconcile_after_boot();
        self.key_store
            .sync_device_revision(self.record.revision_counter());
        self.key_store.reconcile_after_boot();
        self.audit_journal.reconcile_after_boot();
        reconcile_update_boot(
            &mut self.accepted_firmware,
            &mut self.update_transfer,
            &mut self.boot_slots,
            &mut self.recovery_state,
        );
        if self.accepted_firmware.recovery_required && self.record.current_state() != DeviceState::Recovery {
            let mut snapshot = self.record.snapshot();
            snapshot.lifecycle_state.state_code = DeviceState::Recovery;
            self.record.restore_snapshot(snapshot);
        }
        invalidate_approval_tickets(&mut self.approval_tickets);
        retain_active_approval_tickets(&mut self.approval_tickets);
        clear_challenge(&mut self.active_challenge);
        clear_active_session(&mut self.active_session);
        self.session_tracker.last_request_fingerprint = None;
        self.refresh_session_state();
    }

    #[must_use]
    pub fn record(&self) -> &ProvisioningRecord {
        &self.record
    }

    #[must_use]
    pub fn provisioning_snapshot(&self) -> ProvisioningSnapshot {
        self.record.snapshot()
    }

    #[must_use]
    pub fn key_store(&self) -> &PersistentKeyStore {
        &self.key_store
    }

    #[must_use]
    pub fn auth_snapshot(&self) -> &AuthSnapshot {
        &self.auth_snapshot
    }

    #[must_use]
    pub fn crypto_persistent_state(&self) -> CryptoPersistentState {
        self.crypto_state.persistent_state()
    }

    #[must_use]
    pub fn policy_profile(&self) -> PolicyProfile {
        self.policy_profile
    }

    #[must_use]
    pub fn accepted_firmware_state(&self) -> AcceptedFirmwareState {
        self.accepted_firmware
    }

    #[must_use]
    pub fn boot_slots(&self) -> &[BootSlotMetadata; 2] {
        &self.boot_slots
    }

    #[must_use]
    pub fn update_transfer_state(&self) -> &UpdateTransferState {
        &self.update_transfer
    }

    #[must_use]
    pub fn recovery_state(&self) -> RecoveryState {
        self.recovery_state
    }

    #[must_use]
    pub fn audit_snapshot(&self) -> AuditStoreSnapshot {
        self.audit_journal.snapshot()
    }

    #[must_use]
    pub fn approval_tickets(&self) -> &Vec<ApprovalTicket, MAX_APPROVAL_TICKETS> {
        &self.approval_tickets
    }

    #[must_use]
    pub fn next_approval_ticket_id(&self) -> u32 {
        self.next_approval_ticket_id
    }

    pub fn restore_provisioning_snapshot(&mut self, snapshot: ProvisioningSnapshot) {
        self.record.restore_snapshot(snapshot);
    }

    pub fn restore_key_store(
        &mut self,
        snapshot: super::state::KeyStoreSnapshot,
    ) {
        self.key_store.restore_snapshot(snapshot);
    }

    pub fn restore_auth_snapshot(&mut self, snapshot: AuthSnapshot) {
        self.auth_snapshot = snapshot;
        clear_challenge(&mut self.active_challenge);
        clear_active_session(&mut self.active_session);
        self.legacy_session_mode = false;
        self.refresh_session_state();
    }

    pub fn restore_crypto_persistent_state(&mut self, snapshot: CryptoPersistentState) {
        self.crypto_state.restore_persistent_state(snapshot);
    }

    pub fn restore_policy_profile(&mut self, profile: PolicyProfile) {
        self.policy_profile = profile;
        self.policy_profile.developer_commands_visible = self.developer_mode;
    }

    pub fn restore_firmware_update_state(
        &mut self,
        accepted: AcceptedFirmwareState,
        boot_slots: [BootSlotMetadata; 2],
        transfer: UpdateTransferState,
        recovery: RecoveryState,
    ) {
        self.accepted_firmware = accepted;
        self.boot_slots = boot_slots;
        self.update_transfer = transfer;
        self.recovery_state = recovery;
    }

    pub fn restore_audit_snapshot(&mut self, snapshot: AuditStoreSnapshot) {
        self.audit_journal.restore_snapshot(snapshot);
    }

    pub fn restore_approval_tickets(
        &mut self,
        tickets: Vec<ApprovalTicket, MAX_APPROVAL_TICKETS>,
        next_ticket_id: u32,
    ) {
        self.approval_tickets = tickets;
        self.next_approval_ticket_id = next_ticket_id.max(1);
    }

    pub fn seed_rng(&mut self, seed: [u8; 32]) {
        self.crypto_state.seed_rng(seed);
    }

    pub fn set_rng_health(&mut self, healthy: bool) {
        self.crypto_state.set_rng_health(healthy);
    }

    #[must_use]
    pub fn take_firmware_action(&mut self) -> Option<FirmwareAction> {
        self.pending_firmware_action.take()
    }

    pub fn handle_bytes(&mut self, bytes: &[u8]) -> ProtocolFrame {
        match decode_frame(bytes) {
            Ok(mut frame) => {
                let response = self.handle_frame(&mut frame);
                frame.clear();
                response
            }
            Err(err) => Self::decode_error_response(err),
        }
    }

    fn refresh_session_state(&mut self) {
        if self.legacy_session_mode && self.active_session.is_none() && !self.developer_mode {
            return;
        }
        self.session_state = current_session_state(self.active_session, self.developer_mode);
    }

    fn legacy_role_active(&self, role: AuthorityRole) -> bool {
        matches!(
            (role, self.session_state),
            (AuthorityRole::Bootstrap, SessionState::Bootstrap)
                | (AuthorityRole::Administrator, SessionState::Administrator)
                | (AuthorityRole::Recovery, SessionState::Recovery)
                | (AuthorityRole::KeyManager, SessionState::KeyManager)
        )
    }

    fn advance_request_tick(&mut self) {
        self.request_tick = self.request_tick.saturating_add(1);
        if let Some(session) = self.active_session.as_mut()
            && session.state == SessionLifecycleState::Active
            && self.request_tick >= session.expires_at_tick
        {
            session.state = SessionLifecycleState::Expired;
            clear_active_session(&mut self.active_session);
        }
        if let Some(challenge) = self.active_challenge.as_ref()
            && self.request_tick >= challenge.expires_at_tick
        {
            clear_challenge(&mut self.active_challenge);
        }
        self.refresh_session_state();
    }

    fn invalidate_session(&mut self) {
        clear_challenge(&mut self.active_challenge);
        clear_active_session(&mut self.active_session);
        self.session_tracker.last_request_fingerprint = None;
        self.legacy_session_mode = false;
        self.refresh_session_state();
    }

    fn invalidate_authenticated_session_only(&mut self) {
        if self.active_session.is_some() {
            self.invalidate_session();
        }
    }

    fn invalidate_policy_tickets(&mut self) {
        invalidate_approval_tickets(&mut self.approval_tickets);
        retain_active_approval_tickets(&mut self.approval_tickets);
    }

    fn current_session_id(&self) -> u32 {
        self.active_session.map_or(0, |session| session.session_id)
    }

    fn trusted_update_public_key() -> Option<[u8; 32]> {
        ed25519_public_key_from_seed(UPDATE_TRUST_ANCHOR_SEED)
    }

    fn active_slot_index(&self) -> usize {
        usize::from(self.accepted_firmware.active_slot != BootSlotId::A)
    }

    fn staged_slot_index(&self) -> usize {
        usize::from(self.accepted_firmware.active_slot == BootSlotId::A)
    }

    fn firmware_update_status(&self) -> super::state::FirmwareUpdateStatus {
        update_status_view(
            self.accepted_firmware,
            &self.update_transfer,
            &self.boot_slots,
            self.policy_profile.policy_revision,
        )
    }

    fn clear_update_transfer(&mut self) {
        self.update_transfer = UpdateTransferState::default();
        let staged_index = self.staged_slot_index();
        let staged_slot_id = self.boot_slots[staged_index].slot_id;
        self.boot_slots[staged_index] = BootSlotMetadata::new(staged_slot_id, BootSlotState::Empty);
    }

    fn effective_actor_role(&self) -> AuthorityRole {
        if self.developer_mode {
            return AuthorityRole::Developer;
        }
        if let Some(session) = self.active_session {
            return session.role;
        }
        match self.session_state {
            SessionState::Bootstrap => AuthorityRole::Bootstrap,
            SessionState::Administrator => AuthorityRole::Administrator,
            SessionState::Recovery => AuthorityRole::Recovery,
            SessionState::Developer => AuthorityRole::Developer,
            SessionState::KeyManager => AuthorityRole::KeyManager,
            SessionState::Unauthenticated => AuthorityRole::Public,
        }
    }

    fn record_audit_event(
        &mut self,
        event_class: AuditEventClass,
        event_code: AuditEventCode,
        result_class: AuditResultClass,
        detail: &[u8],
    ) {
        self.audit_journal.record(
            event_class,
            event_code,
            self.record.revision_counter(),
            self.record.current_state(),
            self.effective_actor_role(),
            self.session_state,
            result_class,
            detail,
        );
    }

    #[allow(clippy::result_large_err)]
    fn maybe_create_or_confirm_approval(
        &mut self,
        approval_class: ProtectedActionClass,
        target_binding: ApprovalTargetBinding,
        target_id: u32,
        required_role: AuthorityRole,
        device_revision: u32,
    ) -> Result<(), ProtocolFrame> {
        if approval_class == ProtectedActionClass::None
            || !self.policy_profile.dual_control_enabled
            || !self.policy_profile.protects(approval_class)
        {
            return Ok(());
        }

        let mut matching_index = None;
        let mut stale_ticket_id = None;
        let current_tick = self.request_tick;
        for (index, ticket) in self.approval_tickets.iter_mut().enumerate() {
            if ticket.approval_class != approval_class
                || ticket.target_binding != target_binding
                || ticket.target_id != target_id
            {
                continue;
            }
            if ticket.state == ApprovalTicketState::Pending
                && (ticket.policy_revision != self.policy_profile.policy_revision
                    || ticket.device_revision != device_revision
                    || current_tick >= ticket.expires_at_tick)
            {
                ticket.state = ApprovalTicketState::Invalidated;
                stale_ticket_id = Some(ticket.ticket_id);
            }
            if matches!(
                ticket.state,
                ApprovalTicketState::Pending | ApprovalTicketState::Confirmed
            ) {
                if matching_index.is_some() {
                    return Err(policy_status_response(
                        status_for_denial_class(DenialClass::InternalPolicyError),
                        DenialClass::InternalPolicyError,
                        None,
                    ));
                }
                matching_index = Some(index);
            }
        }

        if let Some(ticket_id) = stale_ticket_id {
            retain_active_approval_tickets(&mut self.approval_tickets);
            return Err(policy_status_response(
                status_for_denial_class(DenialClass::ApprovalStale),
                DenialClass::ApprovalStale,
                Some(ticket_id),
            ));
        }

        if let Some(index) = matching_index {
            let session_id = self.current_session_id();
            let ticket = &mut self.approval_tickets[index];
            if ticket.state != ApprovalTicketState::Pending {
                return Err(policy_status_response(
                    status_for_denial_class(DenialClass::ApprovalStale),
                    DenialClass::ApprovalStale,
                    Some(ticket.ticket_id),
                ));
            }
            if session_id == 0 || session_id == ticket.initiator_session_id {
                return Err(policy_status_response(
                    status_for_denial_class(DenialClass::ApprovalMissing),
                    DenialClass::ApprovalMissing,
                    Some(ticket.ticket_id),
                ));
            }
            ticket.state = ApprovalTicketState::Confirmed;
            ticket.confirmer_role = required_role;
            return Ok(());
        }

        let ticket_id = self.next_approval_ticket_id;
        self.next_approval_ticket_id = self.next_approval_ticket_id.saturating_add(1);
        let ticket = new_approval_ticket(
            ticket_id,
            approval_class,
            target_binding,
            target_id,
            required_role,
            required_role,
            self.current_session_id(),
            self.policy_profile.policy_revision,
            device_revision,
            self.request_tick,
        );
        if self.approval_tickets.push(ticket).is_err() {
            return Err(policy_status_response(
                status_for_denial_class(DenialClass::InternalPolicyError),
                DenialClass::InternalPolicyError,
                None,
            ));
        }
        Err(policy_status_response(
            status_for_denial_class(DenialClass::ApprovalMissing),
            DenialClass::ApprovalMissing,
            Some(ticket_id),
        ))
    }

    fn consume_approval_ticket(
        &mut self,
        approval_class: ProtectedActionClass,
        target_binding: ApprovalTargetBinding,
        target_id: u32,
    ) {
        for ticket in &mut self.approval_tickets {
            if ticket.approval_class == approval_class
                && ticket.target_binding == target_binding
                && ticket.target_id == target_id
                && ticket.state == ApprovalTicketState::Confirmed
            {
                ticket.state = ApprovalTicketState::Consumed;
            }
        }
        retain_active_approval_tickets(&mut self.approval_tickets);
    }

    fn authorize_privileged<'a>(
        &mut self,
        role: AuthorityRole,
        payload: &'a [u8],
        min_inner_len: usize,
        max_inner_len: usize,
    ) -> Result<(u32, &'a [u8]), StatusCode> {
        let (session_id, request_counter, inner) =
            decode_authorized_payload(payload, min_inner_len, max_inner_len)?;

        let Some(session) = self.active_session.as_mut() else {
            return Err(StatusCode::AuthorizationError);
        };
        if session.state != SessionLifecycleState::Active
            || session.role != role
            || session.session_id != session_id
        {
            return Err(StatusCode::AuthorizationError);
        }
        if request_counter <= session.last_counter {
            return Err(StatusCode::ReplayError);
        }
        session.last_counter = request_counter;
        session.last_activity_tick = self.request_tick;
        Ok((request_counter, inner))
    }

    fn authorize_privileged_owned<const N: usize>(
        &mut self,
        role: AuthorityRole,
        payload: &[u8],
        min_inner_len: usize,
        max_inner_len: usize,
    ) -> Result<(u32, Vec<u8, N>), StatusCode> {
        if self.active_session.is_none() && self.legacy_role_active(role) {
            let mut owned = Vec::<u8, N>::new();
            if payload.len() > max_inner_len
                && let Ok((_, _, inner)) =
                    decode_authorized_payload(payload, min_inner_len, max_inner_len)
            {
                owned
                    .extend_from_slice(inner)
                    .map_err(|()| StatusCode::ValidationError)?;
            } else {
                if payload.len() < min_inner_len || payload.len() > max_inner_len {
                    return Err(StatusCode::ValidationError);
                }
                owned
                    .extend_from_slice(payload)
                    .map_err(|()| StatusCode::ValidationError)?;
            }
            return Ok((0, owned));
        }
        let (request_counter, inner) =
            self.authorize_privileged(role, payload, min_inner_len, max_inner_len)?;
        let mut owned = Vec::<u8, N>::new();
        owned
            .extend_from_slice(inner)
            .map_err(|()| StatusCode::ValidationError)?;
        Ok((request_counter, owned))
    }

    fn authorize_any_owned<const N: usize>(
        &mut self,
        roles: &[AuthorityRole],
        payload: &[u8],
        min_inner_len: usize,
        max_inner_len: usize,
    ) -> Result<(u32, Vec<u8, N>, AuthorityRole), StatusCode> {
        if self.active_session.is_none() {
            for &role in roles {
                if self.legacy_role_active(role) {
                    let mut owned = Vec::<u8, N>::new();
                    if payload.len() > max_inner_len
                        && let Ok((_, _, inner)) =
                            decode_authorized_payload(payload, min_inner_len, max_inner_len)
                    {
                        owned
                            .extend_from_slice(inner)
                            .map_err(|()| StatusCode::ValidationError)?;
                    } else {
                        if payload.len() < min_inner_len || payload.len() > max_inner_len {
                            return Err(StatusCode::ValidationError);
                        }
                        owned
                            .extend_from_slice(payload)
                            .map_err(|()| StatusCode::ValidationError)?;
                    }
                    return Ok((0, owned, role));
                }
            }
        }

        let (session_id, request_counter, inner) =
            decode_authorized_payload(payload, min_inner_len, max_inner_len)?;
        let Some(session) = self.active_session.as_mut() else {
            return Err(StatusCode::AuthorizationError);
        };
        if session.state != SessionLifecycleState::Active
            || session.session_id != session_id
            || !roles.contains(&session.role)
        {
            return Err(StatusCode::AuthorizationError);
        }
        if request_counter <= session.last_counter {
            return Err(StatusCode::ReplayError);
        }
        session.last_counter = request_counter;
        session.last_activity_tick = self.request_tick;
        let mut owned = Vec::<u8, N>::new();
        owned
            .extend_from_slice(inner)
            .map_err(|()| StatusCode::ValidationError)?;
        Ok((request_counter, owned, session.role))
    }

    fn handle_frame(&mut self, frame: &mut ProtocolFrame) -> ProtocolFrame {
        self.advance_request_tick();
        self.key_store
            .sync_device_revision(self.record.revision_counter());
        if frame.kind != MessageKind::Request {
            return status_response(StatusCode::FormatError, &[]);
        }

        if frame.version != PROTOCOL_VERSION {
            return status_response(StatusCode::VersionError, &[]);
        }

        let Some(command) = lookup_command(frame.code) else {
            return status_response(StatusCode::CommandError, &[]);
        };

        let legacy_payload_allowed = command.required_role != AuthorityRole::Public
            && !command.developer_only
            && self.active_session.is_none()
            && self.legacy_role_active(command.required_role)
            && frame.payload_len().saturating_add(8) >= command.min_payload_len
            && frame.payload_len().saturating_add(8) <= command.max_payload_len;

        if !(legacy_payload_allowed
            || (frame.payload_len() >= command.min_payload_len
                && frame.payload_len() <= command.max_payload_len))
        {
            return status_response(StatusCode::ValidationError, &[]);
        }

        let policy = evaluate_command_policy(
            command,
            self.record.current_state(),
            self.session_state,
            self.developer_mode,
            self.policy_profile,
        );
        if !policy.decision {
            self.record_audit_event(
                AuditEventClass::SecurityDenial,
                AuditEventCode::CommandDenied,
                AuditResultClass::Denied,
                &[frame.code, policy.denial_class as u8],
            );
            let payload = encode_policy_denial_payload(policy.denial_class, policy.approval_ticket_id)
                .unwrap_or_default();
            return status_response(status_for_denial_class(policy.denial_class), &payload);
        }

        let fingerprint = fingerprint_frame(frame.code, &frame.payload);
        if frame.flags & FLAG_REPLAY_SENSITIVE != 0
            && let Err(status) =
                enforce_replay_policy(command, &mut self.session_tracker, fingerprint)
        {
            return status_response(status, &[]);
        }

        self.dispatch(frame)
    }

    fn dispatch(&mut self, frame: &mut ProtocolFrame) -> ProtocolFrame {
        match CommandId::from_byte(frame.code) {
            Some(CommandId::GetProtocolVersion) => protocol_version_response(),
            Some(CommandId::GetDeviceStatus) => self.handle_get_device_status(frame),
            Some(CommandId::GetCommandCatalog) => self.handle_get_command_catalog(frame),
            Some(CommandId::GetLifecycleStatus) => self.handle_get_lifecycle_status(),
            Some(CommandId::GetKeyStoreStatus) => self.handle_get_key_store_status(),
            Some(CommandId::BeginAuthentication) => self.handle_begin_authentication(frame),
            Some(CommandId::CompleteAuthentication) => self.handle_complete_authentication(frame),
            Some(CommandId::GetSessionStatus) => self.handle_get_session_status(),
            Some(CommandId::InvalidateSession) => self.handle_invalidate_session(frame),
            Some(CommandId::GetCryptoCapabilities) => self.handle_get_crypto_capabilities(),
            Some(CommandId::VerifyDetached) => Self::handle_verify_detached(frame),
            Some(CommandId::GetHealthStatus) => self.handle_get_health_status(),
            Some(CommandId::GetAuditPage) => self.handle_get_audit_page(frame),
            Some(CommandId::ListAlgorithms) => self.handle_list_algorithms(frame),
            Some(CommandId::BeginProvisioning) => self.handle_begin_provisioning(frame),
            Some(CommandId::FinalizeProvisioning) => self.handle_finalize_provisioning(frame),
            Some(CommandId::LockDevice) => self.handle_lock_device(frame),
            Some(CommandId::UnlockDevice) => self.handle_unlock_device(frame),
            Some(CommandId::EnterRecovery) => self.handle_enter_recovery(frame),
            Some(CommandId::RecoverToProvisioned) => self.handle_recover_to_provisioned(frame),
            Some(CommandId::ReactivateRecoveredProvisioning) => {
                self.handle_reactivate_recovered_provisioning(frame)
            }
            Some(CommandId::ExecuteZeroize) => self.handle_execute_zeroize(frame),
            Some(CommandId::DeveloperResetLifecycle) => self.handle_developer_reset(frame),
            Some(CommandId::PutPersistentKey) => self.handle_put_persistent_key(frame),
            Some(CommandId::ListPersistentKeys) => self.handle_list_persistent_keys(frame),
            Some(CommandId::GetKeyMetadata) => self.handle_get_key_metadata(frame),
            Some(CommandId::RevokePersistentKey) => self.handle_revoke_persistent_key(frame),
            Some(CommandId::DestroyPersistentKey) => self.handle_destroy_persistent_key(frame),
            Some(CommandId::DeveloperStoreFault) => self.handle_developer_store_fault(frame),
            Some(CommandId::DeveloperReboot) => self.handle_developer_reboot(frame),
            Some(CommandId::DeveloperSetPolicy) => self.handle_developer_set_policy(frame),
            Some(CommandId::GenerateKey) => self.handle_generate_key(frame),
            Some(CommandId::GenerateMac) => self.handle_generate_mac(frame),
            Some(CommandId::VerifyMac) => self.handle_verify_mac(frame),
            Some(CommandId::SignDetached) => self.handle_sign_detached(frame),
            Some(CommandId::GenerateRandom) => self.handle_generate_random(frame),
            Some(CommandId::ImportWrappedKey) => self.handle_import_wrapped_key(frame),
            Some(CommandId::ExportWrappedKey) => self.handle_export_wrapped_key(frame),
            Some(CommandId::Encrypt) => self.handle_encrypt(frame),
            Some(CommandId::Decrypt) => self.handle_decrypt(frame),
            Some(CommandId::DeriveSharedSecret) => self.handle_derive_shared_secret(frame),
            Some(CommandId::GetFirmwareUpdateStatus) => self.handle_get_firmware_update_status(frame),
            Some(CommandId::BeginFirmwareUpdate) => self.handle_begin_firmware_update(frame),
            Some(CommandId::TransferFirmwareChunk) => self.handle_transfer_firmware_chunk(frame),
            Some(CommandId::FinalizeFirmwareUpdate) => self.handle_finalize_firmware_update(frame),
            Some(CommandId::ActivateFirmwareUpdate) => self.handle_activate_firmware_update(frame),
            Some(CommandId::AbortFirmwareUpdate) => self.handle_abort_firmware_update(frame),
            Some(CommandId::RecoverTrustedFirmware) => self.handle_recover_trusted_firmware(frame),
            Some(CommandId::DeveloperUpdateFault) => self.handle_developer_update_fault(frame),
            None => status_response(StatusCode::CommandError, &[]),
        }
    }

    fn handle_get_device_status(&self, frame: &ProtocolFrame) -> ProtocolFrame {
        if frame.payload.as_slice() != [0x00] {
            return status_response(StatusCode::ValidationError, &[]);
        }

        let payload =
            encode_device_status_payload(self.record.current_state(), self.session_state);
        status_response(StatusCode::Success, &payload)
    }

    fn handle_get_command_catalog(&self, frame: &ProtocolFrame) -> ProtocolFrame {
        let include_restricted = match frame.payload.as_slice() {
            [0x00] => false,
            [0x01] => true,
            _ => return status_response(StatusCode::ValidationError, &[]),
        };

        let include_restricted = include_restricted && (frame.flags & FLAG_INCLUDE_RESTRICTED != 0);
        let visible = get_visible_catalog(self.session_state, include_restricted, self.developer_mode);
        let mut payload = Vec::<u8, 48>::new();
        let Ok(visible_count) = u8::try_from(visible.len()) else {
            return status_response(StatusCode::InternalError, &[]);
        };
        let _ = payload.push(visible_count);
        for command in visible {
            let _ = payload.push(command.id as u8);
        }
        status_response(StatusCode::Success, &payload)
    }

    fn handle_get_lifecycle_status(&self) -> ProtocolFrame {
        let payload = encode_lifecycle_status_payload(self.record.status());
        status_response(StatusCode::Success, &payload)
    }

    fn handle_get_key_store_status(&self) -> ProtocolFrame {
        let payload = encode_key_store_status_payload(self.key_store.status());
        status_response(StatusCode::Success, &payload)
    }

    fn handle_get_crypto_capabilities(&self) -> ProtocolFrame {
        let payload = encode_crypto_capabilities_payload(self.crypto_state.capabilities());
        status_response(StatusCode::Success, &payload)
    }

    fn handle_list_algorithms(&self, frame: &ProtocolFrame) -> ProtocolFrame {
        if !frame.payload.is_empty() {
            return status_response(StatusCode::ValidationError, &[]);
        }
        let Some(payload) = encode_algorithm_profiles_payload(self.crypto_state.algorithm_profiles()) else {
            return status_response(StatusCode::InternalError, &[]);
        };
        status_response(StatusCode::Success, &payload)
    }

    fn compose_health_status(&self) -> super::state::HealthStatusView {
        super::state::HealthStatusView {
            device_state: self.record.current_state(),
            key_store_state: self.key_store.status().store_state,
            session_state: self.session_state,
            policy_revision: self.policy_profile.policy_revision,
            audit_store_state: self.audit_journal.store_state(),
            audit_events_retained: self.audit_journal.events_retained(),
            audit_overflow_detected: self.audit_journal.overflow_detected(),
            rollback_detected: self.key_store.status().rollback_detected,
            corruption_detected: self.key_store.status().corruption_detected
                || self.audit_journal.corruption_detected,
        }
    }

    fn handle_get_health_status(&mut self) -> ProtocolFrame {
        let payload = encode_health_status_payload(self.compose_health_status());
        self.record_audit_event(
            AuditEventClass::ObservabilityAccess,
            AuditEventCode::HealthStatusViewed,
            AuditResultClass::Success,
            &[self.record.current_state() as u8, self.audit_journal.store_state() as u8],
        );
        status_response(StatusCode::Success, &payload)
    }

    fn manifest_signature_message(
        manifest: &FirmwarePackageManifest,
    ) -> [u8; 48] {
        let version = manifest.image_version;
        let size = manifest.image_size_bytes.to_le_bytes();
        let flags = manifest.policy_flags.to_le_bytes();
        let mut message = [0u8; 48];
        message[0] = manifest.manifest_version;
        message[1..3].copy_from_slice(&version.security_epoch.to_le_bytes());
        message[3..5].copy_from_slice(&version.major.to_le_bytes());
        message[5..7].copy_from_slice(&version.minor.to_le_bytes());
        message[7..9].copy_from_slice(&version.patch.to_le_bytes());
        message[9..13].copy_from_slice(&size);
        message[13..45].copy_from_slice(&manifest.image_digest_sha256);
        message[45] = manifest.target_slot_hint as u8;
        message[46..48].copy_from_slice(&flags);
        message
    }

    fn handle_get_firmware_update_status(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        if let Err(status) = self.authorize_any_owned::<0>(
            &[AuthorityRole::Administrator, AuthorityRole::Recovery],
            frame.payload.as_slice(),
            0,
            0,
        ) {
            return status_response(status, &[]);
        }
        let payload = encode_firmware_update_status_payload(self.firmware_update_status());
        status_response(StatusCode::Success, &payload)
    }

    fn handle_begin_firmware_update(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        let (_, inner) = match self.authorize_privileged_owned::<128>(
            AuthorityRole::Administrator,
            frame.payload.as_slice(),
            51,
            115,
        ) {
            Ok(values) => values,
            Err(status) => return status_response(status, &[]),
        };
        let request = match decode_begin_firmware_update_request(inner.as_slice()) {
            Ok(request) => request,
            Err(status) => return status_response(status, &[]),
        };
        if request.manifest.manifest_version != UPDATE_MANIFEST_VERSION
            || request.manifest.signature_algorithm != UPDATE_SIGNATURE_ALGORITHM_ED25519
        {
            return status_response(StatusCode::ValidationError, &[]);
        }
        if usize::try_from(request.manifest.image_size_bytes).unwrap_or(usize::MAX)
            > super::state::MAX_FIRMWARE_IMAGE_SIZE
        {
            return status_response(StatusCode::ValidationError, &[]);
        }
        if request.manifest.target_slot_hint != self.accepted_firmware.active_slot.other() {
            return status_response(StatusCode::StateError, &[]);
        }
        if let Err(denial) = firmware_version_allowed(request.manifest.image_version, self.accepted_firmware) {
            self.accepted_firmware.last_update_result = UpdateResultClass::RollbackDenied;
            return policy_status_response(status_for_denial_class(denial), denial, None);
        }
        let Some(public_key_bytes) = Self::trusted_update_public_key() else {
            return status_response(StatusCode::InternalError, &[]);
        };
        let Ok(verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(&public_key_bytes) else {
            return status_response(StatusCode::InternalError, &[]);
        };
        let Ok(signature) = ed25519_dalek::Signature::from_slice(
            request.manifest.signature_bytes.as_slice(),
        ) else {
            self.accepted_firmware.last_update_result = UpdateResultClass::SignatureRejected;
            return status_response(StatusCode::ValidationError, &[]);
        };
        let message = Self::manifest_signature_message(&request.manifest);
        if verifying_key.verify(&message, &signature).is_err() {
            self.accepted_firmware.last_update_result = UpdateResultClass::SignatureRejected;
            return status_response(StatusCode::AuthorizationError, &[]);
        }
        let approval_target = self.record.revision_counter();
        if let Err(response) = self.maybe_create_or_confirm_approval(
            ProtectedActionClass::FirmwareUpdate,
            ApprovalTargetBinding::Device,
            approval_target,
            AuthorityRole::Administrator,
            self.policy_profile.policy_revision,
        ) {
            return response;
        }
        let target_slot = request.manifest.target_slot_hint;
        let target_index = usize::from(target_slot != BootSlotId::A);
        self.boot_slots[target_index].slot_state = BootSlotState::StagedTransfer;
        self.boot_slots[target_index].stored_version = request.manifest.image_version;
        self.boot_slots[target_index].version_present = true;
        self.boot_slots[target_index].stored_digest = request.manifest.image_digest_sha256;
        self.boot_slots[target_index].digest_present = true;
        self.boot_slots[target_index].bootable = false;
        self.boot_slots[target_index].trusted = false;
        self.update_transfer.phase = UpdateTransferPhase::ManifestAccepted;
        self.update_transfer.session_id = self.record.revision_counter().saturating_add(1);
        self.update_transfer.manifest = Some(request.manifest.clone());
        self.update_transfer.bytes_received = 0;
        self.update_transfer.expected_size = request.manifest.image_size_bytes;
        self.update_transfer.staged_image.clear();
        self.update_transfer.started_revision = self.record.revision_counter();
        self.update_transfer.policy_revision = self.policy_profile.policy_revision;
        self.accepted_firmware.trusted_boot_state = TrustedBootState::StagedPending;
        self.accepted_firmware.last_update_result = UpdateResultClass::Begun;
        self.record_audit_event(
            AuditEventClass::Administrative,
            AuditEventCode::CommandCompleted,
            AuditResultClass::Success,
            &[frame.code, target_slot as u8],
        );
        let payload = encode_firmware_update_begin_payload(FirmwareUpdateBeginResult {
            target_slot,
            update_session_id: self.update_transfer.session_id,
            expected_size: self.update_transfer.expected_size,
            policy_revision: self.policy_profile.policy_revision,
        });
        status_response(StatusCode::Success, &payload)
    }

    fn handle_transfer_firmware_chunk(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        let (_, inner) = match self.authorize_privileged_owned::<140>(
            AuthorityRole::Administrator,
            frame.payload.as_slice(),
            10,
            138,
        ) {
            Ok(values) => values,
            Err(status) => return status_response(status, &[]),
        };
        let request = match decode_firmware_chunk_request(inner.as_slice()) {
            Ok(request) => request,
            Err(status) => return status_response(status, &[]),
        };
        if self.update_transfer.session_id != request.update_session_id
            || self.update_transfer.manifest.is_none()
        {
            return status_response(StatusCode::StateError, &[]);
        }
        if request.chunk_offset != self.update_transfer.bytes_received {
            return status_response(StatusCode::ValidationError, &[]);
        }
        if usize::try_from(self.update_transfer.bytes_received).unwrap_or(usize::MAX)
            + request.chunk.len()
            > super::state::MAX_FIRMWARE_IMAGE_SIZE
        {
            return status_response(StatusCode::ValidationError, &[]);
        }
        if self
            .update_transfer
            .staged_image
            .extend_from_slice(request.chunk.as_slice())
            .is_err()
        {
            return status_response(StatusCode::InternalError, &[]);
        }
        self.update_transfer.phase = UpdateTransferPhase::Transferring;
        self.update_transfer.bytes_received = self
            .update_transfer
            .bytes_received
            .saturating_add(u32::try_from(request.chunk.len()).unwrap_or(0));
        if self.update_transfer.bytes_received == self.update_transfer.expected_size {
            self.update_transfer.phase = UpdateTransferPhase::Transferred;
        }
        let remaining = self
            .update_transfer
            .expected_size
            .saturating_sub(self.update_transfer.bytes_received);
        let payload = encode_firmware_chunk_progress_payload(FirmwareChunkProgress {
            bytes_received: self.update_transfer.bytes_received,
            remaining_bytes: remaining,
        });
        status_response(StatusCode::Success, &payload)
    }

    fn handle_finalize_firmware_update(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        let (_, inner) = match self.authorize_privileged_owned::<5>(
            AuthorityRole::Administrator,
            frame.payload.as_slice(),
            5,
            5,
        ) {
            Ok(values) => values,
            Err(status) => return status_response(status, &[]),
        };
        let update_session_id = match decode_transition_request(inner.as_slice(), finalize_marker()) {
            Ok(value) => value,
            Err(status) => return status_response(status, &[]),
        };
        if self.update_transfer.session_id != update_session_id
            || self.update_transfer.phase != UpdateTransferPhase::Transferred
        {
            return status_response(StatusCode::StateError, &[]);
        }
        let Some(manifest) = self.update_transfer.manifest.as_ref() else {
            return status_response(StatusCode::StateError, &[]);
        };
        let validated_version = manifest.image_version;
        if usize::try_from(self.update_transfer.expected_size).unwrap_or(usize::MAX)
            != self.update_transfer.staged_image.len()
        {
            return status_response(StatusCode::StateError, &[]);
        }
        self.update_transfer.phase = UpdateTransferPhase::Validating;
        let digest = Sha256::digest(self.update_transfer.staged_image.as_slice());
        if digest.as_slice() != manifest.image_digest_sha256 {
            self.accepted_firmware.last_update_result = UpdateResultClass::DigestMismatch;
            self.clear_update_transfer();
            return status_response(StatusCode::ValidationError, &[]);
        }
        let approval_target = self.record.revision_counter();
        if let Err(response) = self.maybe_create_or_confirm_approval(
            ProtectedActionClass::FirmwareUpdate,
            ApprovalTargetBinding::Device,
            approval_target,
            AuthorityRole::Administrator,
            self.policy_profile.policy_revision,
        ) {
            return response;
        }
        self.update_transfer.phase = UpdateTransferPhase::ActivationPending;
        let staged_index = self.staged_slot_index();
        self.boot_slots[staged_index].slot_state = BootSlotState::StagedValidated;
        self.accepted_firmware.trusted_boot_state = TrustedBootState::StagedValidating;
        self.accepted_firmware.last_update_result = UpdateResultClass::Finalized;
        let payload = encode_firmware_finalize_payload(FirmwareFinalizeResult {
            staged_slot: self.boot_slots[staged_index].slot_id,
            validated_version,
            activation_pending: true,
        });
        status_response(StatusCode::Success, &payload)
    }

    fn handle_activate_firmware_update(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        let (_, inner) = match self.authorize_privileged_owned::<5>(
            AuthorityRole::Administrator,
            frame.payload.as_slice(),
            5,
            5,
        ) {
            Ok(values) => values,
            Err(status) => return status_response(status, &[]),
        };
        let update_session_id = match decode_transition_request(inner.as_slice(), reactivate_marker()) {
            Ok(value) => value,
            Err(status) => return status_response(status, &[]),
        };
        if self.update_transfer.session_id != update_session_id
            || self.update_transfer.phase != UpdateTransferPhase::ActivationPending
        {
            return status_response(StatusCode::StateError, &[]);
        }
        let approval_target = self.record.revision_counter();
        if let Err(response) = self.maybe_create_or_confirm_approval(
            ProtectedActionClass::FirmwareUpdate,
            ApprovalTargetBinding::Device,
            approval_target,
            AuthorityRole::Administrator,
            self.policy_profile.policy_revision,
        ) {
            return response;
        }
        let manifest = self.update_transfer.manifest.clone().unwrap_or_else(|| FirmwarePackageManifest {
            manifest_version: UPDATE_MANIFEST_VERSION,
            image_version: FirmwareVersion::default(),
            image_size_bytes: 0,
            image_digest_sha256: [0; 32],
            target_slot_hint: self.accepted_firmware.active_slot.other(),
            policy_flags: 0,
            signature_algorithm: UPDATE_SIGNATURE_ALGORITHM_ED25519,
            signature_bytes: Vec::new(),
        });
        let staged_index = self.staged_slot_index();
        let active_index = self.active_slot_index();
        self.boot_slots[active_index].slot_state = BootSlotState::Empty;
        self.boot_slots[active_index].bootable = false;
        self.boot_slots[active_index].trusted = false;
        self.accepted_firmware.active_slot = self.boot_slots[staged_index].slot_id;
        self.accepted_firmware.active_version = manifest.image_version;
        self.accepted_firmware.minimum_accepted_version = manifest.image_version;
        self.accepted_firmware.last_update_result = UpdateResultClass::Activated;
        self.accepted_firmware.recovery_required = false;
        self.accepted_firmware.trusted_boot_state = TrustedBootState::ActiveTrusted;
        self.accepted_firmware.revision_counter =
            self.accepted_firmware.revision_counter.saturating_add(1);
        self.boot_slots[staged_index].slot_state = BootSlotState::ActiveTrusted;
        self.boot_slots[staged_index].bootable = true;
        self.boot_slots[staged_index].trusted = true;
        self.update_transfer = UpdateTransferState::default();
        self.consume_approval_ticket(
            ProtectedActionClass::FirmwareUpdate,
            ApprovalTargetBinding::Device,
            approval_target,
        );
        let payload = encode_firmware_activation_payload(FirmwareActivationResult {
            next_boot_slot: self.accepted_firmware.active_slot,
            next_version: self.accepted_firmware.active_version,
            reboot_required: true,
        });
        status_response(StatusCode::Success, &payload)
    }

    fn handle_abort_firmware_update(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        let (_, inner) = match self.authorize_any_owned::<4>(
            &[AuthorityRole::Administrator, AuthorityRole::Recovery],
            frame.payload.as_slice(),
            4,
            4,
        ) {
            Ok((request_counter, inner, _)) => (request_counter, inner),
            Err(status) => return status_response(status, &[]),
        };
        let update_session_id = u32::from_le_bytes([inner[0], inner[1], inner[2], inner[3]]);
        if self.update_transfer.session_id != update_session_id {
            return status_response(StatusCode::StateError, &[]);
        }
        self.clear_update_transfer();
        self.accepted_firmware.trusted_boot_state = TrustedBootState::ActiveTrusted;
        self.accepted_firmware.last_update_result = UpdateResultClass::Aborted;
        let payload = encode_firmware_abort_payload(FirmwareAbortResult {
            transfer_state_cleared: true,
            staged_slot_invalidated: true,
        });
        status_response(StatusCode::Success, &payload)
    }

    fn handle_recover_trusted_firmware(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        let (_, inner) = match self.authorize_privileged_owned::<1>(
            AuthorityRole::Recovery,
            frame.payload.as_slice(),
            1,
            1,
        ) {
            Ok(values) => values,
            Err(status) => return status_response(status, &[]),
        };
        if let Err(status) = expect_single_marker(inner.as_slice(), recovery_marker()) {
            return status_response(status, &[]);
        }
        let approval_target = self.record.revision_counter();
        if let Err(response) = self.maybe_create_or_confirm_approval(
            ProtectedActionClass::FirmwareUpdate,
            ApprovalTargetBinding::Device,
            approval_target,
            AuthorityRole::Recovery,
            self.policy_profile.policy_revision,
        ) {
            return response;
        }
        self.clear_update_transfer();
        self.accepted_firmware.recovery_required = false;
        self.accepted_firmware.last_update_result = UpdateResultClass::Recovered;
        self.accepted_firmware.trusted_boot_state = TrustedBootState::ActiveTrusted;
        self.recovery_state.reason = UpdateRecoveryReason::None;
        self.recovery_state.staged_slot_present = false;
        let restored = self.accepted_firmware.active_slot;
        let active_index = self.active_slot_index();
        self.boot_slots[active_index].slot_state = BootSlotState::ActiveTrusted;
        self.boot_slots[active_index].bootable = true;
        self.boot_slots[active_index].trusted = true;
        self.consume_approval_ticket(
            ProtectedActionClass::FirmwareUpdate,
            ApprovalTargetBinding::Device,
            approval_target,
        );
        let payload = encode_firmware_recovery_payload(FirmwareRecoveryResult {
            restored_slot: restored,
            restored_version: self.accepted_firmware.active_version,
            recovery_required: false,
        });
        status_response(StatusCode::Success, &payload)
    }

    fn handle_get_audit_page(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        let (_, inner, role) = match self.authorize_any_owned::<5>(
            &[AuthorityRole::Administrator, AuthorityRole::Recovery],
            frame.payload.as_slice(),
            5,
            5,
        ) {
            Ok(values) => values,
            Err(status) => {
                self.record_audit_event(
                    AuditEventClass::ObservabilityAccess,
                    AuditEventCode::AuditPageDenied,
                    AuditResultClass::Denied,
                    &[frame.code, status as u8],
                );
                return status_response(status, &[]);
            }
        };
        let (start_sequence, max_events) = match decode_audit_page_request(inner.as_slice()) {
            Ok(values) => values,
            Err(status) => {
                self.record_audit_event(
                    AuditEventClass::ObservabilityAccess,
                    AuditEventCode::AuditPageDenied,
                    AuditResultClass::Denied,
                    &[status as u8],
                );
                return status_response(status, &[]);
            }
        };
        match self.audit_journal.page(start_sequence, max_events) {
            Ok((page, cursor)) => {
                self.record_audit_event(
                    AuditEventClass::ObservabilityAccess,
                    AuditEventCode::AuditPageViewed,
                    AuditResultClass::Success,
                    &[role as u8, u8::try_from(page.len()).unwrap_or(0)],
                );
                let Some(payload) = encode_audit_page_payload(page.as_slice(), cursor) else {
                    return status_response(StatusCode::InternalError, &[]);
                };
                status_response(StatusCode::Success, &payload)
            }
            Err(status) => {
                self.record_audit_event(
                    AuditEventClass::ObservabilityAccess,
                    AuditEventCode::AuditPageDenied,
                    AuditResultClass::FailedClosed,
                    &[self.audit_journal.store_state() as u8],
                );
                status_response(status, &[])
            }
        }
    }

    fn handle_begin_authentication(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        let role = match decode_authentication_role(frame.payload.as_slice()) {
            Ok(role) => role,
            Err(status) => return status_response(status, &[]),
        };
        let Some(credential) = find_credential(&self.auth_snapshot, role) else {
            return status_response(StatusCode::AuthorizationError, &[]);
        };
        if !credential.enabled || !credential.allows_state(self.record.current_state()) {
            return status_response(StatusCode::AuthorizationError, &[]);
        }
        if role_locked_out(&self.auth_snapshot, role, self.request_tick) {
            return status_response(StatusCode::AuthorizationError, &[]);
        }

        let challenge_id = self.auth_snapshot.next_challenge_id;
        self.auth_snapshot.next_challenge_id =
            self.auth_snapshot.next_challenge_id.saturating_add(1);
        let nonce = issue_challenge_nonce(role, challenge_id, self.record.revision_counter());
        self.active_challenge = Some(AuthenticationChallenge {
            challenge_id,
            requested_role: role,
            nonce: nonce.clone(),
            expires_at_tick: self.request_tick.saturating_add(4),
            request_counter_floor: 0,
        });
        self.refresh_session_state();
        let Some(payload) =
            encode_auth_challenge_payload(challenge_id, role, nonce.as_slice(), 4)
        else {
            return status_response(StatusCode::InternalError, &[]);
        };
        status_response(StatusCode::Success, &payload)
    }

    fn handle_complete_authentication(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        let (challenge_id, request_counter, proof_bytes) =
            match decode_complete_authentication_request(frame.payload.as_slice()) {
                Ok(values) => values,
                Err(status) => return status_response(status, &[]),
            };
        let Some(challenge) = self.active_challenge.clone() else {
            return status_response(StatusCode::AuthorizationError, &[]);
        };
        if challenge.challenge_id != challenge_id || self.request_tick >= challenge.expires_at_tick {
            record_auth_failure(
                &mut self.auth_snapshot,
                challenge.requested_role,
                self.request_tick,
            );
            clear_challenge(&mut self.active_challenge);
            self.record_audit_event(
                AuditEventClass::SecurityDenial,
                AuditEventCode::AuthenticationFailed,
                AuditResultClass::Denied,
                &[challenge.requested_role as u8],
            );
            return status_response(StatusCode::AuthorizationError, &[]);
        }
        if request_counter <= challenge.request_counter_floor {
            record_auth_failure(
                &mut self.auth_snapshot,
                challenge.requested_role,
                self.request_tick,
            );
            clear_challenge(&mut self.active_challenge);
            self.record_audit_event(
                AuditEventClass::SecurityDenial,
                AuditEventCode::AuthenticationFailed,
                AuditResultClass::Denied,
                &[challenge.requested_role as u8],
            );
            return status_response(StatusCode::ReplayError, &[]);
        }
        let Some(credential) = find_credential(&self.auth_snapshot, challenge.requested_role) else {
            return status_response(StatusCode::AuthorizationError, &[]);
        };
        let timeout_ticks = credential.session_timeout_ticks;
        if !super::state::verify_marker_proof(credential, proof_bytes) {
            record_auth_failure(
                &mut self.auth_snapshot,
                challenge.requested_role,
                self.request_tick,
            );
            return status_response(StatusCode::AuthorizationError, &[]);
        }

        clear_auth_failures(&mut self.auth_snapshot, challenge.requested_role);
        let session_id = self.auth_snapshot.next_session_id;
        self.auth_snapshot.next_session_id = self.auth_snapshot.next_session_id.saturating_add(1);
        self.active_session = Some(SessionRecord {
            session_id,
            role: challenge.requested_role,
            state: SessionLifecycleState::Active,
            issued_at_revision: self.record.revision_counter(),
            expires_at_tick: self
                .request_tick
                .saturating_add(u32::from(timeout_ticks)),
            last_counter: request_counter,
            last_activity_tick: self.request_tick,
            authorization_mode: role_to_authorization_mode(challenge.requested_role),
        });
        clear_challenge(&mut self.active_challenge);
        self.refresh_session_state();
        let payload = encode_auth_session_payload(
            session_id,
            challenge.requested_role,
            timeout_ticks,
            request_counter.saturating_add(1),
        );
        self.record_audit_event(
            AuditEventClass::Administrative,
            AuditEventCode::CommandCompleted,
            AuditResultClass::Success,
            &[CommandId::CompleteAuthentication as u8, challenge.requested_role as u8],
        );
        status_response(StatusCode::Success, &payload)
    }

    fn handle_get_session_status(&self) -> ProtocolFrame {
        let payload = encode_session_status_payload(current_session_status(
            self.active_session,
            self.developer_mode,
            self.request_tick,
            self.auth_snapshot.failure_counters.as_slice(),
        ));
        status_response(StatusCode::Success, &payload)
    }

    fn handle_invalidate_session(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        let (session_id, request_counter, inner) =
            match decode_authorized_payload(frame.payload.as_slice(), 0, 0) {
                Ok(values) => values,
                Err(status) => return status_response(status, &[]),
            };
        if !inner.is_empty() {
            return status_response(StatusCode::ValidationError, &[]);
        }
        let Some(session) = self.active_session.as_mut() else {
            return status_response(StatusCode::AuthorizationError, &[]);
        };
        if session.session_id != session_id || request_counter <= session.last_counter {
            return status_response(StatusCode::ReplayError, &[]);
        }
        let invalidated_role = session.role;
        self.invalidate_session();
        self.record_audit_event(
            AuditEventClass::Administrative,
            AuditEventCode::SessionInvalidated,
            AuditResultClass::Success,
            &[invalidated_role as u8],
        );
        status_response(StatusCode::Success, &[SessionLifecycleState::Inactive as u8])
    }

    fn handle_begin_provisioning(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        let (_, inner) = match self.authorize_privileged_owned::<16>(
            AuthorityRole::Bootstrap,
            frame.payload.as_slice(),
            1,
            16,
        ) {
            Ok(values) => values,
            Err(status) => return status_response(status, &[]),
        };
        match self.record.begin_provisioning(inner.as_slice(), frame.code) {
            Ok(result) => {
                self.invalidate_policy_tickets();
                self.record_audit_event(
                    AuditEventClass::LifecycleTransition,
                    AuditEventCode::CommandCompleted,
                    AuditResultClass::Success,
                    &[frame.code, result.state as u8],
                );
                let payload = encode_transition_result_payload(result);
                status_response(StatusCode::Success, &payload)
            }
            Err(status) => status_response(status, &[]),
        }
    }

    fn handle_finalize_provisioning(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        let (_, inner) = match self.authorize_privileged_owned::<5>(
            AuthorityRole::Bootstrap,
            frame.payload.as_slice(),
            5,
            5,
        ) {
            Ok(values) => values,
            Err(status) => return status_response(status, &[]),
        };
        let transition_id = match decode_transition_request(inner.as_slice(), finalize_marker()) {
            Ok(transition_id) => transition_id,
            Err(status) => return status_response(status, &[]),
        };

        match self.record.finalize_provisioning(transition_id) {
            Ok(result) => {
                self.invalidate_policy_tickets();
                self.record_audit_event(
                    AuditEventClass::LifecycleTransition,
                    AuditEventCode::CommandCompleted,
                    AuditResultClass::Success,
                    &[frame.code, result.state as u8],
                );
                let payload = encode_state_revision_payload(result);
                status_response(StatusCode::Success, &payload)
            }
            Err(status) => status_response(status, &[]),
        }
    }

    fn handle_lock_device(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        let (_, inner) = match self.authorize_privileged_owned::<1>(
            AuthorityRole::Administrator,
            frame.payload.as_slice(),
            1,
            1,
        ) {
            Ok(values) => values,
            Err(status) => return status_response(status, &[]),
        };
        match self.record.lock_device(inner[0]) {
            Ok(result) => {
                self.invalidate_policy_tickets();
                self.record_audit_event(
                    AuditEventClass::LifecycleTransition,
                    AuditEventCode::CommandCompleted,
                    AuditResultClass::Success,
                    &[frame.code, result.state as u8],
                );
                let payload = encode_lock_result_payload(result);
                self.invalidate_authenticated_session_only();
                status_response(StatusCode::Success, &payload)
            }
            Err(status) => status_response(status, &[]),
        }
    }

    fn handle_unlock_device(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        let (_, inner) = match self.authorize_privileged_owned::<1>(
            AuthorityRole::Administrator,
            frame.payload.as_slice(),
            1,
            1,
        ) {
            Ok(values) => values,
            Err(status) => return status_response(status, &[]),
        };
        if let Err(status) = expect_single_marker(inner.as_slice(), unlock_marker()) {
            return status_response(status, &[]);
        }

        match self.record.unlock_device() {
            Ok(result) => {
                self.invalidate_policy_tickets();
                self.record_audit_event(
                    AuditEventClass::LifecycleTransition,
                    AuditEventCode::CommandCompleted,
                    AuditResultClass::Success,
                    &[frame.code, result.state as u8],
                );
                let payload = encode_state_revision_payload(result);
                self.invalidate_authenticated_session_only();
                status_response(StatusCode::Success, &payload)
            }
            Err(status) => status_response(status, &[]),
        }
    }

    fn handle_enter_recovery(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        let (_, inner) = match self.authorize_privileged_owned::<1>(
            AuthorityRole::Recovery,
            frame.payload.as_slice(),
            1,
            1,
        ) {
            Ok(values) => values,
            Err(status) => return status_response(status, &[]),
        };
        if let Err(status) = expect_single_marker(inner.as_slice(), recovery_marker()) {
            return status_response(status, &[]);
        }

        match self.record.enter_recovery() {
            Ok(result) => {
                self.invalidate_policy_tickets();
                self.record_audit_event(
                    AuditEventClass::LifecycleTransition,
                    AuditEventCode::CommandCompleted,
                    AuditResultClass::Success,
                    &[frame.code, result.state as u8],
                );
                let payload = encode_recovery_result_payload(result);
                self.invalidate_authenticated_session_only();
                status_response(StatusCode::Success, &payload)
            }
            Err(status) => status_response(status, &[]),
        }
    }

    fn handle_recover_to_provisioned(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        let (_, inner) = match self.authorize_privileged_owned::<1>(
            AuthorityRole::Recovery,
            frame.payload.as_slice(),
            1,
            1,
        ) {
            Ok(values) => values,
            Err(status) => return status_response(status, &[]),
        };
        if let Err(status) = expect_single_marker(inner.as_slice(), recovery_marker()) {
            return status_response(status, &[]);
        }

        let approval_target = self.record.revision_counter();
        if let Err(response) = self.maybe_create_or_confirm_approval(
            ProtectedActionClass::RecoveryTransition,
            ApprovalTargetBinding::Device,
            approval_target,
            AuthorityRole::Recovery,
            self.record.revision_counter(),
        ) {
            return response;
        }

        match self.record.recover_to_provisioned() {
            Ok(result) => {
                self.consume_approval_ticket(
                    ProtectedActionClass::RecoveryTransition,
                    ApprovalTargetBinding::Device,
                    approval_target,
                );
                self.invalidate_policy_tickets();
                self.record_audit_event(
                    AuditEventClass::LifecycleTransition,
                    AuditEventCode::CommandCompleted,
                    AuditResultClass::Success,
                    &[frame.code, result.state as u8],
                );
                let payload = encode_transition_result_payload(result);
                self.invalidate_authenticated_session_only();
                status_response(StatusCode::Success, &payload)
            }
            Err(status) => status_response(status, &[]),
        }
    }

    fn handle_reactivate_recovered_provisioning(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        let (_, inner) = match self.authorize_privileged_owned::<5>(
            AuthorityRole::Recovery,
            frame.payload.as_slice(),
            5,
            5,
        ) {
            Ok(values) => values,
            Err(status) => return status_response(status, &[]),
        };
        let transition_id =
            match decode_transition_request(inner.as_slice(), reactivate_marker()) {
                Ok(transition_id) => transition_id,
                Err(status) => return status_response(status, &[]),
            };

        if let Err(response) = self.maybe_create_or_confirm_approval(
            ProtectedActionClass::RecoveryTransition,
            ApprovalTargetBinding::TransitionId,
            transition_id,
            AuthorityRole::Recovery,
            self.record.revision_counter(),
        ) {
            return response;
        }

        match self.record.reactivate_recovered_provisioning(transition_id) {
            Ok(result) => {
                self.consume_approval_ticket(
                    ProtectedActionClass::RecoveryTransition,
                    ApprovalTargetBinding::TransitionId,
                    transition_id,
                );
                self.invalidate_policy_tickets();
                self.record_audit_event(
                    AuditEventClass::LifecycleTransition,
                    AuditEventCode::CommandCompleted,
                    AuditResultClass::Success,
                    &[frame.code, result.state as u8],
                );
                let payload = encode_state_revision_payload(result);
                self.invalidate_authenticated_session_only();
                status_response(StatusCode::Success, &payload)
            }
            Err(status) => status_response(status, &[]),
        }
    }

    fn handle_execute_zeroize(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        let (_, inner) = match self.authorize_privileged_owned::<2>(
            AuthorityRole::Administrator,
            frame.payload.as_slice(),
            2,
            2,
        ) {
            Ok(values) => values,
            Err(status) => return status_response(status, &[]),
        };
        if let Err(status) = expect_marker_bytes(inner.as_slice(), &zeroize_marker()) {
            return status_response(status, &[]);
        }

        let approval_target = self.record.revision_counter();
        if let Err(response) = self.maybe_create_or_confirm_approval(
            ProtectedActionClass::DestructiveAdmin,
            ApprovalTargetBinding::Device,
            approval_target,
            AuthorityRole::Administrator,
            self.record.revision_counter(),
        ) {
            return response;
        }

        match self.record.execute_zeroize() {
            Ok(result) => {
                self.consume_approval_ticket(
                    ProtectedActionClass::DestructiveAdmin,
                    ApprovalTargetBinding::Device,
                    approval_target,
                );
                self.key_store = PersistentKeyStore::new(self.record.revision_counter());
                self.accepted_firmware = AcceptedFirmwareState::default();
                self.boot_slots = default_boot_slots(self.accepted_firmware);
                self.update_transfer = UpdateTransferState::default();
                self.recovery_state = RecoveryState::default();
                self.audit_journal.record(
                    AuditEventClass::LifecycleTransition,
                    AuditEventCode::CommandCompleted,
                    self.record.revision_counter(),
                    self.record.current_state(),
                    self.effective_actor_role(),
                    self.session_state,
                    AuditResultClass::Success,
                    &[frame.code, result.result_state as u8],
                );
                clear_approval_tickets(&mut self.approval_tickets);
                self.invalidate_authenticated_session_only();
                let payload = encode_zeroize_payload(result);
                status_response(StatusCode::Success, &payload)
            }
            Err(status) => status_response(status, &[]),
        }
    }

    fn handle_developer_reset(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        if let Err(status) = expect_marker_bytes(frame.payload.as_slice(), &developer_reset_marker())
        {
            return status_response(status, &[]);
        }

        let payload = encode_developer_reset_payload(self.record.developer_reset());
        self.key_store = PersistentKeyStore::new(self.record.revision_counter());
        self.audit_journal = AuditJournal::new();
        self.accepted_firmware = AcceptedFirmwareState::default();
        self.boot_slots = default_boot_slots(self.accepted_firmware);
        self.update_transfer = UpdateTransferState::default();
        self.recovery_state = RecoveryState::default();
        self.record_audit_event(
            AuditEventClass::Administrative,
            AuditEventCode::CommandCompleted,
            AuditResultClass::Success,
            &[frame.code, self.record.current_state() as u8],
        );
        clear_failure_counters(&mut self.auth_snapshot.failure_counters);
        clear_approval_tickets(&mut self.approval_tickets);
        self.invalidate_session();
        status_response(StatusCode::Success, &payload)
    }

    fn handle_put_persistent_key(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        let (_, inner) = match self.authorize_privileged_owned::<38>(
            AuthorityRole::KeyManager,
            frame.payload.as_slice(),
            7,
            38,
        ) {
            Ok(values) => values,
            Err(status) => return status_response(status, &[]),
        };
        let request = match decode_put_persistent_key_request(inner.as_slice()) {
            Ok(request) => request,
            Err(status) => return status_response(status, &[]),
        };

        match self.key_store.put_persistent_key(&request) {
            Ok(result) => {
                self.invalidate_policy_tickets();
                self.record_audit_event(
                    AuditEventClass::Administrative,
                    AuditEventCode::CommandCompleted,
                    AuditResultClass::Success,
                    &[frame.code, result.key_id],
                );
                let payload = encode_key_record_result_payload(result);
                status_response(StatusCode::Success, &payload)
            }
            Err(status) => status_response(status, &[]),
        }
    }

    fn handle_list_persistent_keys(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        if let Err(status) =
            self.authorize_privileged_owned::<0>(AuthorityRole::KeyManager, frame.payload.as_slice(), 0, 0)
        {
            return status_response(status, &[]);
        }
        match self.key_store.list_keys() {
            Ok(entries) => {
                let Some(payload) = encode_key_list_payload(entries.as_slice()) else {
                    return status_response(StatusCode::InternalError, &[]);
                };
                status_response(StatusCode::Success, &payload)
            }
            Err(status) => status_response(status, &[]),
        }
    }

    fn handle_get_key_metadata(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        let (_, inner) = match self.authorize_privileged_owned::<1>(
            AuthorityRole::KeyManager,
            frame.payload.as_slice(),
            1,
            1,
        ) {
            Ok(values) => values,
            Err(status) => return status_response(status, &[]),
        };
        let key_id = match decode_key_id_request(inner.as_slice()) {
            Ok(key_id) => key_id,
            Err(status) => return status_response(status, &[]),
        };

        match self.key_store.get_key_metadata(key_id) {
            Ok(view) => match encode_key_metadata_payload(&view) {
                Some(payload) => status_response(StatusCode::Success, &payload),
                None => status_response(StatusCode::InternalError, &[]),
            },
            Err(status) => status_response(status, &[]),
        }
    }

    fn handle_revoke_persistent_key(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        let (_, inner) = match self.authorize_privileged_owned::<3>(
            AuthorityRole::KeyManager,
            frame.payload.as_slice(),
            2,
            3,
        ) {
            Ok(values) => values,
            Err(status) => return status_response(status, &[]),
        };
        let key_id = match decode_key_marker_request(inner.as_slice(), &[revoke_marker()]) {
            Ok(key_id) => key_id,
            Err(status) => return status_response(status, &[]),
        };

        match self.key_store.revoke_key(key_id) {
            Ok(result) => {
                self.invalidate_policy_tickets();
                self.record_audit_event(
                    AuditEventClass::Administrative,
                    AuditEventCode::CommandCompleted,
                    AuditResultClass::Success,
                    &[frame.code, result.key_id],
                );
                let payload = encode_key_record_result_payload(result);
                status_response(StatusCode::Success, &payload)
            }
            Err(status) => status_response(status, &[]),
        }
    }

    fn handle_destroy_persistent_key(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        let (_, inner) = match self.authorize_privileged_owned::<3>(
            AuthorityRole::KeyManager,
            frame.payload.as_slice(),
            3,
            3,
        ) {
            Ok(values) => values,
            Err(status) => return status_response(status, &[]),
        };
        let key_id =
            match decode_key_marker_request(inner.as_slice(), &zeroize_marker()) {
                Ok(key_id) => key_id,
                Err(status) => return status_response(status, &[]),
            };

        let metadata = match self.key_store.get_key_metadata(key_id) {
            Ok(view) => view,
            Err(status) => return status_response(status, &[]),
        };
        let key_policy = evaluate_key_policy(
            &metadata,
            None,
            0,
            false,
            &[KeyLifecycleState::Active, KeyLifecycleState::Revoked],
        );
        if !key_policy.decision {
            return policy_status_response(
                status_for_denial_class(key_policy.denial_class),
                key_policy.denial_class,
                None,
            );
        }
        if let Err(response) = self.maybe_create_or_confirm_approval(
            ProtectedActionClass::DestructiveKey,
            ApprovalTargetBinding::KeyId,
            u32::from(key_id),
            AuthorityRole::KeyManager,
            metadata.record_revision,
        ) {
            return response;
        }

        match self.key_store.destroy_key(key_id) {
            Ok(result) => {
                self.consume_approval_ticket(
                    ProtectedActionClass::DestructiveKey,
                    ApprovalTargetBinding::KeyId,
                    u32::from(key_id),
                );
                self.invalidate_policy_tickets();
                self.record_audit_event(
                    AuditEventClass::Administrative,
                    AuditEventCode::CommandCompleted,
                    AuditResultClass::Success,
                    &[frame.code, result.key_id],
                );
                let payload = encode_key_destroy_payload(result);
                status_response(StatusCode::Success, &payload)
            }
            Err(status) => status_response(status, &[]),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn handle_generate_key(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        let (_, inner) = match self.authorize_privileged_owned::<3>(
            AuthorityRole::KeyManager,
            frame.payload.as_slice(),
            2,
            3,
        ) {
            Ok(values) => values,
            Err(status) => return status_response(status, &[]),
        };
        let request = match decode_generate_key_request(inner.as_slice()) {
            Ok(request) => request,
            Err(status) => return status_response(status, &[]),
        };

        let export_policy = match request.algorithm {
            KeyAlgorithm::Ed25519
            | KeyAlgorithm::P256
            | KeyAlgorithm::P256EcdhHkdfSha256
            | KeyAlgorithm::HmacSha256
            | KeyAlgorithm::X25519ChaCha20Poly1305
            | KeyAlgorithm::ChaCha20Poly1305
            | KeyAlgorithm::Aes256Gcm => request.export_policy,
        };
        let (expected_usage_mask, material_bytes) = match request.algorithm {
            KeyAlgorithm::Ed25519 => {
                if request.usage_mask != USAGE_SIGN {
                    return status_response(StatusCode::AuthorizationError, &[]);
                }
                let bytes = match self
                    .crypto_state
                    .generate_random_bytes(super::state::MAX_KEY_MATERIAL_LEN)
                {
                    Ok(bytes) => bytes,
                    Err(StatusCode::StateError) => return status_response(StatusCode::InternalError, &[]),
                    Err(status) => return status_response(status, &[]),
                };
                (USAGE_SIGN, bytes)
            }
            KeyAlgorithm::P256 => {
                if request.usage_mask != USAGE_SIGN {
                    return status_response(StatusCode::AuthorizationError, &[]);
                }
                let bytes = match self
                    .crypto_state
                    .generate_random_bytes(super::state::MAX_KEY_MATERIAL_LEN)
                {
                    Ok(bytes) => bytes,
                    Err(StatusCode::StateError) => {
                        return status_response(StatusCode::InternalError, &[]);
                    }
                    Err(status) => return status_response(status, &[]),
                };
                (USAGE_SIGN, bytes)
            }
            KeyAlgorithm::ChaCha20Poly1305 => {
                if request.usage_mask != (USAGE_ENCRYPT | USAGE_DECRYPT) {
                    return status_response(StatusCode::AuthorizationError, &[]);
                }
                let bytes = match self
                    .crypto_state
                    .generate_random_bytes(super::state::CHACHA20POLY1305_KEY_LEN)
                {
                    Ok(bytes) => bytes,
                    Err(StatusCode::StateError) => return status_response(StatusCode::InternalError, &[]),
                    Err(status) => return status_response(status, &[]),
                };
                (USAGE_ENCRYPT | USAGE_DECRYPT, bytes)
            }
            KeyAlgorithm::Aes256Gcm => {
                if request.usage_mask != (USAGE_ENCRYPT | USAGE_DECRYPT) {
                    return status_response(StatusCode::AuthorizationError, &[]);
                }
                let bytes = match self
                    .crypto_state
                    .generate_random_bytes(super::state::AES256GCM_KEY_LEN)
                {
                    Ok(bytes) => bytes,
                    Err(StatusCode::StateError) => {
                        return status_response(StatusCode::InternalError, &[]);
                    }
                    Err(status) => return status_response(status, &[]),
                };
                (USAGE_ENCRYPT | USAGE_DECRYPT, bytes)
            }
            KeyAlgorithm::X25519ChaCha20Poly1305 => {
                if request.usage_mask != (USAGE_ENCRYPT | USAGE_DECRYPT) {
                    return status_response(StatusCode::AuthorizationError, &[]);
                }
                let bytes = match self
                    .crypto_state
                    .generate_random_bytes(super::state::MAX_KEY_MATERIAL_LEN)
                {
                    Ok(bytes) => bytes,
                    Err(StatusCode::StateError) => {
                        return status_response(StatusCode::InternalError, &[]);
                    }
                    Err(status) => return status_response(status, &[]),
                };
                (USAGE_ENCRYPT | USAGE_DECRYPT, bytes)
            }
            KeyAlgorithm::HmacSha256 => {
                if request.usage_mask != USAGE_MAC {
                    return status_response(StatusCode::AuthorizationError, &[]);
                }
                let bytes = match self
                    .crypto_state
                    .generate_random_bytes(super::state::MAX_KEY_MATERIAL_LEN)
                {
                    Ok(bytes) => bytes,
                    Err(StatusCode::StateError) => {
                        return status_response(StatusCode::InternalError, &[]);
                    }
                    Err(status) => return status_response(status, &[]),
                };
                (USAGE_MAC, bytes)
            }
            KeyAlgorithm::P256EcdhHkdfSha256 => {
                if request.usage_mask != USAGE_DERIVE {
                    return status_response(StatusCode::AuthorizationError, &[]);
                }
                let bytes = match self
                    .crypto_state
                    .generate_random_bytes(super::state::MAX_KEY_MATERIAL_LEN)
                {
                    Ok(bytes) => bytes,
                    Err(StatusCode::StateError) => {
                        return status_response(StatusCode::InternalError, &[]);
                    }
                    Err(status) => return status_response(status, &[]),
                };
                (USAGE_DERIVE, bytes)
            }
        };

        match self.key_store.store_generated_key(
            request.algorithm,
            expected_usage_mask,
            export_policy,
            material_bytes.as_slice(),
        ) {
            Ok(result) => {
                self.record_audit_event(
                    AuditEventClass::Administrative,
                    AuditEventCode::CommandCompleted,
                    AuditResultClass::Success,
                    &[frame.code, result.key_id, request.algorithm as u8],
                );
                status_response(StatusCode::Success, &encode_key_record_result_payload(result))
            }
            Err(status) => status_response(status, &[]),
        }
    }

    fn handle_sign_detached(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        let (_, mut inner) = match self.authorize_privileged_owned::<140>(
            AuthorityRole::KeyManager,
            frame.payload.as_slice(),
            5,
            132,
        ) {
            Ok(values) => values,
            Err(status) => return status_response(status, &[]),
        };
        let request = match decode_sign_request(inner.as_slice()) {
            Ok(request) => request,
            Err(status) => {
                clear_bytes(inner.as_mut_slice());
                return status_response(status, &[]);
            }
        };
        let metadata = match self.key_store.get_key_metadata(request.key_id) {
            Ok(view) => view,
            Err(status) => {
                clear_bytes(inner.as_mut_slice());
                return status_response(status, &[]);
            }
        };
        let key_policy = evaluate_key_policy(
            &metadata,
            Some(request.algorithm),
            USAGE_SIGN,
            false,
            &[KeyLifecycleState::Active],
        );
        if !key_policy.decision {
            clear_bytes(inner.as_mut_slice());
            return policy_status_response(
                status_for_denial_class(key_policy.denial_class),
                key_policy.denial_class,
                None,
            );
        }

        let mut key_bytes = match self
            .key_store
            .export_key_material_for_operation(request.key_id, request.algorithm, USAGE_SIGN, false)
        {
            Ok(material) => material,
            Err(status) => {
                clear_bytes(inner.as_mut_slice());
                return status_response(status, &[]);
            }
        };
        let response = match request.algorithm {
            KeyAlgorithm::Ed25519 => {
                let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
                let signature = signing_key.sign(request.message.as_slice()).to_bytes();
                match encode_signature_payload(&signature) {
                    Some(payload) => status_response(StatusCode::Success, &payload),
                    None => status_response(StatusCode::InternalError, &[]),
                }
            }
            KeyAlgorithm::P256 => {
                let Ok(signing_key) = P256SigningKey::from_slice(&key_bytes) else {
                    clear_secret_array(&mut key_bytes);
                    clear_bytes(inner.as_mut_slice());
                    return status_response(StatusCode::InternalError, &[]);
                };
                let signature: P256Signature = signing_key.sign(request.message.as_slice());
                match encode_signature_payload(signature.to_bytes().as_slice()) {
                    Some(payload) => status_response(StatusCode::Success, &payload),
                    None => status_response(StatusCode::InternalError, &[]),
                }
            }
            KeyAlgorithm::ChaCha20Poly1305
            | KeyAlgorithm::Aes256Gcm
            | KeyAlgorithm::X25519ChaCha20Poly1305
            | KeyAlgorithm::HmacSha256
            | KeyAlgorithm::P256EcdhHkdfSha256 => {
                status_response(StatusCode::AuthorizationError, &[])
            }
        };
        self.record_audit_event(
            AuditEventClass::Administrative,
            AuditEventCode::CommandCompleted,
            AuditResultClass::Success,
            &[frame.code, request.key_id],
        );
        clear_secret_array(&mut key_bytes);
        clear_bytes(inner.as_mut_slice());
        response
    }

    #[allow(clippy::single_match_else)]
    fn handle_generate_mac(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        let (_, mut inner) = match self.authorize_privileged_owned::<140>(
            AuthorityRole::KeyManager,
            frame.payload.as_slice(),
            5,
            132,
        ) {
            Ok(values) => values,
            Err(status) => return status_response(status, &[]),
        };
        let request = match decode_mac_request(inner.as_slice()) {
            Ok(request) => request,
            Err(status) => {
                clear_bytes(inner.as_mut_slice());
                return status_response(status, &[]);
            }
        };
        let metadata = match self.key_store.get_key_metadata(request.key_id) {
            Ok(view) => view,
            Err(status) => {
                clear_bytes(inner.as_mut_slice());
                return status_response(status, &[]);
            }
        };
        let key_policy = evaluate_key_policy(
            &metadata,
            Some(request.algorithm),
            USAGE_MAC,
            false,
            &[KeyLifecycleState::Active],
        );
        if !key_policy.decision {
            clear_bytes(inner.as_mut_slice());
            return policy_status_response(
                status_for_denial_class(key_policy.denial_class),
                key_policy.denial_class,
                None,
            );
        }
        let mut key_bytes = match self
            .key_store
            .export_key_material_for_operation(request.key_id, request.algorithm, USAGE_MAC, false)
        {
            Ok(material) => material,
            Err(status) => {
                clear_bytes(inner.as_mut_slice());
                return status_response(status, &[]);
            }
        };
        let response = match request.algorithm {
            KeyAlgorithm::HmacSha256 => {
                let mut mac: HmacSha256 =
                    if let Ok(mac) = <HmacSha256 as Mac>::new_from_slice(&key_bytes) {
                        mac
                    } else {
                        clear_secret_array(&mut key_bytes);
                        clear_bytes(inner.as_mut_slice());
                        return status_response(StatusCode::InternalError, &[]);
                    };
                mac.update(request.message.as_slice());
                let result = mac.finalize().into_bytes();
                match encode_mac_payload(result.as_slice()) {
                    Some(payload) => status_response(StatusCode::Success, &payload),
                    None => status_response(StatusCode::InternalError, &[]),
                }
            }
            _ => status_response(StatusCode::AuthorizationError, &[]),
        };
        self.record_audit_event(
            AuditEventClass::Administrative,
            AuditEventCode::CommandCompleted,
            AuditResultClass::Success,
            &[frame.code, request.key_id],
        );
        clear_secret_array(&mut key_bytes);
        clear_bytes(inner.as_mut_slice());
        response
    }

    #[allow(clippy::single_match_else)]
    fn handle_verify_mac(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        let (_, mut inner) = match self.authorize_privileged_owned::<173>(
            AuthorityRole::KeyManager,
            frame.payload.as_slice(),
            6,
            165,
        ) {
            Ok(values) => values,
            Err(status) => return status_response(status, &[]),
        };
        let request = match decode_verify_mac_request(inner.as_slice()) {
            Ok(request) => request,
            Err(status) => {
                clear_bytes(inner.as_mut_slice());
                return status_response(status, &[]);
            }
        };
        let metadata = match self.key_store.get_key_metadata(request.key_id) {
            Ok(view) => view,
            Err(status) => {
                clear_bytes(inner.as_mut_slice());
                return status_response(status, &[]);
            }
        };
        let key_policy = evaluate_key_policy(
            &metadata,
            Some(request.algorithm),
            USAGE_MAC,
            false,
            &[KeyLifecycleState::Active],
        );
        if !key_policy.decision {
            clear_bytes(inner.as_mut_slice());
            return policy_status_response(
                status_for_denial_class(key_policy.denial_class),
                key_policy.denial_class,
                None,
            );
        }
        let mut key_bytes = match self
            .key_store
            .export_key_material_for_operation(request.key_id, request.algorithm, USAGE_MAC, false)
        {
            Ok(material) => material,
            Err(status) => {
                clear_bytes(inner.as_mut_slice());
                return status_response(status, &[]);
            }
        };
        let verified = if request.algorithm == KeyAlgorithm::HmacSha256 {
            let mut mac: HmacSha256 =
                if let Ok(mac) = <HmacSha256 as Mac>::new_from_slice(&key_bytes) {
                    mac
                } else {
                    clear_secret_array(&mut key_bytes);
                    clear_bytes(inner.as_mut_slice());
                    return status_response(StatusCode::InternalError, &[]);
                };
            mac.update(request.message.as_slice());
            mac.verify_slice(request.mac.as_slice()).is_ok()
        } else {
            clear_secret_array(&mut key_bytes);
            clear_bytes(inner.as_mut_slice());
            return status_response(StatusCode::AuthorizationError, &[]);
        };
        let payload = encode_verify_result_payload(verified);
        self.record_audit_event(
            AuditEventClass::Administrative,
            AuditEventCode::CommandCompleted,
            AuditResultClass::Success,
            &[frame.code, request.key_id, u8::from(verified)],
        );
        clear_secret_array(&mut key_bytes);
        clear_bytes(inner.as_mut_slice());
        status_response(StatusCode::Success, &payload)
    }

    #[allow(clippy::too_many_lines)]
    fn handle_encrypt(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        let (_, mut inner) = match self.authorize_privileged_owned::<132>(
            AuthorityRole::KeyManager,
            frame.payload.as_slice(),
            4,
            132,
        ) {
            Ok(values) => values,
            Err(status) => return status_response(status, &[]),
        };
        let request = match decode_encrypt_request(inner.as_slice()) {
            Ok(request) => request,
            Err(status) => {
                clear_bytes(inner.as_mut_slice());
                return status_response(status, &[]);
            }
        };
        let metadata = match self.key_store.get_key_metadata(request.key_id) {
            Ok(view) => view,
            Err(status) => {
                clear_bytes(inner.as_mut_slice());
                return status_response(status, &[]);
            }
        };
        let key_policy = evaluate_key_policy(
            &metadata,
            Some(request.algorithm),
            USAGE_ENCRYPT,
            false,
            &[KeyLifecycleState::Active],
        );
        if !key_policy.decision {
            clear_bytes(inner.as_mut_slice());
            return policy_status_response(
                status_for_denial_class(key_policy.denial_class),
                key_policy.denial_class,
                None,
            );
        }
        let mut key_bytes = match self.key_store.export_key_material_for_operation(
            request.key_id,
            request.algorithm,
            USAGE_ENCRYPT,
            false,
        ) {
            Ok(material) => material,
            Err(status) => {
                clear_bytes(inner.as_mut_slice());
                return status_response(status, &[]);
            }
        };
        let mut ciphertext = request.plaintext.clone();
        let mut tag_bytes = Vec::<u8, { super::state::AES256GCM_TAG_LEN }>::new();
        let mut response_nonce = Vec::<u8, { super::state::MAX_ENCRYPT_HEADER_LEN }>::new();
        match request.algorithm {
            KeyAlgorithm::ChaCha20Poly1305 => {
                let nonce_bytes = match self
                    .crypto_state
                    .generate_random_bytes(super::state::CHACHA20POLY1305_NONCE_LEN)
                {
                    Ok(bytes) => bytes,
                    Err(StatusCode::StateError) => {
                        clear_secret_array(&mut key_bytes);
                        clear_bytes(inner.as_mut_slice());
                        return status_response(StatusCode::InternalError, &[]);
                    }
                    Err(status) => {
                        clear_secret_array(&mut key_bytes);
                        clear_bytes(inner.as_mut_slice());
                        return status_response(status, &[]);
                    }
                };
                let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&key_bytes));
                let nonce = GenericArray::from_slice(nonce_bytes.as_slice());
                let Ok(tag) = cipher.encrypt_in_place_detached(nonce, b"", ciphertext.as_mut_slice()) else {
                    clear_secret_array(&mut key_bytes);
                    clear_bytes(inner.as_mut_slice());
                    return status_response(StatusCode::InternalError, &[]);
                };
                if tag_bytes.extend_from_slice(tag.as_slice()).is_err() {
                    clear_secret_array(&mut key_bytes);
                    clear_bytes(inner.as_mut_slice());
                    return status_response(StatusCode::InternalError, &[]);
                }
                if response_nonce.extend_from_slice(nonce_bytes.as_slice()).is_err() {
                    clear_secret_array(&mut key_bytes);
                    clear_bytes(inner.as_mut_slice());
                    return status_response(StatusCode::InternalError, &[]);
                }
            }
            KeyAlgorithm::Aes256Gcm => {
                let nonce_bytes = match self
                    .crypto_state
                    .generate_random_bytes(super::state::AES256GCM_NONCE_LEN)
                {
                    Ok(bytes) => bytes,
                    Err(StatusCode::StateError) => {
                        clear_secret_array(&mut key_bytes);
                        clear_bytes(inner.as_mut_slice());
                        return status_response(StatusCode::InternalError, &[]);
                    }
                    Err(status) => {
                        clear_secret_array(&mut key_bytes);
                        clear_bytes(inner.as_mut_slice());
                        return status_response(status, &[]);
                    }
                };
                let cipher = Aes256Gcm::new(AesGenericArray::from_slice(&key_bytes));
                let nonce = AesGenericArray::from_slice(nonce_bytes.as_slice());
                let Ok(tag) = cipher.encrypt_in_place_detached(nonce, b"", ciphertext.as_mut_slice()) else {
                    clear_secret_array(&mut key_bytes);
                    clear_bytes(inner.as_mut_slice());
                    return status_response(StatusCode::InternalError, &[]);
                };
                if tag_bytes.extend_from_slice(tag.as_slice()).is_err() {
                    clear_secret_array(&mut key_bytes);
                    clear_bytes(inner.as_mut_slice());
                    return status_response(StatusCode::InternalError, &[]);
                }
                if response_nonce.extend_from_slice(nonce_bytes.as_slice()).is_err() {
                    clear_secret_array(&mut key_bytes);
                    clear_bytes(inner.as_mut_slice());
                    return status_response(StatusCode::InternalError, &[]);
                }
            }
            KeyAlgorithm::X25519ChaCha20Poly1305 => {
                let mut recipient_secret_bytes = [0u8; super::state::MAX_KEY_MATERIAL_LEN];
                recipient_secret_bytes.copy_from_slice(&key_bytes);
                let recipient_secret = X25519StaticSecret::from(recipient_secret_bytes);
                let recipient_public = X25519PublicKey::from(&recipient_secret);
                let ephemeral_seed = match self
                    .crypto_state
                    .generate_random_bytes(super::state::MAX_KEY_MATERIAL_LEN)
                {
                    Ok(bytes) => bytes,
                    Err(StatusCode::StateError) => {
                        clear_secret_array(&mut recipient_secret_bytes);
                        clear_bytes(inner.as_mut_slice());
                        return status_response(StatusCode::InternalError, &[]);
                    }
                    Err(status) => {
                        clear_secret_array(&mut recipient_secret_bytes);
                        clear_bytes(inner.as_mut_slice());
                        return status_response(status, &[]);
                    }
                };
                let nonce_bytes = match self
                    .crypto_state
                    .generate_random_bytes(super::state::CHACHA20POLY1305_NONCE_LEN)
                {
                    Ok(bytes) => bytes,
                    Err(StatusCode::StateError) => {
                        clear_bytes(inner.as_mut_slice());
                        return status_response(StatusCode::InternalError, &[]);
                    }
                    Err(status) => {
                        clear_bytes(inner.as_mut_slice());
                        return status_response(status, &[]);
                    }
                };
                let mut ephemeral_secret_bytes = [0u8; super::state::MAX_KEY_MATERIAL_LEN];
                ephemeral_secret_bytes.copy_from_slice(ephemeral_seed.as_slice());
                let ephemeral_secret = X25519StaticSecret::from(ephemeral_secret_bytes);
                let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
                let shared_secret = ephemeral_secret.diffie_hellman(&recipient_public);
                let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
                let mut derived_key = [0u8; super::state::CHACHA20POLY1305_KEY_LEN];
                if hk
                    .expand(ASYMMETRIC_ENCRYPT_INFO, &mut derived_key)
                    .is_err()
                {
                    clear_secret_array(&mut recipient_secret_bytes);
                    clear_secret_array(&mut ephemeral_secret_bytes);
                    clear_secret_array(&mut derived_key);
                    clear_bytes(inner.as_mut_slice());
                    return status_response(StatusCode::InternalError, &[]);
                }
                let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&derived_key));
                let nonce = GenericArray::from_slice(nonce_bytes.as_slice());
                let Ok(tag) = cipher.encrypt_in_place_detached(nonce, b"", ciphertext.as_mut_slice()) else {
                    clear_secret_array(&mut recipient_secret_bytes);
                    clear_secret_array(&mut ephemeral_secret_bytes);
                    clear_secret_array(&mut derived_key);
                    clear_bytes(inner.as_mut_slice());
                    return status_response(StatusCode::InternalError, &[]);
                };
                if response_nonce.extend_from_slice(ephemeral_public.as_bytes()).is_err()
                    || response_nonce.extend_from_slice(nonce_bytes.as_slice()).is_err()
                    || tag_bytes.extend_from_slice(tag.as_slice()).is_err()
                {
                    clear_secret_array(&mut recipient_secret_bytes);
                    clear_secret_array(&mut ephemeral_secret_bytes);
                    clear_secret_array(&mut derived_key);
                    clear_bytes(inner.as_mut_slice());
                    return status_response(StatusCode::InternalError, &[]);
                }
                clear_secret_array(&mut recipient_secret_bytes);
                clear_secret_array(&mut ephemeral_secret_bytes);
                clear_secret_array(&mut derived_key);
            }
            KeyAlgorithm::Ed25519
            | KeyAlgorithm::P256
            | KeyAlgorithm::HmacSha256
            | KeyAlgorithm::P256EcdhHkdfSha256 => {
                clear_secret_array(&mut key_bytes);
                clear_bytes(inner.as_mut_slice());
                return status_response(StatusCode::AuthorizationError, &[]);
            }
        }
        if ciphertext.extend_from_slice(tag_bytes.as_slice()).is_err() {
            clear_secret_array(&mut key_bytes);
            clear_bytes(inner.as_mut_slice());
            return status_response(StatusCode::InternalError, &[]);
        }
        let mut encoded_ciphertext = Vec::<u8, { super::state::MAX_CIPHERTEXT_LEN }>::new();
        if encoded_ciphertext
            .extend_from_slice(ciphertext.as_slice())
            .is_err()
        {
            clear_secret_array(&mut key_bytes);
            clear_bytes(inner.as_mut_slice());
            return status_response(StatusCode::InternalError, &[]);
        }
        let response_payload = encode_encrypt_response_payload(&EncryptResponse {
            nonce: response_nonce,
            ciphertext: encoded_ciphertext,
        });
        self.record_audit_event(
            AuditEventClass::Administrative,
            AuditEventCode::CommandCompleted,
            AuditResultClass::Success,
            &[frame.code, request.key_id],
        );
        clear_secret_array(&mut key_bytes);
        clear_bytes(inner.as_mut_slice());
        match response_payload {
            Some(payload) => status_response(StatusCode::Success, &payload),
            None => status_response(StatusCode::InternalError, &[]),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn handle_decrypt(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        let (_, mut inner) = match self.authorize_privileged_owned::<199>(
            AuthorityRole::KeyManager,
            frame.payload.as_slice(),
            18,
            199,
        ) {
            Ok(values) => values,
            Err(status) => return status_response(status, &[]),
        };
        let request = match decode_decrypt_request(inner.as_slice()) {
            Ok(request) => request,
            Err(status) => {
                clear_bytes(inner.as_mut_slice());
                return status_response(status, &[]);
            }
        };
        let metadata = match self.key_store.get_key_metadata(request.key_id) {
            Ok(view) => view,
            Err(status) => {
                clear_bytes(inner.as_mut_slice());
                return status_response(status, &[]);
            }
        };
        let key_policy = evaluate_key_policy(
            &metadata,
            Some(request.algorithm),
            USAGE_DECRYPT,
            false,
            &[KeyLifecycleState::Active],
        );
        if !key_policy.decision {
            clear_bytes(inner.as_mut_slice());
            return policy_status_response(
                status_for_denial_class(key_policy.denial_class),
                key_policy.denial_class,
                None,
            );
        }
        let mut key_bytes = match self.key_store.export_key_material_for_operation(
            request.key_id,
            request.algorithm,
            USAGE_DECRYPT,
            false,
        ) {
            Ok(material) => material,
            Err(status) => {
                clear_bytes(inner.as_mut_slice());
                return status_response(status, &[]);
            }
        };
        if request.ciphertext.len() < super::state::CHACHA20POLY1305_TAG_LEN {
            clear_secret_array(&mut key_bytes);
            clear_bytes(inner.as_mut_slice());
            return status_response(StatusCode::ValidationError, &[]);
        }
        let split_at = request
            .ciphertext
            .len()
            .saturating_sub(super::state::CHACHA20POLY1305_TAG_LEN);
        let mut plaintext = Vec::<u8, { super::state::MAX_CRYPTO_MESSAGE_LEN }>::new();
        if plaintext
            .extend_from_slice(&request.ciphertext.as_slice()[..split_at])
            .is_err()
        {
            clear_secret_array(&mut key_bytes);
            clear_bytes(inner.as_mut_slice());
            return status_response(StatusCode::InternalError, &[]);
        }
        let decrypt_result = match request.algorithm {
            KeyAlgorithm::ChaCha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&key_bytes));
                let nonce = GenericArray::from_slice(request.nonce.as_slice());
                let tag =
                    chacha20poly1305::Tag::from_slice(&request.ciphertext.as_slice()[split_at..]);
                cipher.decrypt_in_place_detached(nonce, b"", plaintext.as_mut_slice(), tag)
            }
            KeyAlgorithm::Aes256Gcm => {
                let cipher = Aes256Gcm::new(AesGenericArray::from_slice(&key_bytes));
                let nonce = AesGenericArray::from_slice(request.nonce.as_slice());
                let tag = aes_gcm::Tag::from_slice(&request.ciphertext.as_slice()[split_at..]);
                cipher.decrypt_in_place_detached(nonce, b"", plaintext.as_mut_slice(), tag)
            }
            KeyAlgorithm::X25519ChaCha20Poly1305 => {
                if request.nonce.len() != X25519_ENVELOPE_HEADER_LEN {
                    clear_secret_array(&mut key_bytes);
                    clear_bytes(inner.as_mut_slice());
                    return status_response(StatusCode::ValidationError, &[]);
                }
                let mut recipient_secret_bytes = [0u8; super::state::MAX_KEY_MATERIAL_LEN];
                recipient_secret_bytes.copy_from_slice(&key_bytes);
                let recipient_secret = X25519StaticSecret::from(recipient_secret_bytes);
                let mut ephemeral_public_bytes = [0u8; X25519_PUBLIC_KEY_LEN];
                ephemeral_public_bytes.copy_from_slice(&request.nonce.as_slice()[..X25519_PUBLIC_KEY_LEN]);
                let ephemeral_public = X25519PublicKey::from(ephemeral_public_bytes);
                let shared_secret = recipient_secret.diffie_hellman(&ephemeral_public);
                let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
                let mut derived_key = [0u8; super::state::CHACHA20POLY1305_KEY_LEN];
                if hk
                    .expand(ASYMMETRIC_ENCRYPT_INFO, &mut derived_key)
                    .is_err()
                {
                    clear_secret_array(&mut recipient_secret_bytes);
                    clear_secret_array(&mut derived_key);
                    clear_bytes(inner.as_mut_slice());
                    return status_response(StatusCode::InternalError, &[]);
                }
                let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&derived_key));
                let nonce = GenericArray::from_slice(
                    &request.nonce.as_slice()[X25519_PUBLIC_KEY_LEN..X25519_ENVELOPE_HEADER_LEN],
                );
                let tag =
                    chacha20poly1305::Tag::from_slice(&request.ciphertext.as_slice()[split_at..]);
                let result = cipher.decrypt_in_place_detached(
                    nonce,
                    b"",
                    plaintext.as_mut_slice(),
                    tag,
                );
                clear_secret_array(&mut recipient_secret_bytes);
                clear_secret_array(&mut derived_key);
                result
            }
            KeyAlgorithm::Ed25519
            | KeyAlgorithm::P256
            | KeyAlgorithm::HmacSha256
            | KeyAlgorithm::P256EcdhHkdfSha256 => {
                clear_secret_array(&mut key_bytes);
                clear_bytes(inner.as_mut_slice());
                return status_response(StatusCode::AuthorizationError, &[]);
            }
        };
        clear_secret_array(&mut key_bytes);
        clear_bytes(inner.as_mut_slice());
        match decrypt_result {
            Ok(()) => {
                self.record_audit_event(
                    AuditEventClass::Administrative,
                    AuditEventCode::CommandCompleted,
                    AuditResultClass::Success,
                    &[frame.code, request.key_id],
                );
                match encode_decrypt_response_payload(&DecryptResponse { plaintext }) {
                    Some(payload) => status_response(StatusCode::Success, &payload),
                    None => status_response(StatusCode::InternalError, &[]),
                }
            }
            Err(_) => status_response(StatusCode::ValidationError, &[]),
        }
    }

    fn handle_verify_detached(frame: &ProtocolFrame) -> ProtocolFrame {
        let request = match decode_verify_request(frame.payload.as_slice()) {
            Ok(request) => request,
            Err(status) => return status_response(status, &[]),
        };
        let verified = match request.algorithm {
            KeyAlgorithm::Ed25519 => {
                if request.public_key.len() != 32 || request.signature.len() != 64 {
                    return status_response(StatusCode::ValidationError, &[]);
                }
                let Ok(verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(
                    request.public_key.as_slice().try_into().unwrap_or(&[0; 32]),
                ) else {
                    return status_response(StatusCode::ValidationError, &[]);
                };
                let Ok(signature) = ed25519_dalek::Signature::from_slice(request.signature.as_slice()) else {
                    return status_response(StatusCode::ValidationError, &[]);
                };
                verifying_key.verify(request.message.as_slice(), &signature).is_ok()
            }
            KeyAlgorithm::P256 => {
                if request.public_key.len() != 33 || request.signature.len() != 64 {
                    return status_response(StatusCode::ValidationError, &[]);
                }
                let Ok(verifying_key) =
                    P256VerifyingKey::from_sec1_bytes(request.public_key.as_slice())
                else {
                    return status_response(StatusCode::ValidationError, &[]);
                };
                let Ok(signature) = P256Signature::from_slice(request.signature.as_slice()) else {
                    return status_response(StatusCode::ValidationError, &[]);
                };
                verifying_key.verify(request.message.as_slice(), &signature).is_ok()
            }
            KeyAlgorithm::ChaCha20Poly1305
            | KeyAlgorithm::Aes256Gcm
            | KeyAlgorithm::X25519ChaCha20Poly1305
            | KeyAlgorithm::HmacSha256
            | KeyAlgorithm::P256EcdhHkdfSha256 => {
                return status_response(StatusCode::AuthorizationError, &[])
            }
        };
        let payload = encode_verify_result_payload(verified);
        status_response(StatusCode::Success, &payload)
    }

    fn handle_generate_random(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        let (_, inner, _) = match self.authorize_any_owned::<1>(
            &[AuthorityRole::Administrator, AuthorityRole::KeyManager],
            frame.payload.as_slice(),
            1,
            1,
        ) {
            Ok(values) => values,
            Err(status) => return status_response(status, &[]),
        };
        let request = match decode_random_request(inner.as_slice()) {
            Ok(request) => request,
            Err(status) => return status_response(status, &[]),
        };
        match self
            .crypto_state
            .generate_random_bytes(usize::from(request.requested_len))
        {
            Ok(bytes) => match encode_random_payload(bytes.as_slice()) {
                Some(payload) => {
                    self.record_audit_event(
                        AuditEventClass::Administrative,
                        AuditEventCode::CommandCompleted,
                        AuditResultClass::Success,
                        &[frame.code, request.requested_len],
                    );
                    status_response(StatusCode::Success, &payload)
                }
                None => status_response(StatusCode::InternalError, &[]),
            },
            Err(StatusCode::StateError) => status_response(StatusCode::InternalError, &[]),
            Err(status) => status_response(status, &[]),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn handle_import_wrapped_key(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        let (_, mut inner) = match self.authorize_privileged_owned::<96>(
            AuthorityRole::KeyManager,
            frame.payload.as_slice(),
            8,
            73,
        ) {
            Ok(values) => values,
            Err(status) => return status_response(status, &[]),
        };
        let request = match decode_import_wrapped_key_request(inner.as_slice()) {
            Ok(request) => request,
            Err(status) => {
                clear_bytes(inner.as_mut_slice());
                return status_response(status, &[]);
            }
        };
        if request.wrap_format_version != 0x01
            || request.target_export_policy != super::state::ExportPolicy::NonExportable
            || request.target_usage_mask == 0
        {
            clear_bytes(inner.as_mut_slice());
            return status_response(StatusCode::AuthorizationError, &[]);
        }
        let metadata = match self.key_store.get_key_metadata(request.wrapping_key_id) {
            Ok(view) => view,
            Err(status) => {
                clear_bytes(inner.as_mut_slice());
                return status_response(status, &[]);
            }
        };
        let key_policy = evaluate_key_policy(
            &metadata,
            Some(KeyAlgorithm::ChaCha20Poly1305),
            USAGE_WRAP_IMPORT,
            false,
            &[KeyLifecycleState::Active],
        );
        if !key_policy.decision {
            clear_bytes(inner.as_mut_slice());
            return policy_status_response(
                status_for_denial_class(key_policy.denial_class),
                key_policy.denial_class,
                None,
            );
        }
        let mut wrapping_key = match self.key_store.export_key_material_for_operation(
            request.wrapping_key_id,
            KeyAlgorithm::ChaCha20Poly1305,
            USAGE_WRAP_IMPORT,
            false,
        ) {
            Ok(material) => material,
            Err(status) => {
                clear_bytes(inner.as_mut_slice());
                return status_response(status, &[]);
            }
        };
        if request.integrity_tag.len() != 28 {
            clear_secret_array(&mut wrapping_key);
            clear_bytes(inner.as_mut_slice());
            return status_response(StatusCode::ValidationError, &[]);
        }
        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&wrapping_key));
        let nonce = GenericArray::from_slice(&request.integrity_tag.as_slice()[..12]);
        let mut buffer = [0u8; 32];
        let ciphertext_len = request.ciphertext.len();
        buffer[..ciphertext_len].copy_from_slice(request.ciphertext.as_slice());
        let tag = chacha20poly1305::Tag::clone_from_slice(&request.integrity_tag.as_slice()[12..]);
        if cipher
            .decrypt_in_place_detached(nonce, b"rp_hsm.wrap.v1", &mut buffer[..ciphertext_len], &tag)
            .is_err()
        {
            clear_secret_array(&mut wrapping_key);
            clear_secret_array(&mut buffer);
            clear_bytes(inner.as_mut_slice());
            return status_response(StatusCode::AuthorizationError, &[]);
        }
        let import_result = self.key_store.import_wrapped_key(
            request.target_algorithm,
            request.target_usage_mask,
            request.target_export_policy,
            &buffer[..ciphertext_len],
        );
        clear_secret_array(&mut wrapping_key);
        clear_secret_array(&mut buffer);
        clear_bytes(inner.as_mut_slice());
        match import_result {
            Ok(result) => {
                self.invalidate_policy_tickets();
                self.crypto_state.note_wrapped_import(result.store_revision);
                self.record_audit_event(
                    AuditEventClass::Administrative,
                    AuditEventCode::CommandCompleted,
                    AuditResultClass::Success,
                    &[frame.code, result.key_id],
                );
                let payload = encode_key_record_result_payload(result);
                status_response(StatusCode::Success, &payload)
            }
            Err(status) => status_response(status, &[]),
        }
    }

    #[allow(clippy::too_many_lines)]
    fn handle_export_wrapped_key(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        let (_, mut inner) = match self.authorize_privileged_owned::<10>(
            AuthorityRole::KeyManager,
            frame.payload.as_slice(),
            0,
            2,
        ) {
            Ok(values) => values,
            Err(status) => return status_response(status, &[]),
        };
        if inner.is_empty() {
            clear_bytes(inner.as_mut_slice());
            return status_response(StatusCode::CommandError, &[]);
        }
        let request = match decode_export_wrapped_key_request(inner.as_slice()) {
            Ok(request) => request,
            Err(status) => {
                clear_bytes(inner.as_mut_slice());
                return status_response(status, &[]);
            }
        };
        let wrapping_metadata = match self.key_store.get_key_metadata(request.wrapping_key_id) {
            Ok(view) => view,
            Err(status) => {
                clear_bytes(inner.as_mut_slice());
                return status_response(status, &[]);
            }
        };
        let wrapping_policy = evaluate_key_policy(
            &wrapping_metadata,
            Some(KeyAlgorithm::ChaCha20Poly1305),
            USAGE_WRAP_IMPORT,
            false,
            &[KeyLifecycleState::Active],
        );
        if !wrapping_policy.decision {
            clear_bytes(inner.as_mut_slice());
            return policy_status_response(
                status_for_denial_class(wrapping_policy.denial_class),
                wrapping_policy.denial_class,
                None,
            );
        }
        let target_metadata = match self.key_store.get_key_metadata(request.target_key_id) {
            Ok(view) => view,
            Err(status) => {
                clear_bytes(inner.as_mut_slice());
                return status_response(status, &[]);
            }
        };
        let target_policy = evaluate_key_policy(
            &target_metadata,
            Some(target_metadata.algorithm),
            target_metadata.usage_mask,
            true,
            &[KeyLifecycleState::Active],
        );
        if !target_policy.decision {
            clear_bytes(inner.as_mut_slice());
            return policy_status_response(
                status_for_denial_class(target_policy.denial_class),
                target_policy.denial_class,
                None,
            );
        }
        let mut wrapping_key = match self.key_store.export_key_material_for_operation(
            request.wrapping_key_id,
            KeyAlgorithm::ChaCha20Poly1305,
            USAGE_WRAP_IMPORT,
            false,
        ) {
            Ok(material) => material,
            Err(status) => {
                clear_bytes(inner.as_mut_slice());
                return status_response(status, &[]);
            }
        };
        let target_material = match self.key_store.export_key_material_for_operation(
            request.target_key_id,
            target_metadata.algorithm,
            target_metadata.usage_mask,
            true,
        ) {
            Ok(material) => material,
            Err(status) => {
                clear_secret_array(&mut wrapping_key);
                clear_bytes(inner.as_mut_slice());
                return status_response(status, &[]);
            }
        };
        let nonce_bytes = match self
            .crypto_state
            .generate_random_bytes(super::state::CHACHA20POLY1305_NONCE_LEN)
        {
            Ok(bytes) => bytes,
            Err(StatusCode::StateError) => {
                clear_secret_array(&mut wrapping_key);
                clear_bytes(inner.as_mut_slice());
                return status_response(StatusCode::InternalError, &[]);
            }
            Err(status) => {
                clear_secret_array(&mut wrapping_key);
                clear_bytes(inner.as_mut_slice());
                return status_response(status, &[]);
            }
        };
        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&wrapping_key));
        let nonce = GenericArray::from_slice(nonce_bytes.as_slice());
        let mut ciphertext = Vec::<u8, { super::state::MAX_KEY_MATERIAL_LEN }>::new();
        if ciphertext
            .extend_from_slice(&target_material[..super::state::MAX_KEY_MATERIAL_LEN])
            .is_err()
        {
            clear_secret_array(&mut wrapping_key);
            clear_bytes(inner.as_mut_slice());
            return status_response(StatusCode::InternalError, &[]);
        }
        let Ok(tag) = cipher.encrypt_in_place_detached(nonce, WRAP_EXPORT_AAD, &mut ciphertext) else {
            clear_secret_array(&mut wrapping_key);
            clear_bytes(inner.as_mut_slice());
            return status_response(StatusCode::InternalError, &[]);
        };
        let mut envelope = Vec::<u8, 96>::new();
        if envelope.push(0x01).is_err()
            || envelope.push(request.wrapping_key_id).is_err()
            || envelope.push(target_metadata.algorithm as u8).is_err()
            || envelope.push(target_metadata.usage_mask).is_err()
            || envelope
                .push(super::state::ExportPolicy::NonExportable as u8)
                .is_err()
            || envelope
                .extend_from_slice(
                    &u16::try_from(ciphertext.len()).unwrap_or(0).to_le_bytes(),
                )
                .is_err()
            || envelope.extend_from_slice(ciphertext.as_slice()).is_err()
            || envelope.push(28).is_err()
            || envelope.extend_from_slice(nonce_bytes.as_slice()).is_err()
            || envelope.extend_from_slice(tag.as_slice()).is_err()
        {
            clear_secret_array(&mut wrapping_key);
            clear_bytes(inner.as_mut_slice());
            return status_response(StatusCode::InternalError, &[]);
        }
        clear_secret_array(&mut wrapping_key);
        clear_bytes(inner.as_mut_slice());
        self.record_audit_event(
            AuditEventClass::Administrative,
            AuditEventCode::CommandCompleted,
            AuditResultClass::Success,
            &[frame.code, request.target_key_id, request.wrapping_key_id],
        );
        match encode_wrapped_key_export_payload(envelope.as_slice()) {
            Some(payload) => status_response(StatusCode::Success, &payload),
            None => status_response(StatusCode::InternalError, &[]),
        }
    }

    #[allow(
        clippy::too_many_lines,
        clippy::single_match_else,
        clippy::manual_let_else,
        clippy::ignored_unit_patterns
    )]
    fn handle_derive_shared_secret(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        let (_, mut inner) = match self.authorize_privileged_owned::<78>(
            AuthorityRole::KeyManager,
            frame.payload.as_slice(),
            0,
            69,
        ) {
            Ok(values) => values,
            Err(status) => return status_response(status, &[]),
        };
        if inner.is_empty() {
            clear_bytes(inner.as_mut_slice());
            return status_response(StatusCode::CommandError, &[]);
        }
        let request = match decode_derive_request(inner.as_slice()) {
            Ok(request) => request,
            Err(status) => {
                clear_bytes(inner.as_mut_slice());
                return status_response(status, &[]);
            }
        };
        let metadata = match self.key_store.get_key_metadata(request.key_id) {
            Ok(view) => view,
            Err(status) => {
                clear_bytes(inner.as_mut_slice());
                return status_response(status, &[]);
            }
        };
        let key_policy = evaluate_key_policy(
            &metadata,
            Some(request.algorithm),
            USAGE_DERIVE,
            false,
            &[KeyLifecycleState::Active],
        );
        if !key_policy.decision {
            clear_bytes(inner.as_mut_slice());
            return policy_status_response(
                status_for_denial_class(key_policy.denial_class),
                key_policy.denial_class,
                None,
            );
        }
        let mut key_bytes = match self
            .key_store
            .export_key_material_for_operation(request.key_id, request.algorithm, USAGE_DERIVE, false)
        {
            Ok(material) => material,
            Err(status) => {
                clear_bytes(inner.as_mut_slice());
                return status_response(status, &[]);
            }
        };
        let derived = match request.algorithm {
            KeyAlgorithm::P256EcdhHkdfSha256 => {
                let secret = match P256SecretKey::from_slice(&key_bytes) {
                    Ok(secret) => secret,
                    Err(_) => {
                        clear_secret_array(&mut key_bytes);
                        clear_bytes(inner.as_mut_slice());
                        return status_response(StatusCode::InternalError, &[]);
                    }
                };
                let peer = match P256PublicKey::from_sec1_bytes(request.peer_public_material.as_slice()) {
                    Ok(peer) => peer,
                    Err(_) => {
                        clear_secret_array(&mut key_bytes);
                        clear_bytes(inner.as_mut_slice());
                        return status_response(StatusCode::ValidationError, &[]);
                    }
                };
                let shared_secret = diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
                let mut info = Vec::<u8, 64>::new();
                if info.extend_from_slice(DERIVE_INFO_PREFIX).is_err()
                    || info.extend_from_slice(request.context.as_slice()).is_err()
                {
                    clear_secret_array(&mut key_bytes);
                    clear_bytes(inner.as_mut_slice());
                    return status_response(StatusCode::InternalError, &[]);
                }
                let hk = Hkdf::<Sha256>::new(None, shared_secret.raw_secret_bytes().as_slice());
                let mut output = [0u8; super::state::MAX_DERIVED_OUTPUT_LEN];
                if hk
                    .expand(info.as_slice(), &mut output[..usize::from(request.requested_len)])
                    .is_err()
                {
                    clear_secret_array(&mut key_bytes);
                    clear_secret_array(&mut output);
                    clear_bytes(inner.as_mut_slice());
                    return status_response(StatusCode::InternalError, &[]);
                }
                let result = Vec::<u8, { super::state::MAX_DERIVED_OUTPUT_LEN }>::from_slice(
                    &output[..usize::from(request.requested_len)],
                );
                clear_secret_array(&mut output);
                match result {
                    Ok(result) => result,
                    Err(_) => {
                        clear_secret_array(&mut key_bytes);
                        clear_bytes(inner.as_mut_slice());
                        return status_response(StatusCode::InternalError, &[]);
                    }
                }
            }
            _ => {
                clear_secret_array(&mut key_bytes);
                clear_bytes(inner.as_mut_slice());
                return status_response(StatusCode::AuthorizationError, &[]);
            }
        };
        clear_secret_array(&mut key_bytes);
        clear_bytes(inner.as_mut_slice());
        self.record_audit_event(
            AuditEventClass::Administrative,
            AuditEventCode::CommandCompleted,
            AuditResultClass::Success,
            &[frame.code, request.key_id, request.requested_len],
        );
        match encode_derive_response_payload(derived.as_slice()) {
            Some(payload) => status_response(StatusCode::Success, &payload),
            None => status_response(StatusCode::InternalError, &[]),
        }
    }

    fn handle_developer_store_fault(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        let Some(action) = frame
            .payload
            .first()
            .and_then(|byte| DeveloperStoreFaultAction::from_byte(*byte))
        else {
            return status_response(StatusCode::ValidationError, &[]);
        };

        self.pending_firmware_action = Some(FirmwareAction::DeveloperStoreFault(action));
        self.record_audit_event(
            AuditEventClass::PersistenceAnomaly,
            AuditEventCode::PersistenceFault,
            AuditResultClass::Degraded,
            &[action as u8],
        );
        status_response(StatusCode::Success, &[action as u8])
    }

    fn handle_developer_update_fault(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        self.handle_developer_store_fault(frame)
    }

    fn handle_developer_reboot(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        if let Err(status) = expect_marker_bytes(frame.payload.as_slice(), b"RST") {
            return status_response(status, &[]);
        }

        self.pending_firmware_action = Some(FirmwareAction::DeveloperReboot);
        status_response(StatusCode::Success, &[])
    }

    fn handle_developer_set_policy(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        match frame.payload.as_slice() {
            [] => status_response(
                StatusCode::Success,
                &encode_policy_profile_payload(self.policy_profile),
            ),
            [dual_control] if *dual_control <= 1 => {
                if self.policy_profile.dual_control_enabled != (*dual_control != 0) {
                    self.policy_profile.dual_control_enabled = *dual_control != 0;
                    self.policy_profile.policy_revision =
                        self.policy_profile.policy_revision.saturating_add(1);
                }
                self.policy_profile.developer_commands_visible = self.developer_mode;
                self.record_audit_event(
                    AuditEventClass::Administrative,
                    AuditEventCode::DeveloperPolicyChanged,
                    AuditResultClass::Success,
                    &[u8::from(self.policy_profile.dual_control_enabled)],
                );
                status_response(
                    StatusCode::Success,
                    &encode_policy_profile_payload(self.policy_profile),
                )
            }
            _ => status_response(StatusCode::ValidationError, &[]),
        }
    }

    fn decode_error_response(err: DecodeError) -> ProtocolFrame {
        match err {
            DecodeError::Truncated
            | DecodeError::InvalidKind
            | DecodeError::InvalidFlags
            | DecodeError::LengthMismatch
            | DecodeError::OversizedPayload => status_response(StatusCode::FormatError, &[]),
        }
    }
}

pub fn clear_transient_buffer(buffer: &mut [u8]) {
    clear_bytes(buffer);
}
