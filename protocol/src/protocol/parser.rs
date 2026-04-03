use heapless::Vec;
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{AeadInPlace, generic_array::GenericArray},
};
use ed25519_dalek::{Signer, Verifier};
use p256::ecdsa::{Signature as P256Signature, VerifyingKey as P256VerifyingKey};

use super::codec::{
    DecodeError, StatusCode, clear_bytes, decode_audit_page_request,
    decode_authentication_role, decode_authorized_payload,
    decode_complete_authentication_request, decode_frame, decode_import_wrapped_key_request,
    decode_key_id_request, decode_key_marker_request, decode_put_persistent_key_request,
    decode_random_request, decode_sign_request, decode_transition_request,
    decode_verify_request, encode_audit_page_payload, encode_auth_challenge_payload,
    encode_auth_session_payload, encode_crypto_capabilities_payload,
    encode_developer_reset_payload, encode_device_status_payload, encode_key_destroy_payload,
    encode_key_list_payload, encode_key_metadata_payload, encode_key_record_result_payload,
    encode_key_store_status_payload, encode_lifecycle_status_payload, encode_lock_result_payload,
    encode_policy_denial_payload, encode_policy_profile_payload, encode_random_payload,
    encode_recovery_result_payload, encode_session_status_payload, encode_signature_payload,
    encode_state_revision_payload, encode_transition_result_payload, encode_verify_result_payload,
    encode_zeroize_payload, encode_health_status_payload, policy_status_response,
    protocol_version_response, status_response,
};
use super::command::{CommandId, get_visible_catalog, lookup_command};
use super::frame::{
    FLAG_INCLUDE_RESTRICTED, FLAG_REPLAY_SENSITIVE, MessageKind, PROTOCOL_VERSION, ProtocolFrame,
};
use super::state::{
    ApprovalTargetBinding, ApprovalTicket, ApprovalTicketState, AuditEventClass, AuditEventCode,
    AuditJournal, AuditResultClass, AuditStoreSnapshot, AuthSnapshot, AuthenticationChallenge,
    AuthorityRole, CryptoPersistentState, CryptoRuntimeState, DenialClass, DeviceState,
    KeyAlgorithm, KeyLifecycleState, PersistentKeyStore, PolicyProfile, ProtectedActionClass,
    ProvisioningRecord, ProvisioningSnapshot, SessionLifecycleState, SessionRecord, SessionState,
    SessionTracker, USAGE_SIGN, USAGE_WRAP_IMPORT, clear_active_session,
    clear_approval_tickets, clear_auth_failures, clear_challenge, clear_failure_counters,
    clear_secret_array, current_session_state, current_session_status, developer_mode_session,
    developer_reset_marker, enforce_replay_policy, evaluate_command_policy, evaluate_key_policy,
    expect_marker_bytes, expect_single_marker, finalize_marker, find_credential,
    fingerprint_frame, invalidate_approval_tickets, issue_challenge_nonce, new_approval_ticket,
    reactivate_marker, record_auth_failure, recovery_marker, retain_active_approval_tickets,
    revoke_marker, role_locked_out, role_to_authorization_mode, status_for_denial_class,
    unlock_marker, zeroize_marker, MAX_APPROVAL_TICKETS,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeveloperStoreFaultAction {
    CorruptPersistedStore = 0x01,
    RollbackPersistedStore = 0x02,
    CorruptPersistedAudit = 0x03,
    RollbackPersistedAudit = 0x04,
}

impl DeveloperStoreFaultAction {
    #[must_use]
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::CorruptPersistedStore),
            0x02 => Some(Self::RollbackPersistedStore),
            0x03 => Some(Self::CorruptPersistedAudit),
            0x04 => Some(Self::RollbackPersistedAudit),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FirmwareAction {
    DeveloperStoreFault(DeveloperStoreFaultAction),
    DeveloperReboot,
}

pub struct ProtocolEngine {
    record: ProvisioningRecord,
    key_store: PersistentKeyStore,
    auth_snapshot: AuthSnapshot,
    crypto_state: CryptoRuntimeState,
    audit_journal: AuditJournal,
    policy_profile: PolicyProfile,
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
            if payload.len() < min_inner_len || payload.len() > max_inner_len {
                return Err(StatusCode::ValidationError);
            }
            let mut owned = Vec::<u8, N>::new();
            owned
                .extend_from_slice(payload)
                .map_err(|()| StatusCode::ValidationError)?;
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
                    if payload.len() < min_inner_len || payload.len() > max_inner_len {
                        return Err(StatusCode::ValidationError);
                    }
                    let mut owned = Vec::<u8, N>::new();
                    owned
                        .extend_from_slice(payload)
                        .map_err(|()| StatusCode::ValidationError)?;
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
            Some(CommandId::SignDetached) => self.handle_sign_detached(frame),
            Some(CommandId::GenerateRandom) => self.handle_generate_random(frame),
            Some(CommandId::ImportWrappedKey) => self.handle_import_wrapped_key(frame),
            Some(
                CommandId::ExportWrappedKey
                | CommandId::Encrypt
                | CommandId::Decrypt
                | CommandId::DeriveSharedSecret,
            ) => {
                status_response(StatusCode::CommandError, &[])
            }
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
            Ok(view) => {
                let payload = encode_key_metadata_payload(view);
                status_response(StatusCode::Success, &payload)
            }
            Err(status) => status_response(status, &[]),
        }
    }

    fn handle_revoke_persistent_key(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        let (_, inner) = match self.authorize_privileged_owned::<2>(
            AuthorityRole::KeyManager,
            frame.payload.as_slice(),
            2,
            2,
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
            metadata,
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
        if request.algorithm != KeyAlgorithm::Ed25519 {
            clear_bytes(inner.as_mut_slice());
            return status_response(StatusCode::AuthorizationError, &[]);
        }

        let metadata = match self.key_store.get_key_metadata(request.key_id) {
            Ok(view) => view,
            Err(status) => {
                clear_bytes(inner.as_mut_slice());
                return status_response(status, &[]);
            }
        };
        let key_policy = evaluate_key_policy(
            metadata,
            Some(KeyAlgorithm::Ed25519),
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
            .export_key_material_for_operation(request.key_id, KeyAlgorithm::Ed25519, USAGE_SIGN, false)
        {
            Ok(material) => material,
            Err(status) => {
                clear_bytes(inner.as_mut_slice());
                return status_response(status, &[]);
            }
        };
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
        let signature = signing_key.sign(request.message.as_slice()).to_bytes();
        let response = match encode_signature_payload(&signature) {
            Some(payload) => status_response(StatusCode::Success, &payload),
            None => status_response(StatusCode::InternalError, &[]),
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
            KeyAlgorithm::Aes256 => return status_response(StatusCode::AuthorizationError, &[]),
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
            || request.target_algorithm != KeyAlgorithm::Ed25519
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
            metadata,
            Some(KeyAlgorithm::Aes256),
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
            KeyAlgorithm::Aes256,
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
