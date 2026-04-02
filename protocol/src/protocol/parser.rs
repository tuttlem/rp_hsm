use heapless::Vec;

use super::codec::{
    DecodeError, StatusCode, clear_bytes, decode_authentication_role,
    decode_authorized_payload, decode_complete_authentication_request, decode_frame,
    decode_key_id_request, decode_key_marker_request, decode_put_persistent_key_request,
    decode_transition_request, encode_auth_challenge_payload, encode_auth_session_payload,
    encode_developer_reset_payload, encode_device_status_payload,
    encode_key_destroy_payload, encode_key_list_payload, encode_key_metadata_payload,
    encode_key_record_result_payload, encode_key_store_status_payload,
    encode_lifecycle_status_payload, encode_lock_result_payload,
    encode_recovery_result_payload, encode_session_status_payload, encode_state_revision_payload,
    encode_transition_result_payload, encode_zeroize_payload, protocol_version_response,
    status_response,
};
use super::command::{CommandId, get_visible_catalog, lookup_command};
use super::frame::{
    FLAG_INCLUDE_RESTRICTED, FLAG_REPLAY_SENSITIVE, MessageKind, PROTOCOL_VERSION, ProtocolFrame,
};
use super::state::{
    AuthSnapshot, AuthenticationChallenge, AuthorityRole, DeviceState, PersistentKeyStore,
    ProvisioningRecord, ProvisioningSnapshot, SessionRecord, SessionState, SessionTracker,
    SessionLifecycleState, clear_active_session, clear_auth_failures, clear_challenge,
    clear_failure_counters, current_session_state, current_session_status,
    developer_mode_session, developer_reset_marker, enforce_replay_policy,
    ensure_command_allowed, expect_marker_bytes, expect_single_marker, finalize_marker,
    find_credential, fingerprint_frame, issue_challenge_nonce, reactivate_marker,
    record_auth_failure, recovery_marker, revoke_marker, role_locked_out,
    role_to_authorization_mode, unlock_marker, zeroize_marker,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeveloperStoreFaultAction {
    CorruptPersistedStore = 0x01,
    RollbackPersistedStore = 0x02,
}

impl DeveloperStoreFaultAction {
    #[must_use]
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Self::CorruptPersistedStore),
            0x02 => Some(Self::RollbackPersistedStore),
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
        engine
    }

    pub fn set_device_state(&mut self, device_state: DeviceState) {
        self.record = ProvisioningRecord::new(device_state);
        self.key_store = PersistentKeyStore::new(self.record.revision_counter());
        clear_challenge(&mut self.active_challenge);
        clear_active_session(&mut self.active_session);
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
        self.refresh_session_state();
    }

    pub fn reconcile_boot(&mut self) {
        self.record.reconcile_after_boot();
        self.key_store
            .sync_device_revision(self.record.revision_counter());
        self.key_store.reconcile_after_boot();
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

        if let Err(status) = ensure_command_allowed(
            command,
            self.record.current_state(),
            self.session_state,
            self.developer_mode,
        ) {
            return status_response(status, &[]);
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
            return status_response(StatusCode::AuthorizationError, &[]);
        }
        if request_counter <= challenge.request_counter_floor {
            record_auth_failure(
                &mut self.auth_snapshot,
                challenge.requested_role,
                self.request_tick,
            );
            clear_challenge(&mut self.active_challenge);
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
        self.invalidate_session();
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

        match self.record.recover_to_provisioned() {
            Ok(result) => {
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

        match self.record.reactivate_recovered_provisioning(transition_id) {
            Ok(result) => {
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

        match self.record.execute_zeroize() {
            Ok(result) => {
                self.key_store = PersistentKeyStore::new(self.record.revision_counter());
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
        clear_failure_counters(&mut self.auth_snapshot.failure_counters);
        self.invalidate_session();
        status_response(StatusCode::Success, &payload)
    }

    fn handle_put_persistent_key(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        let (_, inner) = match self.authorize_privileged_owned::<30>(
            AuthorityRole::KeyManager,
            frame.payload.as_slice(),
            7,
            30,
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

        match self.key_store.destroy_key(key_id) {
            Ok(result) => {
                let payload = encode_key_destroy_payload(result);
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
        status_response(StatusCode::Success, &[action as u8])
    }

    fn handle_developer_reboot(&mut self, frame: &ProtocolFrame) -> ProtocolFrame {
        if let Err(status) = expect_marker_bytes(frame.payload.as_slice(), b"RST") {
            return status_response(status, &[]);
        }

        self.pending_firmware_action = Some(FirmwareAction::DeveloperReboot);
        status_response(StatusCode::Success, &[])
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
