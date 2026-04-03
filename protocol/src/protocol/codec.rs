use heapless::Vec;

use super::frame::{
    HEADER_LEN, MAX_FRAME_LEN, MAX_PAYLOAD_LEN, MessageKind, PROTOCOL_VERSION, ProtocolFrame,
    RESERVED_FLAG_MASK,
};
use super::state::{
    ApprovalTicket, AuditEvent, AuditRetrievalCursor, AuthorityRole, BeginFirmwareUpdateRequest,
    BootSlotId, CryptoCapabilities, DenialClass, DeveloperResetOutcome, DeviceState,
    ExportPolicy, FirmwareAbortResult, FirmwareActivationResult, FirmwareChunkProgress,
    FirmwareChunkRequest, FirmwareFinalizeResult, FirmwarePackageManifest,
    FirmwareRecoveryResult, FirmwareUpdateBeginResult, FirmwareUpdateStatus, FirmwareVersion,
    HealthStatusView, ImportWrappedKeyRequest, KeyAlgorithm, KeyDestroyResult, KeyListEntry,
    KeyMaterialEnvelope, KeyMetadataView, KeyOrigin, KeyRecordResult, KeyStoreStatus,
    LifecycleStatus, LockResult, MAX_CRYPTO_MESSAGE_LEN, MAX_FIRMWARE_CHUNK_LEN,
    MAX_FIRMWARE_SIGNATURE_LEN, MAX_RANDOM_OUTPUT_LEN, MAX_SIGNATURE_LEN,
    MAX_WRAPPED_CIPHERTEXT_LEN, MAX_WRAPPED_TAG_LEN, P256_PUBLIC_KEY_LEN, PolicyProfile,
    PutPersistentKeyRequest, RandomRequest, RecoveryResult, SessionState, SessionStatus,
    SignRequest, StateRevision, TransitionResult, UPDATE_MANIFEST_VERSION, VerifyRequest,
    ZeroizeOutcome,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum StatusCode {
    Success = 0x00,
    FormatError = 0x01,
    VersionError = 0x02,
    CommandError = 0x03,
    ValidationError = 0x04,
    StateError = 0x05,
    AuthorizationError = 0x06,
    ReplayError = 0x07,
    InternalError = 0x08,
}

impl StatusCode {
    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    Truncated,
    InvalidKind,
    OversizedPayload,
    InvalidFlags,
    LengthMismatch,
}

#[must_use]
pub fn encode_frame(frame: &ProtocolFrame) -> Option<Vec<u8, MAX_FRAME_LEN>> {
    let payload_len = u16::try_from(frame.payload_len()).ok()?;
    let mut encoded = Vec::new();
    encoded.push(frame.version).ok()?;
    encoded.push(frame.kind as u8).ok()?;
    encoded.push(frame.code).ok()?;
    encoded.push(frame.flags).ok()?;
    encoded.extend_from_slice(&payload_len.to_le_bytes()).ok()?;
    encoded.extend_from_slice(&frame.payload).ok()?;
    Some(encoded)
}

/// # Errors
///
/// Returns `DecodeError` when the provided bytes do not form a valid bounded
/// protocol frame.
pub fn decode_frame(bytes: &[u8]) -> Result<ProtocolFrame, DecodeError> {
    if bytes.len() < HEADER_LEN {
        return Err(DecodeError::Truncated);
    }

    let kind = MessageKind::from_byte(bytes[1]).ok_or(DecodeError::InvalidKind)?;
    let flags = bytes[3];
    if flags & RESERVED_FLAG_MASK != 0 {
        return Err(DecodeError::InvalidFlags);
    }

    let payload_len = usize::from(u16::from_le_bytes([bytes[4], bytes[5]]));
    if payload_len > MAX_PAYLOAD_LEN {
        return Err(DecodeError::OversizedPayload);
    }

    if bytes.len() != HEADER_LEN + payload_len {
        return Err(DecodeError::LengthMismatch);
    }

    let mut payload = Vec::new();
    payload
        .extend_from_slice(&bytes[HEADER_LEN..HEADER_LEN + payload_len])
        .map_err(|()| DecodeError::OversizedPayload)?;

    Ok(ProtocolFrame {
        version: bytes[0],
        kind,
        code: bytes[2],
        flags,
        payload,
    })
}

#[must_use]
pub fn status_response(status: StatusCode, payload: &[u8]) -> ProtocolFrame {
    ProtocolFrame::new(MessageKind::Response, status.as_u8(), 0, payload).unwrap_or_else(|| {
        ProtocolFrame {
            version: PROTOCOL_VERSION,
            kind: MessageKind::Response,
            code: StatusCode::InternalError.as_u8(),
            flags: 0,
            payload: Vec::new(),
        }
    })
}

#[must_use]
pub fn encode_policy_denial_payload(
    denial_class: DenialClass,
    approval_ticket_id: Option<u32>,
) -> Option<Vec<u8, MAX_PAYLOAD_LEN>> {
    let mut payload = Vec::new();
    payload.push(denial_class as u8).ok()?;
    if let Some(ticket_id) = approval_ticket_id {
        payload.extend_from_slice(&ticket_id.to_le_bytes()).ok()?;
    }
    Some(payload)
}

#[must_use]
pub fn policy_status_response(
    status: StatusCode,
    denial_class: DenialClass,
    approval_ticket_id: Option<u32>,
) -> ProtocolFrame {
    let payload = encode_policy_denial_payload(denial_class, approval_ticket_id)
        .unwrap_or_default();
    status_response(status, &payload)
}

#[must_use]
pub fn encode_approval_ticket_payload(ticket: ApprovalTicket) -> [u8; 12] {
    let ticket_id = ticket.ticket_id.to_le_bytes();
    let target_id = ticket.target_id.to_le_bytes();
    [
        ticket.ticket_id.to_le_bytes()[0],
        ticket_id[1],
        ticket_id[2],
        ticket_id[3],
        ticket.approval_class as u8,
        ticket.state as u8,
        target_id[0],
        target_id[1],
        target_id[2],
        target_id[3],
        ticket.initiator_role as u8,
        ticket.confirmer_role as u8,
    ]
}

#[must_use]
pub fn encode_approval_status_payload(
    ticket: ApprovalTicket,
    expires_in_ticks: u16,
) -> [u8; 14] {
    let base = encode_approval_ticket_payload(ticket);
    [
        base[0],
        base[1],
        base[2],
        base[3],
        base[4],
        base[5],
        base[6],
        base[7],
        base[8],
        base[9],
        base[10],
        base[11],
        expires_in_ticks.to_le_bytes()[0],
        expires_in_ticks.to_le_bytes()[1],
    ]
}

pub fn clear_bytes(bytes: &mut [u8]) {
    for byte in bytes {
        *byte = 0;
    }
}

#[must_use]
pub fn protocol_version_response() -> ProtocolFrame {
    status_response(StatusCode::Success, &[PROTOCOL_VERSION])
}

#[must_use]
pub fn encode_device_status_payload(
    device_state: DeviceState,
    session_state: SessionState,
) -> [u8; 2] {
    [device_state as u8, session_state as u8]
}

#[must_use]
pub fn encode_lifecycle_status_payload(status: LifecycleStatus) -> [u8; 4] {
    [
        status.state as u8,
        u8::from(status.owner_present),
        u8::from(status.recovery_required),
        u8::from(status.pending_transition_present),
    ]
}

#[must_use]
pub fn encode_key_store_status_payload(status: KeyStoreStatus) -> [u8; 5] {
    [
        status.store_state as u8,
        status.key_count,
        status.free_slots,
        u8::from(status.rollback_detected),
        u8::from(status.corruption_detected),
    ]
}

#[must_use]
pub fn encode_auth_challenge_payload(
    challenge_id: u32,
    role: AuthorityRole,
    nonce: &[u8],
    expires_after_ticks: u16,
) -> Option<Vec<u8, MAX_PAYLOAD_LEN>> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&challenge_id.to_le_bytes()).ok()?;
    payload.push(role as u8).ok()?;
    payload.push(u8::try_from(nonce.len()).ok()?).ok()?;
    payload.extend_from_slice(nonce).ok()?;
    payload.extend_from_slice(&expires_after_ticks.to_le_bytes()).ok()?;
    Some(payload)
}

#[must_use]
pub fn encode_auth_session_payload(
    session_id: u32,
    role: AuthorityRole,
    session_timeout_ticks: u16,
    next_counter: u32,
) -> [u8; 11] {
    let session_id = session_id.to_le_bytes();
    let next_counter = next_counter.to_le_bytes();
    [
        session_id[0],
        session_id[1],
        session_id[2],
        session_id[3],
        role as u8,
        session_timeout_ticks.to_le_bytes()[0],
        session_timeout_ticks.to_le_bytes()[1],
        next_counter[0],
        next_counter[1],
        next_counter[2],
        next_counter[3],
    ]
}

#[must_use]
pub fn encode_session_status_payload(status: SessionStatus) -> [u8; 6] {
    [
        u8::from(status.session_present),
        status.active_role as u8,
        status.expires_in_ticks.to_le_bytes()[0],
        status.expires_in_ticks.to_le_bytes()[1],
        u8::from(status.lockout_active),
        status.lockout_role as u8,
    ]
}

#[must_use]
pub fn encode_transition_result_payload(result: TransitionResult) -> [u8; 9] {
    let transition_id = result.transition_id.to_le_bytes();
    let revision = result.revision_counter.to_le_bytes();
    [
        result.state as u8,
        transition_id[0],
        transition_id[1],
        transition_id[2],
        transition_id[3],
        revision[0],
        revision[1],
        revision[2],
        revision[3],
    ]
}

#[must_use]
pub fn encode_state_revision_payload(result: StateRevision) -> [u8; 5] {
    let revision = result.revision_counter.to_le_bytes();
    [
        result.state as u8,
        revision[0],
        revision[1],
        revision[2],
        revision[3],
    ]
}

#[must_use]
pub fn encode_lock_result_payload(result: LockResult) -> [u8; 2] {
    [result.state as u8, result.reason_code]
}

#[must_use]
pub fn encode_recovery_result_payload(result: RecoveryResult) -> [u8; 2] {
    [result.state as u8, u8::from(result.recovery_required)]
}

#[must_use]
pub fn encode_zeroize_payload(result: ZeroizeOutcome) -> [u8; 5] {
    [
        result.result_state as u8,
        u8::from(result.owner_binding_cleared),
        u8::from(result.secret_storage_cleared),
        u8::from(result.transient_buffers_cleared),
        u8::from(result.requires_reprovisioning),
    ]
}

#[must_use]
pub fn encode_developer_reset_payload(result: DeveloperResetOutcome) -> [u8; 4] {
    [
        result.result_state as u8,
        u8::from(result.owner_binding_cleared),
        u8::from(result.pending_transition_cleared),
        u8::from(result.transient_buffers_cleared),
    ]
}

#[must_use]
pub fn encode_policy_profile_payload(profile: PolicyProfile) -> [u8; 9] {
    let revision = profile.policy_revision.to_le_bytes();
    let mask = profile.protected_action_mask.to_le_bytes();
    [
        profile.profile_version,
        revision[0],
        revision[1],
        revision[2],
        revision[3],
        u8::from(profile.dual_control_enabled),
        mask[0],
        mask[1],
        u8::from(profile.developer_commands_visible),
    ]
}

#[must_use]
pub fn encode_key_record_result_payload(result: KeyRecordResult) -> [u8; 10] {
    let record_revision = result.record_revision.to_le_bytes();
    let store_revision = result.store_revision.to_le_bytes();
    [
        result.key_id,
        result.lifecycle_state as u8,
        record_revision[0],
        record_revision[1],
        record_revision[2],
        record_revision[3],
        store_revision[0],
        store_revision[1],
        store_revision[2],
        store_revision[3],
    ]
}

#[must_use]
pub fn encode_key_metadata_payload(view: KeyMetadataView) -> [u8; 10] {
    let record_revision = view.record_revision.to_le_bytes();
    [
        view.key_id,
        view.algorithm as u8,
        view.origin as u8,
        view.usage_mask,
        view.export_policy as u8,
        view.lifecycle_state as u8,
        record_revision[0],
        record_revision[1],
        record_revision[2],
        record_revision[3],
    ]
}

#[must_use]
pub fn encode_key_destroy_payload(result: KeyDestroyResult) -> [u8; 4] {
    [
        result.key_id,
        result.lifecycle_state as u8,
        u8::from(result.material_cleared),
        u8::from(result.tombstone_committed),
    ]
}

#[must_use]
pub fn encode_key_list_payload(entries: &[KeyListEntry]) -> Option<Vec<u8, MAX_PAYLOAD_LEN>> {
    let mut payload = Vec::new();
    let count = u8::try_from(entries.len()).ok()?;
    payload.push(count).ok()?;
    for entry in entries {
        payload.push(entry.key_id).ok()?;
        payload.push(entry.algorithm as u8).ok()?;
        payload.push(entry.lifecycle_state as u8).ok()?;
        payload.push(entry.usage_mask).ok()?;
        payload.push(entry.export_policy as u8).ok()?;
    }
    Some(payload)
}

#[must_use]
pub fn encode_crypto_capabilities_payload(
    capabilities: CryptoCapabilities,
) -> [u8; 10] {
    [
        capabilities.service_version,
        capabilities.operation_flags.0,
        capabilities.sign_algorithm_flags,
        capabilities.verify_algorithm_flags,
        capabilities.max_message_len.to_le_bytes()[0],
        capabilities.max_message_len.to_le_bytes()[1],
        capabilities.max_signature_len.to_le_bytes()[0],
        capabilities.max_signature_len.to_le_bytes()[1],
        capabilities.max_random_len,
        u8::from(capabilities.wrapped_import_enabled),
    ]
}

#[must_use]
pub fn encode_health_status_payload(status: HealthStatusView) -> [u8; 13] {
    let policy_revision = status.policy_revision.to_le_bytes();
    let retained = status.audit_events_retained.to_le_bytes();
    [
        status.device_state as u8,
        status.key_store_state as u8,
        status.session_state as u8,
        policy_revision[0],
        policy_revision[1],
        policy_revision[2],
        policy_revision[3],
        status.audit_store_state as u8,
        retained[0],
        retained[1],
        u8::from(status.audit_overflow_detected),
        u8::from(status.rollback_detected),
        u8::from(status.corruption_detected),
    ]
}

#[must_use]
pub fn encode_firmware_version(version: FirmwareVersion) -> [u8; 8] {
    let epoch = version.security_epoch.to_le_bytes();
    let major = version.major.to_le_bytes();
    let minor = version.minor.to_le_bytes();
    let patch = version.patch.to_le_bytes();
    [
        epoch[0], epoch[1], major[0], major[1], minor[0], minor[1], patch[0], patch[1],
    ]
}

#[must_use]
pub fn encode_firmware_update_status_payload(
    status: FirmwareUpdateStatus,
) -> [u8; 25] {
    let active_version = encode_firmware_version(status.active_version);
    let minimum_version = encode_firmware_version(status.minimum_accepted_version);
    let policy_revision = status.policy_revision.to_le_bytes();
    [
        status.active_slot as u8,
        active_version[0],
        active_version[1],
        active_version[2],
        active_version[3],
        active_version[4],
        active_version[5],
        active_version[6],
        active_version[7],
        minimum_version[0],
        minimum_version[1],
        minimum_version[2],
        minimum_version[3],
        minimum_version[4],
        minimum_version[5],
        minimum_version[6],
        minimum_version[7],
        status.transfer_phase as u8,
        status.staged_slot_state as u8,
        u8::from(status.recovery_required),
        status.last_update_result as u8,
        policy_revision[0],
        policy_revision[1],
        policy_revision[2],
        policy_revision[3],
    ]
}

#[must_use]
pub fn encode_firmware_update_begin_payload(
    result: FirmwareUpdateBeginResult,
) -> [u8; 13] {
    let session_id = result.update_session_id.to_le_bytes();
    let expected = result.expected_size.to_le_bytes();
    let policy = result.policy_revision.to_le_bytes();
    [
        result.target_slot as u8,
        session_id[0],
        session_id[1],
        session_id[2],
        session_id[3],
        expected[0],
        expected[1],
        expected[2],
        expected[3],
        policy[0],
        policy[1],
        policy[2],
        policy[3],
    ]
}

#[must_use]
pub fn encode_firmware_chunk_progress_payload(
    progress: FirmwareChunkProgress,
) -> [u8; 8] {
    let received = progress.bytes_received.to_le_bytes();
    let remaining = progress.remaining_bytes.to_le_bytes();
    [
        received[0],
        received[1],
        received[2],
        received[3],
        remaining[0],
        remaining[1],
        remaining[2],
        remaining[3],
    ]
}

#[must_use]
pub fn encode_firmware_finalize_payload(
    result: FirmwareFinalizeResult,
) -> [u8; 10] {
    let version = encode_firmware_version(result.validated_version);
    [
        result.staged_slot as u8,
        version[0],
        version[1],
        version[2],
        version[3],
        version[4],
        version[5],
        version[6],
        version[7],
        u8::from(result.activation_pending),
    ]
}

#[must_use]
pub fn encode_firmware_activation_payload(
    result: FirmwareActivationResult,
) -> [u8; 10] {
    let version = encode_firmware_version(result.next_version);
    [
        result.next_boot_slot as u8,
        version[0],
        version[1],
        version[2],
        version[3],
        version[4],
        version[5],
        version[6],
        version[7],
        u8::from(result.reboot_required),
    ]
}

#[must_use]
pub fn encode_firmware_abort_payload(result: FirmwareAbortResult) -> [u8; 2] {
    [
        u8::from(result.transfer_state_cleared),
        u8::from(result.staged_slot_invalidated),
    ]
}

#[must_use]
pub fn encode_firmware_recovery_payload(
    result: FirmwareRecoveryResult,
) -> [u8; 10] {
    let version = encode_firmware_version(result.restored_version);
    [
        result.restored_slot as u8,
        version[0],
        version[1],
        version[2],
        version[3],
        version[4],
        version[5],
        version[6],
        version[7],
        u8::from(result.recovery_required),
    ]
}

#[must_use]
pub fn encode_audit_page_payload(
    events: &[AuditEvent],
    cursor: AuditRetrievalCursor,
) -> Option<Vec<u8, MAX_PAYLOAD_LEN>> {
    let mut payload = Vec::new();
    payload.push(u8::try_from(events.len()).ok()?).ok()?;
    payload.push(u8::from(cursor.next_sequence.is_some())).ok()?;
    payload
        .extend_from_slice(&cursor.next_sequence.unwrap_or(0).to_le_bytes())
        .ok()?;
    payload.push(u8::from(cursor.truncated)).ok()?;
    for event in events {
        payload.extend_from_slice(&event.sequence_id.to_le_bytes()).ok()?;
        payload.push(event.event_class as u8).ok()?;
        payload.push(event.event_code as u8).ok()?;
        payload.extend_from_slice(&event.device_revision.to_le_bytes()).ok()?;
        payload.push(event.lifecycle_state as u8).ok()?;
        payload.push(event.actor_role as u8).ok()?;
        payload.push(event.session_kind as u8).ok()?;
        payload.push(event.result_class as u8).ok()?;
        payload.push(event.detail_len).ok()?;
        payload.extend_from_slice(event.detail.as_slice()).ok()?;
    }
    Some(payload)
}

#[must_use]
pub fn encode_signature_payload(signature: &[u8]) -> Option<Vec<u8, MAX_PAYLOAD_LEN>> {
    let mut payload = Vec::new();
    payload
        .extend_from_slice(&u16::try_from(signature.len()).ok()?.to_le_bytes())
        .ok()?;
    payload.extend_from_slice(signature).ok()?;
    Some(payload)
}

#[must_use]
pub fn encode_verify_result_payload(verified: bool) -> [u8; 1] {
    [u8::from(verified)]
}

#[must_use]
pub fn encode_random_payload(bytes: &[u8]) -> Option<Vec<u8, MAX_PAYLOAD_LEN>> {
    let mut payload = Vec::new();
    payload.push(u8::try_from(bytes.len()).ok()?).ok()?;
    payload.extend_from_slice(bytes).ok()?;
    Some(payload)
}

/// # Errors
///
/// Returns `StatusCode::ValidationError` when the signing request shape is malformed.
pub fn decode_sign_request(payload: &[u8]) -> Result<SignRequest, StatusCode> {
    if payload.len() < 4 {
        return Err(StatusCode::ValidationError);
    }
    let key_id = payload[0];
    let algorithm = KeyAlgorithm::from_byte(payload[1]).ok_or(StatusCode::ValidationError)?;
    let message_len = usize::from(u16::from_le_bytes([payload[2], payload[3]]));
    if message_len == 0 || message_len > MAX_CRYPTO_MESSAGE_LEN || payload.len() != 4 + message_len {
        return Err(StatusCode::ValidationError);
    }
    let mut message = Vec::<u8, MAX_CRYPTO_MESSAGE_LEN>::new();
    message
        .extend_from_slice(&payload[4..])
        .map_err(|()| StatusCode::ValidationError)?;
    Ok(SignRequest {
        key_id,
        algorithm,
        message,
    })
}

/// # Errors
///
/// Returns `StatusCode::ValidationError` when the verification request is malformed.
pub fn decode_verify_request(payload: &[u8]) -> Result<VerifyRequest, StatusCode> {
    if payload.len() < 7 {
        return Err(StatusCode::ValidationError);
    }
    let algorithm = KeyAlgorithm::from_byte(payload[0]).ok_or(StatusCode::ValidationError)?;
    let message_len = usize::from(u16::from_le_bytes([payload[1], payload[2]]));
    if message_len == 0 || message_len > MAX_CRYPTO_MESSAGE_LEN {
        return Err(StatusCode::ValidationError);
    }
    let public_key_len_index = 3 + message_len;
    if payload.len() < public_key_len_index + 1 {
        return Err(StatusCode::ValidationError);
    }
    let public_key_len = usize::from(payload[public_key_len_index]);
    let signature_len_index = public_key_len_index + 1 + public_key_len;
    if payload.len() < signature_len_index + 2 {
        return Err(StatusCode::ValidationError);
    }
    let signature_len = usize::from(u16::from_le_bytes([
        payload[signature_len_index],
        payload[signature_len_index + 1],
    ]));
    let expected_len = signature_len_index + 2 + signature_len;
    if payload.len() != expected_len
        || public_key_len == 0
        || public_key_len > P256_PUBLIC_KEY_LEN
        || signature_len == 0
        || signature_len > MAX_SIGNATURE_LEN
    {
        return Err(StatusCode::ValidationError);
    }

    let mut message = Vec::<u8, MAX_CRYPTO_MESSAGE_LEN>::new();
    message
        .extend_from_slice(&payload[3..3 + message_len])
        .map_err(|()| StatusCode::ValidationError)?;
    let mut public_key = Vec::<u8, P256_PUBLIC_KEY_LEN>::new();
    public_key
        .extend_from_slice(&payload[public_key_len_index + 1..public_key_len_index + 1 + public_key_len])
        .map_err(|()| StatusCode::ValidationError)?;
    let mut signature = Vec::<u8, MAX_SIGNATURE_LEN>::new();
    signature
        .extend_from_slice(&payload[signature_len_index + 2..])
        .map_err(|()| StatusCode::ValidationError)?;

    Ok(VerifyRequest {
        algorithm,
        message,
        public_key,
        signature,
    })
}

/// # Errors
///
/// Returns `StatusCode::ValidationError` when the random request is malformed.
pub fn decode_random_request(payload: &[u8]) -> Result<RandomRequest, StatusCode> {
    if payload.len() != 1 {
        return Err(StatusCode::ValidationError);
    }
    let requested_len = payload[0];
    if requested_len == 0 || usize::from(requested_len) > MAX_RANDOM_OUTPUT_LEN {
        return Err(StatusCode::ValidationError);
    }
    Ok(RandomRequest { requested_len })
}

/// # Errors
///
/// Returns `StatusCode::ValidationError` when the audit-page request is malformed.
pub fn decode_audit_page_request(payload: &[u8]) -> Result<(u32, u8), StatusCode> {
    if payload.len() != 5 {
        return Err(StatusCode::ValidationError);
    }
    let start_sequence = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let max_events = payload[4];
    if max_events == 0 {
        return Err(StatusCode::ValidationError);
    }
    Ok((start_sequence, max_events))
}

/// # Errors
///
/// Returns `StatusCode::ValidationError` when the wrapped import request is malformed.
pub fn decode_import_wrapped_key_request(
    payload: &[u8],
) -> Result<ImportWrappedKeyRequest, StatusCode> {
    if payload.len() < 8 {
        return Err(StatusCode::ValidationError);
    }
    let wrap_format_version = payload[0];
    let wrapping_key_id = payload[1];
    let target_algorithm = KeyAlgorithm::from_byte(payload[2]).ok_or(StatusCode::ValidationError)?;
    let target_usage_mask = payload[3];
    let target_export_policy =
        ExportPolicy::from_byte(payload[4]).ok_or(StatusCode::ValidationError)?;
    let ciphertext_len = usize::from(u16::from_le_bytes([payload[5], payload[6]]));
    if ciphertext_len == 0 || ciphertext_len > MAX_WRAPPED_CIPHERTEXT_LEN {
        return Err(StatusCode::ValidationError);
    }
    let tag_len_index = 7 + ciphertext_len;
    if payload.len() < tag_len_index + 1 {
        return Err(StatusCode::ValidationError);
    }
    let integrity_tag_len = usize::from(payload[tag_len_index]);
    let expected_len = tag_len_index + 1 + integrity_tag_len;
    if payload.len() != expected_len
        || integrity_tag_len == 0
        || integrity_tag_len > MAX_WRAPPED_TAG_LEN
    {
        return Err(StatusCode::ValidationError);
    }

    let mut ciphertext = Vec::<u8, MAX_WRAPPED_CIPHERTEXT_LEN>::new();
    ciphertext
        .extend_from_slice(&payload[7..7 + ciphertext_len])
        .map_err(|()| StatusCode::ValidationError)?;
    let mut integrity_tag = Vec::<u8, MAX_WRAPPED_TAG_LEN>::new();
    integrity_tag
        .extend_from_slice(&payload[tag_len_index + 1..])
        .map_err(|()| StatusCode::ValidationError)?;

    Ok(ImportWrappedKeyRequest {
        wrap_format_version,
        wrapping_key_id,
        target_algorithm,
        target_usage_mask,
        target_export_policy,
        ciphertext,
        integrity_tag,
    })
}

fn decode_firmware_version(bytes: &[u8]) -> Result<FirmwareVersion, StatusCode> {
    if bytes.len() != 8 {
        return Err(StatusCode::ValidationError);
    }
    Ok(FirmwareVersion {
        security_epoch: u16::from_le_bytes([bytes[0], bytes[1]]),
        major: u16::from_le_bytes([bytes[2], bytes[3]]),
        minor: u16::from_le_bytes([bytes[4], bytes[5]]),
        patch: u16::from_le_bytes([bytes[6], bytes[7]]),
    })
}

/// # Errors
///
/// Returns `StatusCode::ValidationError` when the firmware-update manifest is malformed.
pub fn decode_begin_firmware_update_request(
    payload: &[u8],
) -> Result<BeginFirmwareUpdateRequest, StatusCode> {
    if payload.len() < 48 {
        return Err(StatusCode::ValidationError);
    }
    let manifest_version = payload[0];
    if manifest_version != UPDATE_MANIFEST_VERSION {
        return Err(StatusCode::ValidationError);
    }
    let image_version = decode_firmware_version(&payload[1..9])?;
    let image_size_bytes = u32::from_le_bytes([payload[9], payload[10], payload[11], payload[12]]);
    if image_size_bytes == 0 {
        return Err(StatusCode::ValidationError);
    }
    let mut image_digest_sha256 = [0u8; 32];
    image_digest_sha256.copy_from_slice(&payload[13..45]);
    let target_slot_hint = BootSlotId::from_byte(payload[45]).ok_or(StatusCode::ValidationError)?;
    let policy_flags = u16::from_le_bytes([payload[46], payload[47]]);
    if payload.len() < 51 {
        return Err(StatusCode::ValidationError);
    }
    let signature_algorithm = payload[48];
    let signature_len = usize::from(u16::from_le_bytes([payload[49], payload[50]]));
    if signature_len == 0
        || signature_len > MAX_FIRMWARE_SIGNATURE_LEN
        || payload.len() != 51 + signature_len
    {
        return Err(StatusCode::ValidationError);
    }
    let mut signature_bytes = Vec::<u8, MAX_FIRMWARE_SIGNATURE_LEN>::new();
    signature_bytes
        .extend_from_slice(&payload[51..])
        .map_err(|()| StatusCode::ValidationError)?;
    Ok(BeginFirmwareUpdateRequest {
        manifest: FirmwarePackageManifest {
            manifest_version,
            image_version,
            image_size_bytes,
            image_digest_sha256,
            target_slot_hint,
            policy_flags,
            signature_algorithm,
            signature_bytes,
        },
    })
}

/// # Errors
///
/// Returns `StatusCode::ValidationError` when the transfer chunk request is malformed.
pub fn decode_firmware_chunk_request(
    payload: &[u8],
) -> Result<FirmwareChunkRequest, StatusCode> {
    if payload.len() < 10 {
        return Err(StatusCode::ValidationError);
    }
    let update_session_id = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let chunk_offset = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let chunk_len = usize::from(u16::from_le_bytes([payload[8], payload[9]]));
    if chunk_len == 0
        || chunk_len > MAX_FIRMWARE_CHUNK_LEN
        || payload.len() != 10 + chunk_len
    {
        return Err(StatusCode::ValidationError);
    }
    let mut chunk = Vec::<u8, MAX_FIRMWARE_CHUNK_LEN>::new();
    chunk
        .extend_from_slice(&payload[10..])
        .map_err(|()| StatusCode::ValidationError)?;
    Ok(FirmwareChunkRequest {
        update_session_id,
        chunk_offset,
        chunk,
    })
}

/// # Errors
///
/// Returns `StatusCode::ValidationError` when the payload does not contain a
/// 4-byte transition identifier followed by the required marker.
pub fn decode_transition_request(payload: &[u8], marker: u8) -> Result<u32, StatusCode> {
    if payload.len() != 5 || payload[4] != marker {
        return Err(StatusCode::ValidationError);
    }
    Ok(u32::from_le_bytes([
        payload[0], payload[1], payload[2], payload[3],
    ]))
}

/// # Errors
///
/// Returns `StatusCode::ValidationError` when the auth completion payload is malformed.
pub fn decode_complete_authentication_request(
    payload: &[u8],
) -> Result<(u32, u32, &[u8]), StatusCode> {
    if payload.len() < 9 {
        return Err(StatusCode::ValidationError);
    }
    let challenge_id = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let request_counter = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let proof_len = usize::from(payload[8]);
    if proof_len == 0 || payload.len() != 9 + proof_len {
        return Err(StatusCode::ValidationError);
    }
    Ok((challenge_id, request_counter, &payload[9..]))
}

/// # Errors
///
/// Returns `StatusCode::ValidationError` when the auth role is malformed or unsupported.
pub fn decode_authentication_role(payload: &[u8]) -> Result<AuthorityRole, StatusCode> {
    if payload.len() != 1 {
        return Err(StatusCode::ValidationError);
    }
    match payload[0] {
        0x02 => Ok(AuthorityRole::Bootstrap),
        0x03 => Ok(AuthorityRole::Administrator),
        0x04 => Ok(AuthorityRole::Recovery),
        0x06 => Ok(AuthorityRole::KeyManager),
        _ => Err(StatusCode::ValidationError),
    }
}

/// # Errors
///
/// Returns `StatusCode::ValidationError` when a privileged payload does not contain
/// a session id, a request counter, and a bounded inner payload.
pub fn decode_authorized_payload(
    payload: &[u8],
    min_inner_len: usize,
    max_inner_len: usize,
) -> Result<(u32, u32, &[u8]), StatusCode> {
    if payload.len() < 8 {
        return Err(StatusCode::ValidationError);
    }
    let inner = &payload[8..];
    if inner.len() < min_inner_len || inner.len() > max_inner_len {
        return Err(StatusCode::ValidationError);
    }
    Ok((
        u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]),
        u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]),
        inner,
    ))
}

/// # Errors
///
/// Returns `StatusCode::ValidationError` when the persistent-key payload is
/// malformed or contains unsupported enum values.
pub fn decode_put_persistent_key_request(payload: &[u8]) -> Result<PutPersistentKeyRequest, StatusCode> {
    if payload.len() < 7 {
        return Err(StatusCode::ValidationError);
    }
    let key_id = payload[0];
    let algorithm = KeyAlgorithm::from_byte(payload[1]).ok_or(StatusCode::ValidationError)?;
    let origin = KeyOrigin::from_byte(payload[2]).ok_or(StatusCode::ValidationError)?;
    let usage_mask = payload[3];
    let export_policy = ExportPolicy::from_byte(payload[4]).ok_or(StatusCode::ValidationError)?;
    let material_len = usize::from(payload[5]);
    if material_len == 0 || payload.len() != 6 + material_len {
        return Err(StatusCode::ValidationError);
    }
    let material = KeyMaterialEnvelope::try_from_bytes(origin, &payload[6..])
        .ok_or(StatusCode::ValidationError)?;
    Ok(PutPersistentKeyRequest {
        key_id,
        algorithm,
        origin,
        usage_mask,
        export_policy,
        material,
    })
}

/// # Errors
///
/// Returns `StatusCode::ValidationError` when the payload does not contain the
/// expected key identifier and marker.
pub fn decode_key_marker_request(payload: &[u8], marker: &[u8]) -> Result<u8, StatusCode> {
    if payload.len() != marker.len() + 1 || &payload[1..] != marker {
        return Err(StatusCode::ValidationError);
    }
    Ok(payload[0])
}

/// # Errors
///
/// Returns `StatusCode::ValidationError` when the payload does not contain a
/// single key identifier byte.
pub fn decode_key_id_request(payload: &[u8]) -> Result<u8, StatusCode> {
    if payload.len() != 1 {
        return Err(StatusCode::ValidationError);
    }
    Ok(payload[0])
}
