use heapless::Vec;

use super::frame::{
    HEADER_LEN, MAX_FRAME_LEN, MAX_PAYLOAD_LEN, MessageKind, PROTOCOL_VERSION, ProtocolFrame,
    RESERVED_FLAG_MASK,
};
use super::state::{
    AuthorityRole, CryptoCapabilities, DeveloperResetOutcome, DeviceState, ExportPolicy,
    ImportWrappedKeyRequest, KeyAlgorithm, KeyDestroyResult, KeyListEntry, KeyMaterialEnvelope,
    KeyMetadataView, KeyOrigin, KeyRecordResult, KeyStoreStatus, LifecycleStatus, LockResult,
    MAX_CRYPTO_MESSAGE_LEN, MAX_RANDOM_OUTPUT_LEN, MAX_SIGNATURE_LEN, MAX_WRAPPED_CIPHERTEXT_LEN,
    MAX_WRAPPED_TAG_LEN, P256_PUBLIC_KEY_LEN, PutPersistentKeyRequest, RandomRequest,
    RecoveryResult, SessionState, SessionStatus, SignRequest, StateRevision, TransitionResult,
    VerifyRequest, ZeroizeOutcome,
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
