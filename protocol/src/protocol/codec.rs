use heapless::Vec;

use super::frame::{
    HEADER_LEN, MAX_FRAME_LEN, MAX_PAYLOAD_LEN, MessageKind, PROTOCOL_VERSION, ProtocolFrame,
    RESERVED_FLAG_MASK,
};
use super::state::{
    DeveloperResetOutcome, DeviceState, LifecycleStatus, LockResult, RecoveryResult, SessionState,
    StateRevision, TransitionResult, ZeroizeOutcome,
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
