use core::slice;

use critical_section::with;
use heapless::Vec;
use protocol::protocol::{
    ApprovalTargetBinding, ApprovalTicket, ApprovalTicketState, AuditEvent, AuditEventClass,
    AuditEventCode, AuditResultClass, AuditStoreSnapshot, AuthSnapshot, AuthorityRole,
    CredentialKind, CredentialRecord, CryptoPersistentState, DeveloperStoreFaultAction,
    DeviceState, ExportPolicy, KeyAlgorithm, KeyLifecycleState, KeyMetadata, KeyOrigin,
    KeyStoreRecord, KeyStoreSnapshot, MAX_APPROVAL_TICKETS, MAX_AUDIT_DETAIL_LEN,
    MAX_AUDIT_EVENTS, MAX_KEY_JOURNAL_RECORDS, MAX_KEY_MATERIAL_LEN, POLICY_PROFILE_VERSION,
    PolicyProfile, ProtectedActionClass, ProvisioningSnapshot, RecoveryPolicy, SessionState,
    TransitionIntent, TransitionType,
};
use protocol::protocol::state::{
    AuthorizationMode, FreshnessAnchor, KeyMaterialEnvelope, LifecycleState, MaterialEncoding,
    OwnerBinding, MAX_AUTH_SNAPSHOT_LEN, MAX_OWNER_ID_LEN,
};
use rp235x_hal as hal;

const FLASH_XIP_BASE: usize = 0x1000_0000;
const SLOT_SIZE: usize = 4096;
const PAGE_SIZE: usize = 256;
const MAGIC: [u8; 4] = *b"HSM3";
const FORMAT_VERSION: u8 = 2;
const HEADER_SIZE: usize = 20;
const PAYLOAD_CAPACITY: usize = SLOT_SIZE - HEADER_SIZE;

unsafe extern "C" {
    static __persistent_store_start: u8;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistedState {
    pub provisioning: ProvisioningSnapshot,
    pub key_store: KeyStoreSnapshot,
    pub audit: AuditStoreSnapshot,
    pub auth: AuthSnapshot,
    pub crypto: CryptoPersistentState,
    pub policy: PolicyProfile,
    pub approval_tickets: Vec<ApprovalTicket, MAX_APPROVAL_TICKETS>,
    pub next_approval_ticket_id: u32,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoadOutcome {
    Empty,
    Restored(PersistedState),
    Corrupted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PersistenceError {
    EncodeOverflow,
    DecodeFailure,
    MissingState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SlotHeader {
    generation: u32,
    payload_len: u16,
    payload_crc: u32,
    header_crc: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ValidSlot {
    index: usize,
    generation: u32,
    state: PersistedState,
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
enum SlotScan {
    Empty,
    Valid(ValidSlot),
    Invalid,
}

pub struct FlashStateStore;

impl FlashStateStore {
    pub fn load() -> Result<LoadOutcome, PersistenceError> {
        let slot0 = scan_slot(0);
        let slot1 = scan_slot(1);

        match (&slot0, &slot1) {
            (SlotScan::Invalid, _)
            | (_, SlotScan::Invalid) => Ok(LoadOutcome::Corrupted),
            (SlotScan::Empty, SlotScan::Empty) => Ok(LoadOutcome::Empty),
            _ => {
                let best = [slot0, slot1]
                    .into_iter()
                    .filter_map(|slot| match slot {
                        SlotScan::Valid(valid) => Some(valid),
                        SlotScan::Empty | SlotScan::Invalid => None,
                    })
                    .max_by_key(|slot| slot.generation)
                    .ok_or(PersistenceError::MissingState)?;
                Ok(LoadOutcome::Restored(best.state))
            }
        }
    }

    pub fn save(state: &PersistedState) -> Result<(), PersistenceError> {
        let active = Self::active_slot();
        if active.is_none() {
            erase_slot(0);
            erase_slot(1);
        }
        let generation = active
            .as_ref()
            .map_or(1, |slot| slot.generation.saturating_add(1));
        let target_slot = active.as_ref().map_or(0, |slot| usize::from(slot.index == 0));
        write_slot(target_slot, generation, state)
    }

    pub fn inject_fault(
        action: DeveloperStoreFaultAction,
    ) -> Result<(), PersistenceError> {
        let active = Self::active_slot().ok_or(PersistenceError::MissingState)?;
        let target_slot = usize::from(active.index == 0);

        match action {
            DeveloperStoreFaultAction::CorruptPersistedStore => {
                write_invalid_slot(target_slot);
                Ok(())
            }
            DeveloperStoreFaultAction::RollbackPersistedStore => {
                let mut state = active.state.clone();
                state.key_store.anchor.accepted_device_revision = 0;
                state.key_store.anchor.refresh_integrity();
                write_slot(target_slot, active.generation.saturating_add(1), &state)
            }
            DeveloperStoreFaultAction::CorruptPersistedAudit => {
                let mut state = active.state.clone();
                if let Some(event) = state.audit.events.first_mut() {
                    event.integrity_tag ^= 0xffff_ffff;
                } else {
                    state.audit.corruption_detected = true;
                    state.audit.retrieval_locked = true;
                }
                write_slot(target_slot, active.generation.saturating_add(1), &state)
            }
            DeveloperStoreFaultAction::RollbackPersistedAudit => {
                let mut state = active.state.clone();
                state.audit.next_sequence_id = 1;
                state.audit.retrieval_locked = true;
                state.audit.corruption_detected = true;
                write_slot(target_slot, active.generation.saturating_add(1), &state)
            }
        }
    }

    fn active_slot() -> Option<ValidSlot> {
        let slot0 = scan_slot(0);
        let slot1 = scan_slot(1);
        if matches!(slot0, SlotScan::Invalid) || matches!(slot1, SlotScan::Invalid) {
            return None;
        }

        [slot0, slot1]
            .into_iter()
            .filter_map(|slot| match slot {
                SlotScan::Valid(valid) => Some(valid),
                SlotScan::Empty | SlotScan::Invalid => None,
            })
            .max_by_key(|slot| slot.generation)
    }
}

pub fn corrupted_recovery_state() -> PersistedState {
    let mut corrupted_record = KeyStoreRecord::new(
        0,
        1,
        1,
        1,
        KeyLifecycleState::Active,
        KeyMetadata {
            algorithm: KeyAlgorithm::Ed25519,
            origin: KeyOrigin::Imported,
            usage_mask: 0x01,
            export_policy: ExportPolicy::NonExportable,
            created_revision: 1,
            last_state_change_revision: 1,
        },
        KeyMaterialEnvelope::try_from_bytes(KeyOrigin::Imported, b"invalid")
            .unwrap_or_default(),
    );
    corrupted_record.integrity_tag ^= 0xffff_ffff;

    let mut journal = Vec::<KeyStoreRecord, MAX_KEY_JOURNAL_RECORDS>::new();
    let _ = journal.push(corrupted_record);

    let mut anchor = FreshnessAnchor::new(1);
    anchor.accepted_store_epoch = 1;
    anchor.store_revision = 1;
    anchor.refresh_integrity();

    PersistedState {
        provisioning: ProvisioningSnapshot {
            record_version: 1,
            lifecycle_state: LifecycleState {
                state_code: DeviceState::Recovery,
                entered_revision: 0,
            },
            pending_transition: None,
            owner_binding: OwnerBinding::default(),
            recovery_policy: RecoveryPolicy::default(),
            revision_counter: 0,
            integrity_tag: 0,
            next_transition_id: 1,
        },
        key_store: KeyStoreSnapshot {
            journal,
            anchor,
        },
        audit: AuditStoreSnapshot {
            events: Vec::new(),
            next_sequence_id: 1,
            overflow_count: 0,
            corruption_detected: true,
            retrieval_locked: true,
        },
        auth: AuthSnapshot::default(),
        crypto: CryptoPersistentState::default(),
        policy: PolicyProfile::default(),
        approval_tickets: Vec::new(),
        next_approval_ticket_id: 1,
    }
}

fn scan_slot(index: usize) -> SlotScan {
    let bytes = slot_bytes(index);
    if bytes.iter().all(|byte| *byte == 0xff) {
        return SlotScan::Empty;
    }

    let Some(header) = decode_header(bytes) else {
        return SlotScan::Invalid;
    };

    let payload_end = HEADER_SIZE + usize::from(header.payload_len);
    if payload_end > SLOT_SIZE {
        return SlotScan::Invalid;
    }

    let payload = &bytes[HEADER_SIZE..payload_end];
    if checksum(payload) != header.payload_crc {
        return SlotScan::Invalid;
    }

    let Ok(state) = decode_state(payload) else {
        return SlotScan::Invalid;
    };
    SlotScan::Valid(ValidSlot {
        index,
        generation: header.generation,
        state,
    })
}

fn write_slot(
    index: usize,
    generation: u32,
    state: &PersistedState,
) -> Result<(), PersistenceError> {
    let mut payload = Vec::<u8, PAYLOAD_CAPACITY>::new();
    encode_state(state, &mut payload)?;

    let payload_crc = checksum(payload.as_slice());
    let payload_len =
        u16::try_from(payload.len()).map_err(|_| PersistenceError::EncodeOverflow)?;
    let mut header = [0xff; HEADER_SIZE];
    header[0..4].copy_from_slice(&MAGIC);
    header[4] = FORMAT_VERSION;
    header[5] = 0;
    header[6..8].copy_from_slice(&payload_len.to_le_bytes());
    header[8..12].copy_from_slice(&generation.to_le_bytes());
    header[12..16].copy_from_slice(&payload_crc.to_le_bytes());
    let header_crc = checksum(&header[..16]);
    header[16..20].copy_from_slice(&header_crc.to_le_bytes());

    let mut image = [0xff; SLOT_SIZE];
    image[..HEADER_SIZE].copy_from_slice(&header);
    image[HEADER_SIZE..HEADER_SIZE + payload.len()].copy_from_slice(payload.as_slice());
    program_slot(index, &image);
    Ok(())
}

fn write_invalid_slot(index: usize) {
    let mut image = [0xff; SLOT_SIZE];
    image[..4].copy_from_slice(&MAGIC);
    image[4] = FORMAT_VERSION;
    image[8..12].copy_from_slice(&1u32.to_le_bytes());
    program_slot(index, &image);
}

fn erase_slot(index: usize) {
    let offset = slot_offset(index);
    with(|_| unsafe {
        hal::rom_data::connect_internal_flash();
        hal::rom_data::flash_exit_xip();
        hal::rom_data::flash_range_erase(offset, SLOT_SIZE, 4096, 0x20);
        hal::rom_data::flash_flush_cache();
        hal::rom_data::flash_enter_cmd_xip();
    });
}

fn program_slot(index: usize, image: &[u8; SLOT_SIZE]) {
    let offset = slot_offset(index);
    erase_slot(index);
    with(|_| unsafe {
        hal::rom_data::connect_internal_flash();
        hal::rom_data::flash_exit_xip();
        for (page_index, chunk) in image.chunks(PAGE_SIZE).enumerate() {
            hal::rom_data::flash_range_program(
                offset + u32::try_from(page_index * PAGE_SIZE).unwrap_or(0),
                chunk.as_ptr(),
                PAGE_SIZE,
            );
        }
        hal::rom_data::flash_flush_cache();
        hal::rom_data::flash_enter_cmd_xip();
    });
}

fn decode_header(bytes: &[u8]) -> Option<SlotHeader> {
    if bytes.len() < HEADER_SIZE || bytes[..4] != MAGIC || bytes[4] != FORMAT_VERSION {
        return None;
    }

    let generation = u32::from_le_bytes(bytes[8..12].try_into().ok()?);
    let payload_crc = u32::from_le_bytes(bytes[12..16].try_into().ok()?);
    let header_crc = u32::from_le_bytes(bytes[16..20].try_into().ok()?);
    if checksum(&bytes[..16]) != header_crc {
        return None;
    }

    Some(SlotHeader {
        generation,
        payload_len: u16::from_le_bytes(bytes[6..8].try_into().ok()?),
        payload_crc,
        header_crc,
    })
}

fn encode_state(
    state: &PersistedState,
    out: &mut Vec<u8, PAYLOAD_CAPACITY>,
) -> Result<(), PersistenceError> {
    encode_provisioning(&state.provisioning, out)?;
    encode_key_store(&state.key_store, out)?;
    encode_audit_store(&state.audit, out)?;
    encode_auth_snapshot(&state.auth, out)?;
    encode_crypto_state(&state.crypto, out)?;
    encode_policy_state(&state.policy, &state.approval_tickets, state.next_approval_ticket_id, out)
}

fn encode_provisioning(
    snapshot: &ProvisioningSnapshot,
    out: &mut Vec<u8, PAYLOAD_CAPACITY>,
) -> Result<(), PersistenceError> {
    push_u8(out, snapshot.record_version)?;
    push_u8(out, snapshot.lifecycle_state.state_code as u8)?;
    push_u32(out, snapshot.lifecycle_state.entered_revision)?;
    push_u32(out, snapshot.revision_counter)?;
    push_u32(out, snapshot.integrity_tag)?;
    push_u32(out, snapshot.next_transition_id)?;
    push_u8(out, u8::from(snapshot.recovery_policy.recovery_enabled))?;
    push_u8(out, snapshot.recovery_policy.required_authority as u8)?;
    push_u8(out, snapshot.recovery_policy.max_attempts)?;
    push_vec(out, &snapshot.owner_binding.owner_id)?;
    push_u32(out, snapshot.owner_binding.provisioning_epoch)?;
    push_u8(out, snapshot.owner_binding.authorization_mode as u8)?;
    push_u8(out, u8::from(snapshot.owner_binding.transfer_allowed))?;
    push_u32(out, snapshot.owner_binding.binding_digest)?;
    match &snapshot.pending_transition {
        Some(transition) => {
            push_u8(out, 1)?;
            push_transition(transition, out)?;
        }
        None => push_u8(out, 0)?,
    }
    Ok(())
}

fn encode_key_store(
    snapshot: &KeyStoreSnapshot,
    out: &mut Vec<u8, PAYLOAD_CAPACITY>,
) -> Result<(), PersistenceError> {
    push_u32(out, snapshot.anchor.accepted_store_epoch)?;
    push_u32(out, snapshot.anchor.accepted_device_revision)?;
    push_u32(out, snapshot.anchor.store_revision)?;
    push_u32(out, snapshot.anchor.integrity_tag)?;
    push_u8(
        out,
        u8::try_from(snapshot.journal.len()).map_err(|_| PersistenceError::EncodeOverflow)?,
    )?;
    for record in &snapshot.journal {
        push_u8(out, record.record_version)?;
        push_u8(out, record.slot_id)?;
        push_u8(out, record.key_id)?;
        push_u32(out, record.record_revision)?;
        push_u32(out, record.store_epoch)?;
        push_u8(out, record.lifecycle_state as u8)?;
        push_u8(out, record.metadata.algorithm as u8)?;
        push_u8(out, record.metadata.origin as u8)?;
        push_u8(out, record.metadata.usage_mask)?;
        push_u8(out, record.metadata.export_policy as u8)?;
        push_u32(out, record.metadata.created_revision)?;
        push_u32(out, record.metadata.last_state_change_revision)?;
        push_u8(out, record.material.encoding as u8)?;
        push_vec(out, &record.material.material_bytes)?;
        push_u8(out, u8::from(record.material.destroyed_marker))?;
        push_u8(out, u8::from(record.complete))?;
        push_u32(out, record.integrity_tag)?;
    }
    Ok(())
}

fn encode_auth_snapshot(
    snapshot: &AuthSnapshot,
    out: &mut Vec<u8, PAYLOAD_CAPACITY>,
) -> Result<(), PersistenceError> {
    push_u8(
        out,
        u8::try_from(snapshot.credentials.len()).map_err(|_| PersistenceError::EncodeOverflow)?,
    )?;
    for credential in &snapshot.credentials {
        push_u8(out, credential.role as u8)?;
        push_u8(out, credential.credential_kind as u8)?;
        push_vec(out, &credential.verifier_bytes)?;
        push_u8(out, u8::from(credential.enabled))?;
        push_u8(out, credential.session_timeout_ticks.to_le_bytes()[0])?;
        push_u8(out, credential.session_timeout_ticks.to_le_bytes()[1])?;
        push_u8(out, credential.max_failures)?;
        push_u8(out, credential.lockout_ticks.to_le_bytes()[0])?;
        push_u8(out, credential.lockout_ticks.to_le_bytes()[1])?;
    }
    push_u8(
        out,
        u8::try_from(snapshot.failure_counters.len())
            .map_err(|_| PersistenceError::EncodeOverflow)?,
    )?;
    for counter in &snapshot.failure_counters {
        push_u8(out, counter.role as u8)?;
        push_u8(out, counter.consecutive_failures)?;
        push_u32(out, counter.locked_until_tick)?;
    }
    push_u32(out, snapshot.next_challenge_id)?;
    push_u32(out, snapshot.next_session_id)
}

fn encode_audit_store(
    snapshot: &AuditStoreSnapshot,
    out: &mut Vec<u8, PAYLOAD_CAPACITY>,
) -> Result<(), PersistenceError> {
    push_u32(out, snapshot.next_sequence_id)?;
    push_u32(out, snapshot.overflow_count)?;
    push_u8(out, u8::from(snapshot.corruption_detected))?;
    push_u8(out, u8::from(snapshot.retrieval_locked))?;
    push_u8(
        out,
        u8::try_from(snapshot.events.len()).map_err(|_| PersistenceError::EncodeOverflow)?,
    )?;
    for event in &snapshot.events {
        push_u32(out, event.sequence_id)?;
        push_u8(out, event.event_class as u8)?;
        push_u8(out, event.event_code as u8)?;
        push_u32(out, event.device_revision)?;
        push_u8(out, event.lifecycle_state as u8)?;
        push_u8(out, event.actor_role as u8)?;
        push_u8(out, event.session_kind as u8)?;
        push_u8(out, event.result_class as u8)?;
        push_vec(out, &event.detail)?;
        push_u32(out, event.integrity_tag)?;
    }
    Ok(())
}

fn encode_crypto_state(
    snapshot: &CryptoPersistentState,
    out: &mut Vec<u8, PAYLOAD_CAPACITY>,
) -> Result<(), PersistenceError> {
    push_u8(out, snapshot.policy_version)?;
    push_u32(out, snapshot.wrapped_import_count)?;
    push_u32(out, snapshot.last_wrapped_import_revision)
}

fn encode_policy_state(
    profile: &PolicyProfile,
    tickets: &Vec<ApprovalTicket, MAX_APPROVAL_TICKETS>,
    next_ticket_id: u32,
    out: &mut Vec<u8, PAYLOAD_CAPACITY>,
) -> Result<(), PersistenceError> {
    push_u8(out, profile.profile_version)?;
    push_u32(out, profile.policy_revision)?;
    push_u8(out, u8::from(profile.dual_control_enabled))?;
    out.extend_from_slice(&profile.protected_action_mask.to_le_bytes())
        .map_err(|()| PersistenceError::EncodeOverflow)?;
    push_u8(out, u8::from(profile.developer_commands_visible))?;
    push_u8(
        out,
        u8::try_from(tickets.len()).map_err(|_| PersistenceError::EncodeOverflow)?,
    )?;
    for ticket in tickets {
        push_u32(out, ticket.ticket_id)?;
        push_u8(out, ticket.approval_class as u8)?;
        push_u8(out, ticket.target_binding as u8)?;
        push_u32(out, ticket.target_id)?;
        push_u8(out, ticket.initiator_role as u8)?;
        push_u8(out, ticket.confirmer_role as u8)?;
        push_u32(out, ticket.initiator_session_id)?;
        push_u32(out, ticket.policy_revision)?;
        push_u32(out, ticket.device_revision)?;
        push_u32(out, ticket.expires_at_tick)?;
        push_u8(out, ticket.state as u8)?;
    }
    push_u32(out, next_ticket_id)
}

fn push_transition(
    transition: &TransitionIntent,
    out: &mut Vec<u8, PAYLOAD_CAPACITY>,
) -> Result<(), PersistenceError> {
    push_u32(out, transition.transition_id)?;
    push_u8(out, transition.transition_type as u8)?;
    push_u8(out, transition.source_state as u8)?;
    push_u8(out, transition.target_state as u8)?;
    push_u8(out, transition.command_code)?;
    push_vec(out, &transition.authorization_snapshot)?;
    push_u32(out, transition.created_revision)
}

fn push_u8(out: &mut Vec<u8, PAYLOAD_CAPACITY>, value: u8) -> Result<(), PersistenceError> {
    out.push(value).map_err(|_| PersistenceError::EncodeOverflow)
}

fn push_u32(out: &mut Vec<u8, PAYLOAD_CAPACITY>, value: u32) -> Result<(), PersistenceError> {
    out.extend_from_slice(&value.to_le_bytes())
        .map_err(|()| PersistenceError::EncodeOverflow)
}

fn push_vec<const N: usize>(
    out: &mut Vec<u8, PAYLOAD_CAPACITY>,
    bytes: &Vec<u8, N>,
) -> Result<(), PersistenceError> {
    push_u8(
        out,
        u8::try_from(bytes.len()).map_err(|_| PersistenceError::EncodeOverflow)?,
    )?;
    out.extend_from_slice(bytes.as_slice())
        .map_err(|()| PersistenceError::EncodeOverflow)
}

fn decode_state(bytes: &[u8]) -> Result<PersistedState, PersistenceError> {
    let mut cursor = Cursor::new(bytes);
    let provisioning = decode_provisioning(&mut cursor)?;
    let key_store = decode_key_store(&mut cursor)?;
    let audit = decode_audit_store(&mut cursor)?;
    let auth = decode_auth_snapshot(&mut cursor)?;
    let crypto = decode_crypto_state(&mut cursor)?;
    let (policy, approval_tickets, next_approval_ticket_id) = decode_policy_state(&mut cursor)?;
    if !cursor.is_at_end() {
        return Err(PersistenceError::DecodeFailure);
    }
    Ok(PersistedState {
        provisioning,
        key_store,
        audit,
        auth,
        crypto,
        policy,
        approval_tickets,
        next_approval_ticket_id,
    })
}

fn decode_provisioning(cursor: &mut Cursor<'_>) -> Result<ProvisioningSnapshot, PersistenceError> {
    let record_version = cursor.read_u8()?;
    let lifecycle_state = LifecycleState {
        state_code: decode_device_state(cursor.read_u8()?)?,
        entered_revision: cursor.read_u32()?,
    };
    let revision_counter = cursor.read_u32()?;
    let integrity_tag = cursor.read_u32()?;
    let next_transition_id = cursor.read_u32()?;
    let recovery_policy = RecoveryPolicy {
        recovery_enabled: cursor.read_u8()? != 0,
        required_authority: decode_authority_role(cursor.read_u8()?)?,
        max_attempts: cursor.read_u8()?,
    };
    let owner_id = cursor.read_vec::<{ MAX_OWNER_ID_LEN }>()?;
    let owner_binding = OwnerBinding {
        owner_id,
        provisioning_epoch: cursor.read_u32()?,
        authorization_mode: decode_authorization_mode(cursor.read_u8()?)?,
        transfer_allowed: cursor.read_u8()? != 0,
        binding_digest: cursor.read_u32()?,
    };
    let pending_transition = match cursor.read_u8()? {
        0 => None,
        1 => Some(decode_transition(cursor)?),
        _ => return Err(PersistenceError::DecodeFailure),
    };

    Ok(ProvisioningSnapshot {
        record_version,
        lifecycle_state,
        pending_transition,
        owner_binding,
        recovery_policy,
        revision_counter,
        integrity_tag,
        next_transition_id,
    })
}

fn decode_transition(cursor: &mut Cursor<'_>) -> Result<TransitionIntent, PersistenceError> {
    Ok(TransitionIntent {
        transition_id: cursor.read_u32()?,
        transition_type: decode_transition_type(cursor.read_u8()?)?,
        source_state: decode_device_state(cursor.read_u8()?)?,
        target_state: decode_device_state(cursor.read_u8()?)?,
        command_code: cursor.read_u8()?,
        authorization_snapshot: cursor.read_vec::<{ MAX_AUTH_SNAPSHOT_LEN }>()?,
        created_revision: cursor.read_u32()?,
    })
}

fn decode_key_store(cursor: &mut Cursor<'_>) -> Result<KeyStoreSnapshot, PersistenceError> {
    let anchor = FreshnessAnchor {
        accepted_store_epoch: cursor.read_u32()?,
        accepted_device_revision: cursor.read_u32()?,
        store_revision: cursor.read_u32()?,
        integrity_tag: cursor.read_u32()?,
    };
    let journal_len = usize::from(cursor.read_u8()?);
    let mut journal = Vec::<KeyStoreRecord, MAX_KEY_JOURNAL_RECORDS>::new();
    for _ in 0..journal_len {
        let record_version = cursor.read_u8()?;
        let slot_id = cursor.read_u8()?;
        let key_id = cursor.read_u8()?;
        let record_revision = cursor.read_u32()?;
        let store_epoch = cursor.read_u32()?;
        let lifecycle_state = decode_key_lifecycle_state(cursor.read_u8()?)?;
        let algorithm = decode_key_algorithm(cursor.read_u8()?)?;
        let origin = decode_key_origin(cursor.read_u8()?)?;
        let usage_mask = cursor.read_u8()?;
        let export_policy = decode_export_policy(cursor.read_u8()?)?;
        let created_revision = cursor.read_u32()?;
        let last_state_change_revision = cursor.read_u32()?;
        let encoding = decode_material_encoding(cursor.read_u8()?)?;
        let material_bytes = cursor.read_vec::<MAX_KEY_MATERIAL_LEN>()?;
        let material_len =
            u8::try_from(material_bytes.len()).map_err(|_| PersistenceError::DecodeFailure)?;
        let material = KeyMaterialEnvelope {
            encoding,
            material_len,
            material_bytes,
            destroyed_marker: cursor.read_u8()? != 0,
        };
        let record = KeyStoreRecord {
            record_version,
            slot_id,
            key_id,
            record_revision,
            store_epoch,
            lifecycle_state,
            metadata: KeyMetadata {
                algorithm,
                origin,
                usage_mask,
                export_policy,
                created_revision,
                last_state_change_revision,
            },
            material,
            complete: cursor.read_u8()? != 0,
            integrity_tag: cursor.read_u32()?,
        };
        journal
            .push(record)
            .map_err(|_| PersistenceError::DecodeFailure)?;
    }
    Ok(KeyStoreSnapshot { journal, anchor })
}

fn decode_auth_snapshot(cursor: &mut Cursor<'_>) -> Result<AuthSnapshot, PersistenceError> {
    let credential_len = usize::from(cursor.read_u8()?);
    let mut credentials = Vec::new();
    for _ in 0..credential_len {
        let role = decode_authority_role(cursor.read_u8()?)?;
        let credential_kind = decode_credential_kind(cursor.read_u8()?)?;
        let verifier_bytes = cursor.read_vec()?;
        let enabled = cursor.read_u8()? != 0;
        let session_timeout_ticks = u16::from_le_bytes([cursor.read_u8()?, cursor.read_u8()?]);
        let max_failures = cursor.read_u8()?;
        let lockout_ticks = u16::from_le_bytes([cursor.read_u8()?, cursor.read_u8()?]);
        credentials
            .push(CredentialRecord {
                role,
                credential_kind,
                verifier_bytes,
                enabled,
                session_timeout_ticks,
                max_failures,
                lockout_ticks,
            })
            .map_err(|_| PersistenceError::DecodeFailure)?;
    }

    let counter_len = usize::from(cursor.read_u8()?);
    let mut failure_counters = Vec::new();
    for _ in 0..counter_len {
        failure_counters
            .push(protocol::protocol::AccessFailureCounter {
                role: decode_authority_role(cursor.read_u8()?)?,
                consecutive_failures: cursor.read_u8()?,
                locked_until_tick: cursor.read_u32()?,
            })
            .map_err(|_| PersistenceError::DecodeFailure)?;
    }

    Ok(AuthSnapshot {
        credentials,
        failure_counters,
        next_challenge_id: cursor.read_u32()?,
        next_session_id: cursor.read_u32()?,
    })
}

fn decode_audit_store(cursor: &mut Cursor<'_>) -> Result<AuditStoreSnapshot, PersistenceError> {
    let next_sequence_id = cursor.read_u32()?;
    let overflow_count = cursor.read_u32()?;
    let corruption_detected = cursor.read_u8()? != 0;
    let retrieval_locked = cursor.read_u8()? != 0;
    let event_len = usize::from(cursor.read_u8()?);
    let mut events = Vec::<AuditEvent, MAX_AUDIT_EVENTS>::new();
    for _ in 0..event_len {
        let sequence_id = cursor.read_u32()?;
        let event_class = decode_audit_event_class(cursor.read_u8()?)?;
        let event_code = decode_audit_event_code(cursor.read_u8()?)?;
        let device_revision = cursor.read_u32()?;
        let lifecycle_state = decode_device_state(cursor.read_u8()?)?;
        let actor_role = decode_authority_role(cursor.read_u8()?)?;
        let session_kind = decode_session_state(cursor.read_u8()?)?;
        let result_class = decode_audit_result_class(cursor.read_u8()?)?;
        let detail = cursor.read_vec::<MAX_AUDIT_DETAIL_LEN>()?;
        let detail_len = u8::try_from(detail.len()).map_err(|_| PersistenceError::DecodeFailure)?;
        let integrity_tag = cursor.read_u32()?;
        events
            .push(AuditEvent {
                sequence_id,
                event_class,
                event_code,
                device_revision,
                lifecycle_state,
                actor_role,
                session_kind,
                result_class,
                detail_len,
                detail,
                integrity_tag,
            })
            .map_err(|_| PersistenceError::DecodeFailure)?;
    }
    Ok(AuditStoreSnapshot {
        events,
        next_sequence_id,
        overflow_count,
        corruption_detected,
        retrieval_locked,
    })
}

fn decode_crypto_state(cursor: &mut Cursor<'_>) -> Result<CryptoPersistentState, PersistenceError> {
    Ok(CryptoPersistentState {
        policy_version: cursor.read_u8()?,
        wrapped_import_count: cursor.read_u32()?,
        last_wrapped_import_revision: cursor.read_u32()?,
    })
}

fn decode_policy_state(
    cursor: &mut Cursor<'_>,
) -> Result<(PolicyProfile, Vec<ApprovalTicket, MAX_APPROVAL_TICKETS>, u32), PersistenceError> {
    let profile = PolicyProfile {
        profile_version: cursor.read_u8()?,
        policy_revision: cursor.read_u32()?,
        dual_control_enabled: cursor.read_u8()? != 0,
        protected_action_mask: u16::from_le_bytes([cursor.read_u8()?, cursor.read_u8()?]),
        developer_commands_visible: cursor.read_u8()? != 0,
    };
    if profile.profile_version != POLICY_PROFILE_VERSION {
        return Err(PersistenceError::DecodeFailure);
    }
    let ticket_len = usize::from(cursor.read_u8()?);
    let mut tickets = Vec::<ApprovalTicket, MAX_APPROVAL_TICKETS>::new();
    for _ in 0..ticket_len {
        tickets
            .push(ApprovalTicket {
                ticket_id: cursor.read_u32()?,
                approval_class: decode_protected_action_class(cursor.read_u8()?)?,
                target_binding: decode_approval_target_binding(cursor.read_u8()?)?,
                target_id: cursor.read_u32()?,
                initiator_role: decode_authority_role(cursor.read_u8()?)?,
                confirmer_role: decode_authority_role(cursor.read_u8()?)?,
                initiator_session_id: cursor.read_u32()?,
                policy_revision: cursor.read_u32()?,
                device_revision: cursor.read_u32()?,
                expires_at_tick: cursor.read_u32()?,
                state: decode_approval_ticket_state(cursor.read_u8()?)?,
            })
            .map_err(|_| PersistenceError::DecodeFailure)?;
    }
    let next_ticket_id = cursor.read_u32()?;
    Ok((profile, tickets, next_ticket_id))
}

fn decode_device_state(byte: u8) -> Result<DeviceState, PersistenceError> {
    match byte {
        0x01 => Ok(DeviceState::Factory),
        0x02 => Ok(DeviceState::Provisioned),
        0x03 => Ok(DeviceState::Operational),
        0x04 => Ok(DeviceState::Locked),
        0x05 => Ok(DeviceState::Recovery),
        0x06 => Ok(DeviceState::Zeroized),
        _ => Err(PersistenceError::DecodeFailure),
    }
}

fn decode_authority_role(byte: u8) -> Result<AuthorityRole, PersistenceError> {
    match byte {
        0x01 => Ok(AuthorityRole::Public),
        0x02 => Ok(AuthorityRole::Bootstrap),
        0x03 => Ok(AuthorityRole::Administrator),
        0x04 => Ok(AuthorityRole::Recovery),
        0x05 => Ok(AuthorityRole::Developer),
        0x06 => Ok(AuthorityRole::KeyManager),
        _ => Err(PersistenceError::DecodeFailure),
    }
}

fn decode_session_state(byte: u8) -> Result<SessionState, PersistenceError> {
    match byte {
        0x01 => Ok(SessionState::Unauthenticated),
        0x02 => Ok(SessionState::Bootstrap),
        0x03 => Ok(SessionState::Administrator),
        0x04 => Ok(SessionState::Recovery),
        0x05 => Ok(SessionState::Developer),
        0x06 => Ok(SessionState::KeyManager),
        _ => Err(PersistenceError::DecodeFailure),
    }
}

fn decode_audit_event_class(byte: u8) -> Result<AuditEventClass, PersistenceError> {
    match byte {
        0x01 => Ok(AuditEventClass::Administrative),
        0x02 => Ok(AuditEventClass::SecurityDenial),
        0x03 => Ok(AuditEventClass::LifecycleTransition),
        0x04 => Ok(AuditEventClass::PersistenceAnomaly),
        0x05 => Ok(AuditEventClass::ObservabilityAccess),
        _ => Err(PersistenceError::DecodeFailure),
    }
}

fn decode_audit_event_code(byte: u8) -> Result<AuditEventCode, PersistenceError> {
    match byte {
        0x01 => Ok(AuditEventCode::CommandCompleted),
        0x02 => Ok(AuditEventCode::CommandDenied),
        0x03 => Ok(AuditEventCode::AuthenticationFailed),
        0x04 => Ok(AuditEventCode::SessionInvalidated),
        0x05 => Ok(AuditEventCode::HealthStatusViewed),
        0x06 => Ok(AuditEventCode::HealthStatusDenied),
        0x07 => Ok(AuditEventCode::AuditPageViewed),
        0x08 => Ok(AuditEventCode::AuditPageDenied),
        0x09 => Ok(AuditEventCode::RetentionOverflow),
        0x0a => Ok(AuditEventCode::PersistenceFault),
        0x0b => Ok(AuditEventCode::DeveloperPolicyChanged),
        _ => Err(PersistenceError::DecodeFailure),
    }
}

fn decode_audit_result_class(byte: u8) -> Result<AuditResultClass, PersistenceError> {
    match byte {
        0x01 => Ok(AuditResultClass::Success),
        0x02 => Ok(AuditResultClass::Denied),
        0x03 => Ok(AuditResultClass::FailedClosed),
        0x04 => Ok(AuditResultClass::Degraded),
        _ => Err(PersistenceError::DecodeFailure),
    }
}

fn decode_authorization_mode(byte: u8) -> Result<AuthorizationMode, PersistenceError> {
    match byte {
        0x00 => Ok(AuthorizationMode::None),
        0x01 => Ok(AuthorizationMode::DeveloperMode),
        0x02 => Ok(AuthorizationMode::BootstrapProof),
        0x03 => Ok(AuthorizationMode::AdministratorProof),
        0x04 => Ok(AuthorizationMode::RecoveryProof),
        0x05 => Ok(AuthorizationMode::KeyManagerProof),
        _ => Err(PersistenceError::DecodeFailure),
    }
}

fn decode_credential_kind(byte: u8) -> Result<CredentialKind, PersistenceError> {
    match byte {
        0x01 => Ok(CredentialKind::Marker),
        _ => Err(PersistenceError::DecodeFailure),
    }
}

fn decode_transition_type(byte: u8) -> Result<TransitionType, PersistenceError> {
    match byte {
        0x01 => Ok(TransitionType::Provisioning),
        0x02 => Ok(TransitionType::Activation),
        0x03 => Ok(TransitionType::Lock),
        0x04 => Ok(TransitionType::Unlock),
        0x05 => Ok(TransitionType::EnterRecovery),
        0x06 => Ok(TransitionType::RecoverToProvisioned),
        0x07 => Ok(TransitionType::ReactivateRecoveredProvisioning),
        0x08 => Ok(TransitionType::Zeroize),
        0x09 => Ok(TransitionType::DeveloperReset),
        _ => Err(PersistenceError::DecodeFailure),
    }
}

fn decode_protected_action_class(byte: u8) -> Result<ProtectedActionClass, PersistenceError> {
    match byte {
        0x00 => Ok(ProtectedActionClass::None),
        0x01 => Ok(ProtectedActionClass::DestructiveAdmin),
        0x02 => Ok(ProtectedActionClass::DestructiveKey),
        0x03 => Ok(ProtectedActionClass::RecoveryTransition),
        _ => Err(PersistenceError::DecodeFailure),
    }
}

fn decode_approval_target_binding(byte: u8) -> Result<ApprovalTargetBinding, PersistenceError> {
    match byte {
        0x01 => Ok(ApprovalTargetBinding::Device),
        0x02 => Ok(ApprovalTargetBinding::KeyId),
        0x03 => Ok(ApprovalTargetBinding::TransitionId),
        _ => Err(PersistenceError::DecodeFailure),
    }
}

fn decode_approval_ticket_state(byte: u8) -> Result<ApprovalTicketState, PersistenceError> {
    match byte {
        0x01 => Ok(ApprovalTicketState::Pending),
        0x02 => Ok(ApprovalTicketState::Confirmed),
        0x03 => Ok(ApprovalTicketState::Consumed),
        0x04 => Ok(ApprovalTicketState::Invalidated),
        _ => Err(PersistenceError::DecodeFailure),
    }
}

fn decode_key_lifecycle_state(byte: u8) -> Result<KeyLifecycleState, PersistenceError> {
    match byte {
        0x01 => Ok(KeyLifecycleState::Pending),
        0x02 => Ok(KeyLifecycleState::Active),
        0x03 => Ok(KeyLifecycleState::Revoked),
        0x04 => Ok(KeyLifecycleState::PendingDestroy),
        0x05 => Ok(KeyLifecycleState::Destroyed),
        _ => Err(PersistenceError::DecodeFailure),
    }
}

fn decode_key_algorithm(byte: u8) -> Result<KeyAlgorithm, PersistenceError> {
    KeyAlgorithm::from_byte(byte).ok_or(PersistenceError::DecodeFailure)
}

fn decode_key_origin(byte: u8) -> Result<KeyOrigin, PersistenceError> {
    KeyOrigin::from_byte(byte).ok_or(PersistenceError::DecodeFailure)
}

fn decode_export_policy(byte: u8) -> Result<ExportPolicy, PersistenceError> {
    ExportPolicy::from_byte(byte).ok_or(PersistenceError::DecodeFailure)
}

fn decode_material_encoding(byte: u8) -> Result<MaterialEncoding, PersistenceError> {
    match byte {
        0x01 => Ok(MaterialEncoding::Internal),
        0x02 => Ok(MaterialEncoding::WrappedImport),
        0x03 => Ok(MaterialEncoding::Destroyed),
        _ => Err(PersistenceError::DecodeFailure),
    }
}

fn checksum(bytes: &[u8]) -> u32 {
    let mut value = 0x9e37_79b9u32;
    for &byte in bytes {
        value = value.rotate_left(5) ^ u32::from(byte);
    }
    value ^ (u32::try_from(bytes.len()).unwrap_or(0)).rotate_left(13)
}

fn slot_runtime_address(index: usize) -> usize {
    (&raw const __persistent_store_start as usize) + (index * SLOT_SIZE)
}

fn slot_offset(index: usize) -> u32 {
    u32::try_from(slot_runtime_address(index).saturating_sub(FLASH_XIP_BASE)).unwrap_or(0)
}

fn slot_bytes(index: usize) -> &'static [u8] {
    unsafe { slice::from_raw_parts(slot_runtime_address(index) as *const u8, SLOT_SIZE) }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    index: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, index: 0 }
    }

    fn is_at_end(&self) -> bool {
        self.index == self.bytes.len()
    }

    fn read_u8(&mut self) -> Result<u8, PersistenceError> {
        let value = *self.bytes.get(self.index).ok_or(PersistenceError::DecodeFailure)?;
        self.index += 1;
        Ok(value)
    }

    fn read_u32(&mut self) -> Result<u32, PersistenceError> {
        let end = self.index.saturating_add(4);
        let bytes = self
            .bytes
            .get(self.index..end)
            .ok_or(PersistenceError::DecodeFailure)?;
        self.index = end;
        Ok(u32::from_le_bytes(bytes.try_into().map_err(|_| PersistenceError::DecodeFailure)?))
    }

    fn read_vec<const N: usize>(&mut self) -> Result<Vec<u8, N>, PersistenceError> {
        let len = usize::from(self.read_u8()?);
        let end = self.index.saturating_add(len);
        let bytes = self
            .bytes
            .get(self.index..end)
            .ok_or(PersistenceError::DecodeFailure)?;
        self.index = end;
        let mut out = Vec::new();
        out.extend_from_slice(bytes)
            .map_err(|()| PersistenceError::DecodeFailure)?;
        Ok(out)
    }
}
