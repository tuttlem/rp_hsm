use crate::cli::args::{AuthOptions, CommandSpec, ParsedArgs};
use crate::cli::device::{DiscoveredDevice, discover_devices, resolve_device_selector};
use crate::cli::output::{CliError, CommandOutput, audit_page_lines, lines_output};
use crate::client::{
    AlgorithmProfileRecord, FirmwareVersionInput, KeyListRecord, KeyMetadataRecord,
    SerialBackend, SessionContext, StatusReport,
};
use std::io::Read;

/// # Errors
///
/// Returns `CliError` when device selection, authentication input, transport
/// exchange, or command capability checks fail.
#[allow(clippy::too_many_lines)]
pub fn execute(parsed: ParsedArgs) -> Result<CommandOutput, CliError> {
    match parsed.command {
        CommandSpec::Find => {
            let devices = discover_devices(parsed.global.baud)?;
            if devices.is_empty() {
                return Err(CliError::not_found("no compatible RP HSM devices found"));
            }
            Ok(lines_output(
                &devices.iter().map(format_device_line).collect::<Vec<_>>(),
            ))
        }
        CommandSpec::Status => {
            let devices = discover_devices(parsed.global.baud)?;
            let selected = resolve_device_selector(parsed.global.device.as_deref(), &devices)?;
            let report = SerialBackend::new(crate::client::ClientConfig::new(selected, parsed.global.baud))
                .status_report()?;
            Ok(lines_output(&format_status(&report)))
        }
        CommandSpec::ListAlgorithms => {
            let devices = discover_devices(parsed.global.baud)?;
            let selected = resolve_device_selector(parsed.global.device.as_deref(), &devices)?;
            let algorithms = SerialBackend::new(crate::client::ClientConfig::new(selected, parsed.global.baud))
                .list_algorithms()?;
            Ok(lines_output(
                &algorithms
                    .iter()
                    .map(format_algorithm_profile)
                    .collect::<Vec<_>>(),
            ))
        }
        CommandSpec::UpdateStatus { auth } => {
            let proof = load_proof(&auth)?;
            let devices = discover_devices(parsed.global.baud)?;
            let selected = resolve_device_selector(parsed.global.device.as_deref(), &devices)?;
            let payload = SerialBackend::new(crate::client::ClientConfig::new(selected.clone(), parsed.global.baud))
                .get_firmware_update_status(auth.role, &proof)?;
            Ok(lines_output(&format_update_status(&selected, payload)))
        }
        CommandSpec::ApplyUpdate { image_path, version, auth } => {
            let proof = load_proof(&auth)?;
            let image = std::fs::read(&image_path)
                .map_err(|err| CliError::invalid_response(format!("failed to read image: {err}")))?;
            let version = FirmwareVersionInput::parse(&version)?;
            let devices = discover_devices(parsed.global.baud)?;
            let selected = resolve_device_selector(parsed.global.device.as_deref(), &devices)?;
            let (begin, activation) = SerialBackend::new(crate::client::ClientConfig::new(selected.clone(), parsed.global.baud))
                .apply_firmware_update(&proof, version, &image)?;
            Ok(lines_output(&[
                format!("device={selected}"),
                format!("target_slot={}", boot_slot_name(begin.target_slot)),
                format!("update_session_id={}", begin.update_session_id),
                format!("expected_size={}", begin.expected_size),
                format!("policy_revision={}", begin.policy_revision),
                format!("next_boot_slot={}", boot_slot_name(activation.next_boot_slot)),
                format!("reboot_required={}", yes_no(activation.reboot_required)),
            ]))
        }
        CommandSpec::AbortUpdate { session_id, auth } => {
            let proof = load_proof(&auth)?;
            let devices = discover_devices(parsed.global.baud)?;
            let selected = resolve_device_selector(parsed.global.device.as_deref(), &devices)?;
            let result = SerialBackend::new(crate::client::ClientConfig::new(selected.clone(), parsed.global.baud))
                .abort_firmware_update(&proof, session_id)?;
            Ok(lines_output(&[
                format!("device={selected}"),
                format!("transfer_state_cleared={}", yes_no(result[0] != 0)),
                format!("staged_slot_invalidated={}", yes_no(result[1] != 0)),
            ]))
        }
        CommandSpec::RecoverTrustedFirmware { auth } => {
            let proof = load_proof(&auth)?;
            let devices = discover_devices(parsed.global.baud)?;
            let selected = resolve_device_selector(parsed.global.device.as_deref(), &devices)?;
            let result = SerialBackend::new(crate::client::ClientConfig::new(selected.clone(), parsed.global.baud))
                .recover_trusted_firmware(&proof)?;
            Ok(lines_output(&[
                format!("device={selected}"),
                format!("restored_slot={}", boot_slot_name(result[0])),
                format!(
                    "restored_version={}.{}.{}.{}",
                    u16::from_le_bytes([result[1], result[2]]),
                    u16::from_le_bytes([result[3], result[4]]),
                    u16::from_le_bytes([result[5], result[6]]),
                    u16::from_le_bytes([result[7], result[8]])
                ),
                format!("recovery_required={}", yes_no(result[9] != 0)),
            ]))
        }
        CommandSpec::DeveloperReset => {
            let devices = discover_devices(parsed.global.baud)?;
            let selected = resolve_device_selector(parsed.global.device.as_deref(), &devices)?;
            let result = SerialBackend::new(crate::client::ClientConfig::new(selected.clone(), parsed.global.baud))
                .developer_reset()?;
            Ok(lines_output(&[
                format!("device={selected}"),
                format!("result_state={}", device_state_name(result[0])),
                format!("owner_binding_cleared={}", yes_no(result[1] != 0)),
                format!("pending_transition_cleared={}", yes_no(result[2] != 0)),
                format!("transient_buffers_cleared={}", yes_no(result[3] != 0)),
            ]))
        }
        CommandSpec::DeveloperReboot => {
            let devices = discover_devices(parsed.global.baud)?;
            let selected = resolve_device_selector(parsed.global.device.as_deref(), &devices)?;
            SerialBackend::new(crate::client::ClientConfig::new(selected.clone(), parsed.global.baud))
                .developer_reboot()?;
            Ok(lines_output(&[
                format!("device={selected}"),
                "reboot_requested=yes".to_string(),
            ]))
        }
        CommandSpec::DeveloperStoreFault { action } => {
            let devices = discover_devices(parsed.global.baud)?;
            let selected = resolve_device_selector(parsed.global.device.as_deref(), &devices)?;
            SerialBackend::new(crate::client::ClientConfig::new(selected.clone(), parsed.global.baud))
                .developer_store_fault(action)?;
            Ok(lines_output(&[
                format!("device={selected}"),
                format!("action={}", developer_fault_name(action)),
            ]))
        }
        CommandSpec::DeveloperUpdateFault { action } => {
            let devices = discover_devices(parsed.global.baud)?;
            let selected = resolve_device_selector(parsed.global.device.as_deref(), &devices)?;
            SerialBackend::new(crate::client::ClientConfig::new(selected.clone(), parsed.global.baud))
                .developer_update_fault(action)?;
            Ok(lines_output(&[
                format!("device={selected}"),
                format!("action={}", developer_fault_name(action)),
            ]))
        }
        CommandSpec::DeveloperSetPolicy { update } => {
            let devices = discover_devices(parsed.global.baud)?;
            let selected = resolve_device_selector(parsed.global.device.as_deref(), &devices)?;
            let result = SerialBackend::new(crate::client::ClientConfig::new(selected.clone(), parsed.global.baud))
                .developer_set_policy(update)?;
            Ok(lines_output(&[
                format!("device={selected}"),
                format!("policy_profile_version={}", result[0]),
                format!(
                    "policy_revision={}",
                    u32::from_le_bytes([result[1], result[2], result[3], result[4]])
                ),
                format!("dual_control_enabled={}", yes_no(result[5] != 0)),
                format!(
                    "protected_action_mask=0x{:04x}",
                    u16::from_le_bytes([result[6], result[7]])
                ),
                format!("developer_commands_visible={}", yes_no(result[8] != 0)),
            ]))
        }
        CommandSpec::Provision { proof_env, label } => {
            let proof = load_named_proof(&proof_env)?;
            let devices = discover_devices(parsed.global.baud)?;
            let selected = resolve_device_selector(parsed.global.device.as_deref(), &devices)?;
            let result = SerialBackend::new(crate::client::ClientConfig::new(selected.clone(), parsed.global.baud))
                .provision(&proof, label.as_bytes())?;
            Ok(lines_output(&[
                format!("device={selected}"),
                format!("result_state={}", device_state_name(result.result_state)),
                format!("transition_id={}", result.transition_id),
                format!("revision_counter={}", result.revision_counter),
            ]))
        }
        CommandSpec::ProvisionBootstrap { proof_env, label } => {
            let proof = load_named_proof(&proof_env)?;
            let devices = discover_devices(parsed.global.baud)?;
            let selected = resolve_device_selector(parsed.global.device.as_deref(), &devices)?;
            let result = SerialBackend::new(crate::client::ClientConfig::new(selected.clone(), parsed.global.baud))
                .provision_bootstrap(&proof, label.as_bytes())?;
            Ok(lines_output(&[
                format!("device={selected}"),
                format!("result_state={}", device_state_name(result[0])),
                format!(
                    "transition_id={}",
                    u32::from_le_bytes([result[1], result[2], result[3], result[4]])
                ),
                format!(
                    "revision_counter={}",
                    u32::from_le_bytes([result[5], result[6], result[7], result[8]])
                ),
            ]))
        }
        CommandSpec::AuthCheck { auth } => {
            let proof = load_proof(&auth)?;
            let devices = discover_devices(parsed.global.baud)?;
            let selected = resolve_device_selector(parsed.global.device.as_deref(), &devices)?;
            let session = SerialBackend::new(crate::client::ClientConfig::new(selected.clone(), parsed.global.baud))
                .auth_check(auth.role, &proof)?;
            Ok(lines_output(&format_auth_check(&selected, &session)))
        }
        CommandSpec::Lock { auth } => {
            let proof = load_proof(&auth)?;
            let devices = discover_devices(parsed.global.baud)?;
            let selected = resolve_device_selector(parsed.global.device.as_deref(), &devices)?;
            let result = SerialBackend::new(crate::client::ClientConfig::new(selected.clone(), parsed.global.baud))
                .lock_device(&proof)?;
            Ok(lines_output(&[
                format!("device={selected}"),
                format!("result_state={}", device_state_name(result[0])),
                format!("reason_code={}", result[1]),
            ]))
        }
        CommandSpec::Unlock { auth } => {
            let proof = load_proof(&auth)?;
            let devices = discover_devices(parsed.global.baud)?;
            let selected = resolve_device_selector(parsed.global.device.as_deref(), &devices)?;
            let result = SerialBackend::new(crate::client::ClientConfig::new(selected.clone(), parsed.global.baud))
                .unlock_device(&proof)?;
            Ok(lines_output(&[
                format!("device={selected}"),
                format!("result_state={}", device_state_name(result[0])),
                format!("revision_counter={}", u32::from_le_bytes([result[1], result[2], result[3], result[4]])),
            ]))
        }
        CommandSpec::Zeroize { auth } => {
            let proof = load_proof(&auth)?;
            let devices = discover_devices(parsed.global.baud)?;
            let selected = resolve_device_selector(parsed.global.device.as_deref(), &devices)?;
            let result = SerialBackend::new(crate::client::ClientConfig::new(selected.clone(), parsed.global.baud))
                .execute_zeroize(&proof)?;
            Ok(lines_output(&[
                format!("device={selected}"),
                format!("result_state={}", device_state_name(result[0])),
                format!("owner_binding_cleared={}", yes_no(result[1] != 0)),
                format!("secret_storage_cleared={}", yes_no(result[2] != 0)),
                format!("transient_buffers_cleared={}", yes_no(result[3] != 0)),
                format!("requires_reprovisioning={}", yes_no(result[4] != 0)),
            ]))
        }
        CommandSpec::Logout { auth } => {
            let proof = load_proof(&auth)?;
            let devices = discover_devices(parsed.global.baud)?;
            let selected = resolve_device_selector(parsed.global.device.as_deref(), &devices)?;
            SerialBackend::new(crate::client::ClientConfig::new(selected.clone(), parsed.global.baud))
                .logout(auth.role, &proof)?;
            Ok(lines_output(&[
                format!("device={selected}"),
                "session_invalidated=yes".to_string(),
            ]))
        }
        CommandSpec::EnterRecovery { auth } => {
            let proof = load_proof(&auth)?;
            let devices = discover_devices(parsed.global.baud)?;
            let selected = resolve_device_selector(parsed.global.device.as_deref(), &devices)?;
            let result = SerialBackend::new(crate::client::ClientConfig::new(selected.clone(), parsed.global.baud))
                .enter_recovery(&proof)?;
            Ok(lines_output(&[
                format!("device={selected}"),
                format!("result_state={}", device_state_name(result[0])),
                format!("recovery_required={}", yes_no(result[1] != 0)),
            ]))
        }
        CommandSpec::RecoverToProvisioned { auth } => {
            let proof = load_proof(&auth)?;
            let devices = discover_devices(parsed.global.baud)?;
            let selected = resolve_device_selector(parsed.global.device.as_deref(), &devices)?;
            let result = SerialBackend::new(crate::client::ClientConfig::new(selected.clone(), parsed.global.baud))
                .recover_to_provisioned(&proof)?;
            Ok(lines_output(&[
                format!("device={selected}"),
                format!("result_state={}", device_state_name(result[0])),
                format!("transition_id={}", u32::from_le_bytes([result[1], result[2], result[3], result[4]])),
                format!("revision_counter={}", u32::from_le_bytes([result[5], result[6], result[7], result[8]])),
            ]))
        }
        CommandSpec::ReactivateRecovered { transition_id, auth } => {
            let proof = load_proof(&auth)?;
            let devices = discover_devices(parsed.global.baud)?;
            let selected = resolve_device_selector(parsed.global.device.as_deref(), &devices)?;
            let result = SerialBackend::new(crate::client::ClientConfig::new(selected.clone(), parsed.global.baud))
                .reactivate_recovered(&proof, transition_id)?;
            Ok(lines_output(&[
                format!("device={selected}"),
                format!("result_state={}", device_state_name(result[0])),
                format!("revision_counter={}", u32::from_le_bytes([result[1], result[2], result[3], result[4]])),
            ]))
        }
        CommandSpec::GetRandom { bytes, auth } => {
            let proof = load_proof(&auth)?;
            let devices = discover_devices(parsed.global.baud)?;
            let selected = resolve_device_selector(parsed.global.device.as_deref(), &devices)?;
            let bytes = SerialBackend::new(crate::client::ClientConfig::new(selected, parsed.global.baud))
                .get_random(auth.role, &proof, bytes)?;
            Ok(CommandOutput::Bytes(bytes))
        }
        CommandSpec::GenerateKey { algorithm, usage, auth } => {
            let proof = load_proof(&auth)?;
            let usage_mask = parse_usage_mask(&usage)?;
            let devices = discover_devices(parsed.global.baud)?;
            let selected = resolve_device_selector(parsed.global.device.as_deref(), &devices)?;
            let result = SerialBackend::new(crate::client::ClientConfig::new(selected.clone(), parsed.global.baud))
                .generate_key(&proof, algorithm, usage_mask)?;
            Ok(lines_output(&[
                format!("device={selected}"),
                format!("key_id={}", result.key_id),
                format!("algorithm={}", algorithm_name(algorithm as u8)),
                format!("usage_mask=0x{usage_mask:02x}"),
                format!("lifecycle={}", key_lifecycle_name(result.lifecycle_state)),
                format!("record_revision={}", result.record_revision),
                format!("store_revision={}", result.store_revision),
            ]))
        }
        CommandSpec::SymEncrypt { key_id, algorithm, auth } => {
            let proof = load_proof(&auth)?;
            let plaintext = read_stdin_required()?;
            let devices = discover_devices(parsed.global.baud)?;
            let selected = resolve_device_selector(parsed.global.device.as_deref(), &devices)?;
            let result = SerialBackend::new(crate::client::ClientConfig::new(selected, parsed.global.baud))
                .sym_encrypt(&proof, key_id, algorithm, &plaintext)?;
            Ok(CommandOutput::Bytes(encode_symmetric_blob(&result.nonce, &result.ciphertext)?))
        }
        CommandSpec::SymDecrypt { key_id, algorithm, auth } => {
            let proof = load_proof(&auth)?;
            let blob = read_stdin_required()?;
            let (nonce, ciphertext) = decode_symmetric_blob(&blob)?;
            let devices = discover_devices(parsed.global.baud)?;
            let selected = resolve_device_selector(parsed.global.device.as_deref(), &devices)?;
            let plaintext = SerialBackend::new(crate::client::ClientConfig::new(selected, parsed.global.baud))
                .sym_decrypt(&proof, key_id, algorithm, &nonce, &ciphertext)?;
            Ok(CommandOutput::Bytes(plaintext))
        }
        CommandSpec::GetAuditPage {
            start_sequence,
            max_events,
            one_line,
            auth,
        } => {
            let proof = load_proof(&auth)?;
            let devices = discover_devices(parsed.global.baud)?;
            let selected = resolve_device_selector(parsed.global.device.as_deref(), &devices)?;
            let page = SerialBackend::new(crate::client::ClientConfig::new(selected.clone(), parsed.global.baud))
                .get_audit_page(auth.role, &proof, start_sequence, max_events)?;
            Ok(lines_output(&audit_page_lines(&selected, &page, one_line)))
        }
        CommandSpec::Sign { key_id, auth } => {
            let proof = load_proof(&auth)?;
            let message = read_stdin_required()?;
            let devices = discover_devices(parsed.global.baud)?;
            let selected = resolve_device_selector(parsed.global.device.as_deref(), &devices)?;
            let signature = SerialBackend::new(crate::client::ClientConfig::new(selected, parsed.global.baud))
                .sign_detached(key_id, &proof, &message)?;
            Ok(CommandOutput::Bytes(signature))
        }
        CommandSpec::Verify { algorithm, public_key_hex, signature_hex } => {
            let message = read_stdin_required()?;
            let public_key = parse_hex_bytes(&public_key_hex)?;
            let signature = parse_hex_bytes(&signature_hex)?;
            let devices = discover_devices(parsed.global.baud)?;
            let selected = resolve_device_selector(parsed.global.device.as_deref(), &devices)?;
            let verified = SerialBackend::new(crate::client::ClientConfig::new(selected, parsed.global.baud))
                .verify_detached(algorithm, &message, &public_key, &signature)?;
            Ok(lines_output(&[verified.to_string()]))
        }
        CommandSpec::ImportWrappedKey { auth } => {
            let proof = load_proof(&auth)?;
            let envelope = read_stdin_required()?;
            let devices = discover_devices(parsed.global.baud)?;
            let selected = resolve_device_selector(parsed.global.device.as_deref(), &devices)?;
            let result = SerialBackend::new(crate::client::ClientConfig::new(selected.clone(), parsed.global.baud))
                .import_wrapped_key(&proof, &envelope)?;
            Ok(lines_output(&[format_key_record_result(&selected, result)]))
        }
        CommandSpec::ListKeys { auth } => {
            let proof = load_proof(&auth)?;
            let devices = discover_devices(parsed.global.baud)?;
            let selected = resolve_device_selector(parsed.global.device.as_deref(), &devices)?;
            let keys = SerialBackend::new(crate::client::ClientConfig::new(selected, parsed.global.baud))
                .list_keys(&proof)?;
            Ok(lines_output(
                &keys.iter().map(format_key_line).collect::<Vec<_>>(),
            ))
        }
        CommandSpec::GetKeyMetadata { key_id, auth } => {
            let proof = load_proof(&auth)?;
            let devices = discover_devices(parsed.global.baud)?;
            let selected = resolve_device_selector(parsed.global.device.as_deref(), &devices)?;
            let metadata = SerialBackend::new(crate::client::ClientConfig::new(selected, parsed.global.baud))
                .get_key_metadata(key_id, &proof)?;
            Ok(lines_output(&[format_metadata_line(&metadata)]))
        }
        CommandSpec::RevokeKey { key_id, auth } => {
            let proof = load_proof(&auth)?;
            let devices = discover_devices(parsed.global.baud)?;
            let selected = resolve_device_selector(parsed.global.device.as_deref(), &devices)?;
            let result = SerialBackend::new(crate::client::ClientConfig::new(selected.clone(), parsed.global.baud))
                .revoke_key(key_id, &proof)?;
            Ok(lines_output(&[format_key_record_result(&selected, result)]))
        }
        CommandSpec::DestroyKey { key_id, auth } => {
            let proof = load_proof(&auth)?;
            let devices = discover_devices(parsed.global.baud)?;
            let selected = resolve_device_selector(parsed.global.device.as_deref(), &devices)?;
            let result = SerialBackend::new(crate::client::ClientConfig::new(selected.clone(), parsed.global.baud))
                .destroy_key(key_id, &proof)?;
            Ok(lines_output(&[
                format!("device={selected}"),
                format!("key_id={}", result[0]),
                format!("lifecycle={}", key_lifecycle_name(result[1])),
                format!("owner_binding_cleared={}", yes_no(result[2] != 0)),
                format!("material_cleared={}", yes_no(result[3] != 0)),
            ]))
        }
        CommandSpec::Unsupported { verb } => Err(CliError::unsupported(format!(
            "{verb} is reserved for a later firmware capability and is not available yet"
        ))),
    }
}

fn load_proof(auth: &AuthOptions) -> Result<Vec<u8>, CliError> {
    load_named_proof(&auth.proof_env)
}

fn load_named_proof(var_name: &str) -> Result<Vec<u8>, CliError> {
    let value = std::env::var(var_name).map_err(|_| {
        CliError::auth(format!(
            "environment variable '{var_name}' is required for authentication proof input"
        ))
    })?;
    if value.is_empty() {
        return Err(CliError::auth("authentication proof must not be empty"));
    }
    Ok(value.into_bytes())
}

fn format_auth_check(device: &str, session: &SessionContext) -> Vec<String> {
    vec![
        format!("device={device}"),
        format!("role={}", role_name(session.role.to_wire())),
        format!(
            "session_id={}",
            u32::from_le_bytes(session.session_id)
        ),
        format!("next_counter={}", session.next_counter),
    ]
}

fn format_device_line(device: &DiscoveredDevice) -> String {
    format!(
        "{}\tprotocol={}\tdevice_state={}\tsession_state={}\tdeveloper_mode={}",
        device.device_path,
        device.protocol_version,
        device.device_state,
        device.session_state,
        yes_no(device.developer_mode_present)
    )
}

fn format_status(report: &StatusReport) -> Vec<String> {
    let mut lines = vec![
        format!("device={}", report.device_path),
        format!("protocol_version={}", report.protocol_version),
        format!("device_state={}", device_state_name(report.device_state)),
        format!("session_state={}", session_state_name(report.session_state)),
        format!("lifecycle_state={}", device_state_name(report.lifecycle_status[0])),
        format!("owner_present={}", yes_no(report.lifecycle_status[1] != 0)),
        format!("recovery_required={}", yes_no(report.lifecycle_status[2] != 0)),
        format!(
            "pending_transition_present={}",
            yes_no(report.lifecycle_status[3] != 0)
        ),
        format!("key_store_state={}", key_store_state_name(report.key_store_status[0])),
        format!("key_count={}", report.key_store_status[1]),
        format!("free_slots={}", report.key_store_status[2]),
        format!("rollback_detected={}", yes_no(report.key_store_status[3] != 0)),
        format!("corruption_detected={}", yes_no(report.key_store_status[4] != 0)),
        format!("session_present={}", yes_no(report.session_status[0] != 0)),
        format!("active_role={}", role_name(report.session_status[1])),
        format!(
            "expires_in_ticks={}",
            u16::from_le_bytes([report.session_status[2], report.session_status[3]])
        ),
        format!("lockout_active={}", yes_no(report.session_status[4] != 0)),
        format!("lockout_role={}", role_name(report.session_status[5])),
    ];
    if let Some(capabilities) = report.crypto_capabilities {
        lines.push(format!("crypto_service_version={}", capabilities[0]));
        lines.push(format!("crypto_operation_flags=0x{:02x}", capabilities[1]));
        lines.push(format!("crypto_sign_flags=0x{:02x}", capabilities[2]));
        lines.push(format!("crypto_verify_flags=0x{:02x}", capabilities[3]));
        lines.push(format!(
            "crypto_max_message_len={}",
            u16::from_le_bytes([capabilities[4], capabilities[5]])
        ));
        lines.push(format!(
            "crypto_max_signature_len={}",
            u16::from_le_bytes([capabilities[6], capabilities[7]])
        ));
        lines.push(format!("crypto_max_random_len={}", capabilities[8]));
        lines.push(format!("wrapped_import_enabled={}", yes_no(capabilities[9] != 0)));
    }
    if let Some(update) = report.firmware_update_status {
        lines.push(format!("firmware_active_slot={}", boot_slot_name(update[0])));
        lines.push(format!(
            "firmware_active_version={}.{}.{}.{}",
            u16::from_le_bytes([update[1], update[2]]),
            u16::from_le_bytes([update[3], update[4]]),
            u16::from_le_bytes([update[5], update[6]]),
            u16::from_le_bytes([update[7], update[8]])
        ));
        lines.push(format!(
            "firmware_minimum_version={}.{}.{}.{}",
            u16::from_le_bytes([update[9], update[10]]),
            u16::from_le_bytes([update[11], update[12]]),
            u16::from_le_bytes([update[13], update[14]]),
            u16::from_le_bytes([update[15], update[16]])
        ));
        lines.push(format!("firmware_transfer_phase={}", update_transfer_phase_name(update[17])));
        lines.push(format!("firmware_staged_slot_state={}", boot_slot_state_name(update[18])));
        lines.push(format!("firmware_recovery_required={}", yes_no(update[19] != 0)));
        lines.push(format!("firmware_last_update_result={}", update_result_name(update[20])));
        lines.push(format!(
            "firmware_policy_revision={}",
            u32::from_le_bytes([update[21], update[22], update[23], update[24]])
        ));
    }
    if let Some(policy) = report.policy_profile {
        lines.push(format!("policy_profile_version={}", policy[0]));
        lines.push(format!(
            "policy_revision={}",
            u32::from_le_bytes([policy[1], policy[2], policy[3], policy[4]])
        ));
        lines.push(format!("dual_control_enabled={}", yes_no(policy[5] != 0)));
        lines.push(format!(
            "protected_action_mask=0x{:04x}",
            u16::from_le_bytes([policy[6], policy[7]])
        ));
        lines.push(format!("developer_commands_visible={}", yes_no(policy[8] != 0)));
    }
    if let Some(health) = report.health_status {
        lines.push(format!("health_device_state={}", device_state_name(health[0])));
        lines.push(format!("health_key_store_state={}", key_store_state_name(health[1])));
        lines.push(format!("health_session_state={}", session_state_name(health[2])));
        lines.push(format!(
            "health_policy_revision={}",
            u32::from_le_bytes([health[3], health[4], health[5], health[6]])
        ));
        lines.push(format!("audit_store_state={}", audit_store_state_name(health[7])));
        lines.push(format!(
            "audit_events_retained={}",
            u16::from_le_bytes([health[8], health[9]])
        ));
        lines.push(format!("audit_overflow_detected={}", yes_no(health[10] != 0)));
        lines.push(format!("health_rollback_detected={}", yes_no(health[11] != 0)));
        lines.push(format!("health_corruption_detected={}", yes_no(health[12] != 0)));
    }
    lines
}

fn format_key_line(record: &KeyListRecord) -> String {
    format!(
        "key_id={}\talgorithm={}\tlifecycle={}\tusage_mask=0x{:02x}\texport_policy={}",
        record.key_id,
        algorithm_name(record.algorithm),
        key_lifecycle_name(record.lifecycle_state),
        record.usage_mask,
        export_policy_name(record.export_policy)
    )
}

fn format_algorithm_profile(profile: &AlgorithmProfileRecord) -> String {
    let algorithm = format!("algorithm={}", algorithm_name(profile.algorithm));
    let operations = format!(
        "operations={}",
        algorithm_operation_names(profile.operation_mask)
    );
    format!(
        "{algorithm:<32} {operations:<55} public_material_len={}",
        profile.public_material_len
    )
}

fn format_metadata_line(metadata: &KeyMetadataRecord) -> String {
    let public_material = if metadata.public_material.is_empty() {
        "none".to_string()
    } else {
        format_hex_bytes(&metadata.public_material)
    };
    format!(
        "key_id={}\talgorithm={}\torigin={}\tusage_mask=0x{:02x}\texport_policy={}\tlifecycle={}\trecord_revision={}\tpublic_material={}",
        metadata.key_id,
        algorithm_name(metadata.algorithm),
        origin_name(metadata.origin),
        metadata.usage_mask,
        export_policy_name(metadata.export_policy),
        key_lifecycle_name(metadata.lifecycle_state),
        metadata.record_revision,
        public_material
    )
}

fn format_key_record_result(device: &str, result: [u8; 10]) -> String {
    let revision = u32::from_le_bytes([result[6], result[7], result[8], result[9]]);
    format!(
        "device={device}\tkey_id={}\talgorithm={}\torigin={}\tlifecycle={}\trecord_revision={}",
        result[0],
        algorithm_name(result[1]),
        origin_name(result[2]),
        key_lifecycle_name(result[3]),
        revision
    )
}

fn developer_fault_name(action: crate::client::DeveloperFaultAction) -> &'static str {
    match action {
        crate::client::DeveloperFaultAction::CorruptPersistedStore => "corrupt-persisted-store",
        crate::client::DeveloperFaultAction::RollbackPersistedStore => "rollback-persisted-store",
        crate::client::DeveloperFaultAction::CorruptPersistedAudit => "corrupt-persisted-audit",
        crate::client::DeveloperFaultAction::RollbackPersistedAudit => "rollback-persisted-audit",
        crate::client::DeveloperFaultAction::AmbiguousFirmwareActivation => "ambiguous-firmware-activation",
        crate::client::DeveloperFaultAction::RollbackFirmwareVersion => "rollback-firmware-version",
    }
}

fn format_update_status(device: &str, payload: [u8; 25]) -> Vec<String> {
    vec![
        format!("device={device}"),
        format!("active_slot={}", boot_slot_name(payload[0])),
        format!(
            "active_version={}.{}.{}.{}",
            u16::from_le_bytes([payload[1], payload[2]]),
            u16::from_le_bytes([payload[3], payload[4]]),
            u16::from_le_bytes([payload[5], payload[6]]),
            u16::from_le_bytes([payload[7], payload[8]])
        ),
        format!(
            "minimum_accepted_version={}.{}.{}.{}",
            u16::from_le_bytes([payload[9], payload[10]]),
            u16::from_le_bytes([payload[11], payload[12]]),
            u16::from_le_bytes([payload[13], payload[14]]),
            u16::from_le_bytes([payload[15], payload[16]])
        ),
        format!("transfer_phase={}", update_transfer_phase_name(payload[17])),
        format!("staged_slot_state={}", boot_slot_state_name(payload[18])),
        format!("recovery_required={}", yes_no(payload[19] != 0)),
        format!("last_update_result={}", update_result_name(payload[20])),
        format!(
            "policy_revision={}",
            u32::from_le_bytes([payload[21], payload[22], payload[23], payload[24]])
        ),
    ]
}

fn read_stdin_required() -> Result<Vec<u8>, CliError> {
    let mut buffer = Vec::new();
    std::io::stdin()
        .read_to_end(&mut buffer)
        .map_err(|err| CliError::failure(format!("failed to read stdin: {err}")))?;
    if buffer.is_empty() {
        return Err(CliError::usage("stdin input is required for this command"));
    }
    Ok(buffer)
}

fn parse_hex_bytes(value: &str) -> Result<Vec<u8>, CliError> {
    let compact: String = value.chars().filter(|ch| !ch.is_ascii_whitespace()).collect();
    if compact.is_empty() || !compact.len().is_multiple_of(2) {
        return Err(CliError::usage("hex input must contain an even number of digits"));
    }
    let mut bytes = Vec::with_capacity(compact.len() / 2);
    let mut idx = 0usize;
    while idx < compact.len() {
        let end = idx + 2;
        let byte = u8::from_str_radix(&compact[idx..end], 16)
            .map_err(|_| CliError::usage("invalid hex input"))?;
        bytes.push(byte);
        idx = end;
    }
    Ok(bytes)
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn device_state_name(value: u8) -> &'static str {
    match value {
        0x01 => "factory",
        0x02 => "provisioned",
        0x03 => "operational",
        0x04 => "locked",
        0x05 => "recovery",
        0x06 => "zeroized",
        _ => "unknown",
    }
}

fn session_state_name(value: u8) -> &'static str {
    match value {
        0x01 => "public",
        0x02 => "bootstrap",
        0x03 => "administrator",
        0x04 => "recovery",
        0x05 => "developer",
        0x06 => "key-manager",
        _ => "unknown",
    }
}

fn role_name(value: u8) -> &'static str {
    match value {
        0x00 => "public",
        0x02 => "bootstrap",
        0x03 => "administrator",
        0x04 => "recovery",
        0x05 => "developer",
        0x06 => "key-manager",
        _ => "unknown",
    }
}

fn boot_slot_name(value: u8) -> &'static str {
    match value {
        0x01 => "a",
        0x02 => "b",
        _ => "unknown",
    }
}

fn boot_slot_state_name(value: u8) -> &'static str {
    match value {
        0x01 => "empty",
        0x02 => "active-trusted",
        0x03 => "staged-transfer",
        0x04 => "staged-validated",
        0x05 => "invalid",
        _ => "unknown",
    }
}

fn update_transfer_phase_name(value: u8) -> &'static str {
    match value {
        0x00 => "empty",
        0x01 => "manifest-accepted",
        0x02 => "transferring",
        0x03 => "transferred",
        0x04 => "validating",
        0x05 => "activation-pending",
        0x06 => "aborted",
        _ => "unknown",
    }
}

fn update_result_name(value: u8) -> &'static str {
    match value {
        0x00 => "none",
        0x01 => "begun",
        0x02 => "aborted",
        0x03 => "finalized",
        0x04 => "activated",
        0x05 => "rollback-denied",
        0x06 => "signature-rejected",
        0x07 => "digest-mismatch",
        0x08 => "interrupted",
        0x09 => "recovered",
        _ => "unknown",
    }
}

fn key_store_state_name(value: u8) -> &'static str {
    match value {
        0x01 => "ready",
        0x02 => "active",
        0x03 => "full",
        0x04 => "rollback-required",
        0x05 => "degraded",
        _ => "unknown",
    }
}

fn audit_store_state_name(value: u8) -> &'static str {
    match value {
        0x01 => "empty",
        0x02 => "ready",
        0x03 => "full",
        0x04 => "degraded",
        0x05 => "locked",
        _ => "unknown",
    }
}

fn algorithm_name(value: u8) -> &'static str {
    match value {
        0x01 => "ed25519",
        0x02 => "p256",
        0x03 => "chacha20poly1305",
        0x04 => "aes256gcm",
        _ => "unknown",
    }
}

fn algorithm_operation_names(mask: u8) -> String {
    let mut names = Vec::new();
    if mask & 0x01 != 0 {
        names.push("generate");
    }
    if mask & 0x02 != 0 {
        names.push("sign");
    }
    if mask & 0x04 != 0 {
        names.push("verify");
    }
    if mask & 0x08 != 0 {
        names.push("encrypt");
    }
    if mask & 0x10 != 0 {
        names.push("decrypt");
    }
    if mask & 0x20 != 0 {
        names.push("wrapped-import");
    }
    if names.is_empty() {
        "none".to_string()
    } else {
        names.join(",")
    }
}

fn parse_usage_mask(value: &str) -> Result<u8, CliError> {
    let mut mask = 0u8;
    for part in value.split(',') {
        match part.trim() {
            "sign" => mask |= 0x01,
            "verify" => mask |= 0x02,
            "encrypt" => mask |= 0x04,
            "decrypt" => mask |= 0x08,
            "wrapped-import" | "wrap-import" => mask |= 0x20,
            "" => return Err(CliError::usage("usage entries must not be empty")),
            _ => return Err(CliError::usage("invalid usage value")),
        }
    }
    if mask == 0 {
        return Err(CliError::usage("usage mask must not be empty"));
    }
    Ok(mask)
}

fn encode_symmetric_blob(nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, CliError> {
    let mut blob = Vec::with_capacity(1 + nonce.len() + ciphertext.len());
    blob.push(u8::try_from(nonce.len()).map_err(|_| CliError::usage("nonce too large"))?);
    blob.extend_from_slice(nonce);
    blob.extend_from_slice(ciphertext);
    Ok(blob)
}

fn decode_symmetric_blob(blob: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CliError> {
    let Some(&nonce_len) = blob.first() else {
        return Err(CliError::usage("ciphertext blob is truncated"));
    };
    let nonce_len = usize::from(nonce_len);
    if blob.len() <= 1 + nonce_len {
        return Err(CliError::usage("ciphertext blob is truncated"));
    }
    Ok((blob[1..=nonce_len].to_vec(), blob[1 + nonce_len..].to_vec()))
}

fn format_hex_bytes(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn origin_name(value: u8) -> &'static str {
    match value {
        0x01 => "generated",
        0x02 => "imported",
        _ => "unknown",
    }
}

fn export_policy_name(value: u8) -> &'static str {
    match value {
        0x01 => "non-exportable",
        0x02 => "wrapped-only",
        _ => "unknown",
    }
}

fn key_lifecycle_name(value: u8) -> &'static str {
    match value {
        0x01 => "pending",
        0x02 => "active",
        0x03 => "revoked",
        0x04 => "pending-destroy",
        0x05 => "destroyed",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::{execute, format_algorithm_profile, format_status};
    use crate::cli::args::{AuthOptions, CommandSpec, GlobalOptions, ParsedArgs};
    use crate::client::{AlgorithmProfileRecord, Role, StatusReport};

    #[test]
    fn formats_status_report_with_capabilities() {
        let lines = format_status(&StatusReport {
            device_path: "/dev/ttyACM0".into(),
            protocol_version: 1,
            device_state: 1,
            session_state: 5,
            lifecycle_status: [1, 0, 0, 0],
            key_store_status: [1, 0, 8, 0, 0],
            session_status: [0, 5, 0, 0, 0, 1],
            crypto_capabilities: Some([1, 0x0f, 1, 3, 0x80, 0x00, 0x40, 0x00, 0x40, 1]),
            firmware_update_status: None,
            policy_profile: Some([1, 0x02, 0x00, 0x00, 0x00, 1, 0x07, 0x00, 1]),
            health_status: Some([1, 1, 5, 0x02, 0x00, 0x00, 0x00, 2, 0x04, 0x00, 0, 0, 0]),
        });
        assert!(lines.iter().any(|line| line == "device=/dev/ttyACM0"));
        assert!(lines.iter().any(|line| line == "wrapped_import_enabled=yes"));
        assert!(lines.iter().any(|line| line == "dual_control_enabled=yes"));
    }

    #[test]
    fn unsupported_verbs_fail_explicitly() {
        let err = execute(ParsedArgs {
            global: GlobalOptions {
                device: None,
                baud: 115_200,
            },
            command: CommandSpec::Unsupported {
                verb: "sym-encrypt".into(),
            },
        })
        .expect_err("must fail");
        assert!(err.message.contains("reserved for a later firmware capability"));
    }

    #[test]
    fn missing_auth_env_is_rejected_before_transport() {
        let err = execute(ParsedArgs {
            global: GlobalOptions {
                device: Some("/dev/ttyACM0".into()),
                baud: 115_200,
            },
            command: CommandSpec::ListKeys {
                auth: AuthOptions {
                    role: Role::KeyManager,
                    proof_env: "RPHSM_MISSING".into(),
                },
            },
        })
        .expect_err("must fail");
        assert!(err.message.contains("environment variable"));
    }

    #[test]
    fn formats_algorithm_profiles_in_aligned_columns() {
        let line = format_algorithm_profile(&AlgorithmProfileRecord {
            algorithm: 0x03,
            operation_mask: 0x39,
            public_material_len: 0,
        });
        assert_eq!(
            line,
            "algorithm=chacha20poly1305       operations=generate,encrypt,decrypt,wrapped-import      public_material_len=0"
        );
    }
}
