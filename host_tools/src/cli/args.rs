use super::output::CliError;
use crate::client::{DeveloperFaultAction, PolicyProfileUpdate, Role, VerifyAlgorithm};

pub const DEFAULT_BAUD: u32 = 115_200;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlobalOptions {
    pub device: Option<String>,
    pub baud: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthOptions {
    pub role: Role,
    pub proof_env: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommandSpec {
    Find,
    Status,
    DeveloperReset,
    DeveloperReboot,
    DeveloperStoreFault { action: DeveloperFaultAction },
    DeveloperSetPolicy { update: PolicyProfileUpdate },
    Provision { proof_env: String, label: String },
    ProvisionBootstrap { proof_env: String, label: String },
    AuthCheck { auth: AuthOptions },
    Lock { auth: AuthOptions },
    Unlock { auth: AuthOptions },
    Zeroize { auth: AuthOptions },
    Logout { auth: AuthOptions },
    EnterRecovery { auth: AuthOptions },
    RecoverToProvisioned { auth: AuthOptions },
    ReactivateRecovered { transition_id: u32, auth: AuthOptions },
    GetRandom { bytes: u8, auth: AuthOptions },
    GetAuditPage { start_sequence: u32, max_events: u8, auth: AuthOptions },
    Sign { key_id: u8, auth: AuthOptions },
    Verify {
        algorithm: VerifyAlgorithm,
        public_key_hex: String,
        signature_hex: String,
    },
    ImportWrappedKey { auth: AuthOptions },
    ListKeys { auth: AuthOptions },
    GetKeyMetadata { key_id: u8, auth: AuthOptions },
    RevokeKey { key_id: u8, auth: AuthOptions },
    DestroyKey { key_id: u8, auth: AuthOptions },
    Unsupported { verb: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedArgs {
    pub global: GlobalOptions,
    pub command: CommandSpec,
}

struct CommandInvocation {
    command_name: String,
    rest: Vec<String>,
    show_all_help: bool,
}

/// # Errors
///
/// Returns `CliError` when the provided arguments are incomplete, malformed, or
/// request an unsupported command shape.
#[allow(clippy::too_many_lines)]
pub fn parse_args<I>(args: I) -> Result<ParsedArgs, CliError>
where
    I: IntoIterator<Item = String>,
{
    let CommandInvocation {
        command_name,
        rest,
        show_all_help,
    } = parse_command_invocation(args)?;

    let mut device = None;
    let mut baud = DEFAULT_BAUD;
    let mut role = None;
    let mut proof_env = None;
    let mut bytes = None;
    let mut key_id = None;
    let mut label = None;
    let mut algorithm = None;
    let mut public_key_hex = None;
    let mut signature_hex = None;
    let mut transition_id = None;
    let mut action = None;
    let mut dual_control = None;
    let mut start_sequence = None;
    let mut max_events = None;

    let mut idx = 0usize;
    while idx < rest.len() {
        match rest[idx].as_str() {
            "--device" => {
                idx += 1;
                let Some(value) = rest.get(idx) else {
                    return Err(CliError::usage("missing value for --device"));
                };
                device = Some(value.clone());
            }
            "--baud" => {
                idx += 1;
                let Some(value) = rest.get(idx) else {
                    return Err(CliError::usage("missing value for --baud"));
                };
                baud = value
                    .parse::<u32>()
                    .map_err(|_| CliError::usage("invalid value for --baud"))?;
            }
            "--role" => {
                idx += 1;
                let Some(value) = rest.get(idx) else {
                    return Err(CliError::usage("missing value for --role"));
                };
                role = Some(Role::parse(value)?);
            }
            "--proof-env" => {
                idx += 1;
                let Some(value) = rest.get(idx) else {
                    return Err(CliError::usage("missing value for --proof-env"));
                };
                proof_env = Some(value.clone());
            }
            "--bytes" => {
                idx += 1;
                let Some(value) = rest.get(idx) else {
                    return Err(CliError::usage("missing value for --bytes"));
                };
                bytes = Some(
                    value
                        .parse::<u8>()
                        .map_err(|_| CliError::usage("invalid value for --bytes"))?,
                );
            }
            "--key-id" => {
                idx += 1;
                let Some(value) = rest.get(idx) else {
                    return Err(CliError::usage("missing value for --key-id"));
                };
                key_id = Some(parse_u8(value)?);
            }
            "--label" => {
                idx += 1;
                let Some(value) = rest.get(idx) else {
                    return Err(CliError::usage("missing value for --label"));
                };
                label = Some(value.clone());
            }
            "--algorithm" => {
                idx += 1;
                let Some(value) = rest.get(idx) else {
                    return Err(CliError::usage("missing value for --algorithm"));
                };
                algorithm = Some(VerifyAlgorithm::parse(value)?);
            }
            "--public-key-hex" => {
                idx += 1;
                let Some(value) = rest.get(idx) else {
                    return Err(CliError::usage("missing value for --public-key-hex"));
                };
                public_key_hex = Some(value.clone());
            }
            "--signature-hex" => {
                idx += 1;
                let Some(value) = rest.get(idx) else {
                    return Err(CliError::usage("missing value for --signature-hex"));
                };
                signature_hex = Some(value.clone());
            }
            "--transition-id" => {
                idx += 1;
                let Some(value) = rest.get(idx) else {
                    return Err(CliError::usage("missing value for --transition-id"));
                };
                transition_id = Some(parse_u32(value)?);
            }
            "--action" => {
                idx += 1;
                let Some(value) = rest.get(idx) else {
                    return Err(CliError::usage("missing value for --action"));
                };
                action = Some(DeveloperFaultAction::parse(value)?);
            }
            "--dual-control" => {
                idx += 1;
                let Some(value) = rest.get(idx) else {
                    return Err(CliError::usage("missing value for --dual-control"));
                };
                dual_control = Some(parse_toggle(value)?);
            }
            "--start-sequence" => {
                idx += 1;
                let Some(value) = rest.get(idx) else {
                    return Err(CliError::usage("missing value for --start-sequence"));
                };
                start_sequence = Some(parse_u32(value)?);
            }
            "--max-events" => {
                idx += 1;
                let Some(value) = rest.get(idx) else {
                    return Err(CliError::usage("missing value for --max-events"));
                };
                max_events = Some(parse_u8(value)?);
            }
            "--help" | "-h" => {
                return Err(CliError::usage(command_usage(&command_name, show_all_help)));
            }
            other => return Err(CliError::usage(format!("unknown argument: {other}"))),
        }
        idx += 1;
    }

    let global = GlobalOptions { device, baud };
    let command = build_command(
        command_name,
        role,
        proof_env,
        bytes,
        key_id,
        label,
        algorithm,
        public_key_hex,
        signature_hex,
        transition_id,
        action,
        dual_control,
        start_sequence,
        max_events,
    )?;

    Ok(ParsedArgs { global, command })
}

fn parse_command_invocation<I>(args: I) -> Result<CommandInvocation, CliError>
where
    I: IntoIterator<Item = String>,
{
    let mut it = args.into_iter();
    let _program = it.next();

    let Some(first) = it.next() else {
        return Err(CliError::usage(usage_text()));
    };

    let mut rest: Vec<String> = it.collect();
    let show_all_help = rest.iter().any(|arg| arg == "--all");
    rest.retain(|arg| arg != "--all");

    if matches!(first.as_str(), "--help" | "-h" | "help") {
        return Err(CliError::usage(if show_all_help {
            all_usage_text()
        } else {
            usage_text()
        }));
    }

    let command_name = match first.as_str() {
        "dev" => qualify_subcommand("dev", &mut rest)?,
        "recovery" => qualify_subcommand("recovery", &mut rest)?,
        "key" => qualify_subcommand("key", &mut rest)?,
        _ => first,
    };

    Ok(CommandInvocation {
        command_name,
        rest,
        show_all_help,
    })
}

fn qualify_subcommand(prefix: &str, rest: &mut Vec<String>) -> Result<String, CliError> {
    let Some(subcommand) = rest.first().cloned() else {
        return Err(CliError::usage(format!("missing subcommand for {prefix}")));
    };
    rest.remove(0);
    Ok(format!("{prefix}-{subcommand}"))
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn build_command(
    command_name: String,
    role: Option<Role>,
    proof_env: Option<String>,
    bytes: Option<u8>,
    key_id: Option<u8>,
    label: Option<String>,
    algorithm: Option<VerifyAlgorithm>,
    public_key_hex: Option<String>,
    signature_hex: Option<String>,
    transition_id: Option<u32>,
    action: Option<DeveloperFaultAction>,
    dual_control: Option<bool>,
    start_sequence: Option<u32>,
    max_events: Option<u8>,
) -> Result<CommandSpec, CliError> {
    match command_name.as_str() {
        "find" => Ok(CommandSpec::Find),
        "status" => Ok(CommandSpec::Status),
        "reset" | "developer-reset" | "dev-reset" => Ok(CommandSpec::DeveloperReset),
        "developer-set-policy" | "dev-set-policy" => Ok(CommandSpec::DeveloperSetPolicy {
            update: PolicyProfileUpdate {
                dual_control_enabled: dual_control.ok_or_else(|| {
                    CliError::usage("missing --dual-control for developer-set-policy")
                })?,
            },
        }),
        "provision" => Ok(CommandSpec::Provision {
            proof_env: proof_env
                .ok_or_else(|| CliError::usage("missing --proof-env for provision"))?,
            label: label.unwrap_or_else(|| "lab".to_string()),
        }),
        "developer-reboot" | "dev-reboot" => Ok(CommandSpec::DeveloperReboot),
        "developer-store-fault" | "dev-store-fault" => Ok(CommandSpec::DeveloperStoreFault {
            action: action.ok_or_else(|| CliError::usage("missing --action for developer-store-fault"))?,
        }),
        "provision-bootstrap" => Ok(CommandSpec::ProvisionBootstrap {
            proof_env: proof_env
                .ok_or_else(|| CliError::usage("missing --proof-env for provision-bootstrap"))?,
            label: label.unwrap_or_else(|| "lab".to_string()),
        }),
        "auth-check" => Ok(CommandSpec::AuthCheck {
            auth: parse_auth(
                role,
                proof_env,
                &[
                    Role::Bootstrap,
                    Role::Administrator,
                    Role::Recovery,
                    Role::KeyManager,
                ],
            )?,
        }),
        "lock" => Ok(CommandSpec::Lock {
            auth: parse_auth(role, proof_env, &[Role::Administrator])?,
        }),
        "unlock" => Ok(CommandSpec::Unlock {
            auth: parse_auth(role, proof_env, &[Role::Administrator])?,
        }),
        "zeroize" => Ok(CommandSpec::Zeroize {
            auth: parse_auth(role, proof_env, &[Role::Administrator])?,
        }),
        "logout" => Ok(CommandSpec::Logout {
            auth: parse_auth(
                role,
                proof_env,
                &[Role::Bootstrap, Role::Administrator, Role::Recovery, Role::KeyManager],
            )?,
        }),
        "enter-recovery" | "recovery-enter" => Ok(CommandSpec::EnterRecovery {
            auth: parse_auth(role, proof_env, &[Role::Recovery])?,
        }),
        "recover-to-provisioned" | "recovery-recover" => Ok(CommandSpec::RecoverToProvisioned {
            auth: parse_auth(role, proof_env, &[Role::Recovery])?,
        }),
        "reactivate-recovered" | "recovery-reactivate" => Ok(CommandSpec::ReactivateRecovered {
            transition_id: transition_id
                .ok_or_else(|| CliError::usage("missing --transition-id for reactivate-recovered"))?,
            auth: parse_auth(role, proof_env, &[Role::Recovery])?,
        }),
        "get-random" => Ok(CommandSpec::GetRandom {
            bytes: bytes.ok_or_else(|| CliError::usage("missing --bytes for get-random"))?,
            auth: parse_auth(role, proof_env, &[Role::Administrator, Role::KeyManager])?,
        }),
        "get-audit-page" | "audit-page" => Ok(CommandSpec::GetAuditPage {
            start_sequence: start_sequence.unwrap_or(0),
            max_events: max_events.ok_or_else(|| CliError::usage("missing --max-events for get-audit-page"))?,
            auth: parse_auth(role, proof_env, &[Role::Administrator, Role::Recovery])?,
        }),
        "sign" | "key-sign" => Ok(CommandSpec::Sign {
            key_id: key_id.ok_or_else(|| CliError::usage("missing --key-id for sign"))?,
            auth: parse_auth(role, proof_env, &[Role::KeyManager])?,
        }),
        "verify" => Ok(CommandSpec::Verify {
            algorithm: algorithm.ok_or_else(|| CliError::usage("missing --algorithm for verify"))?,
            public_key_hex: public_key_hex
                .ok_or_else(|| CliError::usage("missing --public-key-hex for verify"))?,
            signature_hex: signature_hex
                .ok_or_else(|| CliError::usage("missing --signature-hex for verify"))?,
        }),
        "import-wrapped-key" | "key-import-wrapped" => Ok(CommandSpec::ImportWrappedKey {
            auth: parse_auth(role, proof_env, &[Role::KeyManager])?,
        }),
        "list-keys" | "key-list" => Ok(CommandSpec::ListKeys {
            auth: parse_auth(role, proof_env, &[Role::KeyManager])?,
        }),
        "get-key-metadata" | "key-metadata" => Ok(CommandSpec::GetKeyMetadata {
            key_id: key_id.ok_or_else(|| CliError::usage("missing --key-id for get-key-metadata"))?,
            auth: parse_auth(role, proof_env, &[Role::KeyManager])?,
        }),
        "revoke-key" | "key-revoke" => Ok(CommandSpec::RevokeKey {
            key_id: key_id.ok_or_else(|| CliError::usage("missing --key-id for revoke-key"))?,
            auth: parse_auth(role, proof_env, &[Role::KeyManager])?,
        }),
        "destroy-key" | "key-destroy" => Ok(CommandSpec::DestroyKey {
            key_id: key_id.ok_or_else(|| CliError::usage("missing --key-id for destroy-key"))?,
            auth: parse_auth(role, proof_env, &[Role::KeyManager])?,
        }),
        "sym-encrypt" | "sym-decrypt" => {
            Ok(CommandSpec::Unsupported { verb: command_name })
        }
        other => Err(CliError::usage(format!("unknown command: {other}"))),
    }
}

fn parse_auth(
    role: Option<Role>,
    proof_env: Option<String>,
    allowed: &[Role],
) -> Result<AuthOptions, CliError> {
    let role = role.ok_or_else(|| CliError::usage("missing --role"))?;
    if !allowed.contains(&role) {
        return Err(CliError::usage("role is not allowed for this command"));
    }
    let proof_env = proof_env.ok_or_else(|| CliError::usage("missing --proof-env"))?;
    Ok(AuthOptions { role, proof_env })
}

fn parse_u8(value: &str) -> Result<u8, CliError> {
    if let Some(hex) = value.strip_prefix("0x") {
        u8::from_str_radix(hex, 16).map_err(|_| CliError::usage("invalid hex value"))
    } else {
        value
            .parse::<u8>()
            .map_err(|_| CliError::usage("invalid key id"))
    }
}

fn parse_u32(value: &str) -> Result<u32, CliError> {
    if let Some(hex) = value.strip_prefix("0x") {
        u32::from_str_radix(hex, 16).map_err(|_| CliError::usage("invalid hex value"))
    } else {
        value
            .parse::<u32>()
            .map_err(|_| CliError::usage("invalid transition id"))
    }
}

fn parse_toggle(value: &str) -> Result<bool, CliError> {
    match value {
        "on" | "enable" | "enabled" | "true" | "yes" | "1" => Ok(true),
        "off" | "disable" | "disabled" | "false" | "no" | "0" => Ok(false),
        _ => Err(CliError::usage("invalid value for --dual-control")),
    }
}

fn command_usage(command: &str, show_all_help: bool) -> String {
    match command {
        "find" => "Usage: rphsmtool find [--baud 115200]".into(),
        "status" => "Usage: rphsmtool status [--device PATH] [--baud 115200]".into(),
        "reset" => "Usage: rphsmtool reset [--device PATH] [--baud 115200]".into(),
        "provision" => "Usage: rphsmtool provision [--device PATH] --proof-env VAR [--label NAME] [--baud 115200]".into(),
        "developer-reset" => "Usage: rphsmtool developer-reset [--device PATH] [--baud 115200]".into(),
        "dev-reset" => "Usage: rphsmtool dev reset [--device PATH] [--baud 115200]".into(),
        "developer-reboot" => "Usage: rphsmtool developer-reboot [--device PATH] [--baud 115200]".into(),
        "dev-reboot" => "Usage: rphsmtool dev reboot [--device PATH] [--baud 115200]".into(),
        "developer-store-fault" => "Usage: rphsmtool developer-store-fault [--device PATH] --action corrupt-persisted-store|rollback-persisted-store|corrupt-persisted-audit|rollback-persisted-audit [--baud 115200]".into(),
        "dev-store-fault" => "Usage: rphsmtool dev store-fault [--device PATH] --action corrupt-persisted-store|rollback-persisted-store|corrupt-persisted-audit|rollback-persisted-audit [--baud 115200]".into(),
        "developer-set-policy" => "Usage: rphsmtool developer-set-policy [--device PATH] --dual-control on|off [--baud 115200]".into(),
        "dev-set-policy" => "Usage: rphsmtool dev set-policy [--device PATH] --dual-control on|off [--baud 115200]".into(),
        "provision-bootstrap" => "Usage: rphsmtool provision-bootstrap [--device PATH] --proof-env VAR [--label NAME] [--baud 115200]".into(),
        "auth-check" => "Usage: rphsmtool auth-check [--device PATH] --role bootstrap|administrator|recovery|key-manager --proof-env VAR [--baud 115200]".into(),
        "lock" => "Usage: rphsmtool lock [--device PATH] --role administrator --proof-env VAR [--baud 115200]".into(),
        "unlock" => "Usage: rphsmtool unlock [--device PATH] --role administrator --proof-env VAR [--baud 115200]".into(),
        "zeroize" => "Usage: rphsmtool zeroize [--device PATH] --role administrator --proof-env VAR [--baud 115200]".into(),
        "logout" => "Usage: rphsmtool logout [--device PATH] --role bootstrap|administrator|recovery|key-manager --proof-env VAR [--baud 115200]".into(),
        "enter-recovery" => "Usage: rphsmtool enter-recovery [--device PATH] --role recovery --proof-env VAR [--baud 115200]".into(),
        "recover-to-provisioned" => "Usage: rphsmtool recover-to-provisioned [--device PATH] --role recovery --proof-env VAR [--baud 115200]".into(),
        "reactivate-recovered" => "Usage: rphsmtool reactivate-recovered [--device PATH] --transition-id ID --role recovery --proof-env VAR [--baud 115200]".into(),
        "get-random" => "Usage: rphsmtool get-random [--device PATH] --bytes N --role administrator|key-manager --proof-env VAR [--baud 115200]".into(),
        "get-audit-page" => "Usage: rphsmtool get-audit-page [--device PATH] [--start-sequence N] --max-events N --role administrator|recovery --proof-env VAR [--baud 115200]".into(),
        "sign" => "Usage: rphsmtool sign [--device PATH] --key-id ID --role key-manager --proof-env VAR [--baud 115200] < message.bin".into(),
        "verify" => "Usage: rphsmtool verify [--device PATH] --algorithm ed25519|p256 --public-key-hex HEX --signature-hex HEX [--baud 115200] < message.bin".into(),
        "import-wrapped-key" => "Usage: rphsmtool import-wrapped-key [--device PATH] --role key-manager --proof-env VAR [--baud 115200] < envelope.bin".into(),
        "list-keys" => "Usage: rphsmtool list-keys [--device PATH] --role key-manager --proof-env VAR [--baud 115200]".into(),
        "get-key-metadata" => "Usage: rphsmtool get-key-metadata [--device PATH] --key-id ID --role key-manager --proof-env VAR [--baud 115200]".into(),
        "revoke-key" => "Usage: rphsmtool revoke-key [--device PATH] --key-id ID --role key-manager --proof-env VAR [--baud 115200]".into(),
        "destroy-key" => "Usage: rphsmtool destroy-key [--device PATH] --key-id ID --role key-manager --proof-env VAR [--baud 115200]".into(),
        "sym-encrypt" => "Usage: rphsmtool sym-encrypt [reserved for a later firmware feature]".into(),
        "sym-decrypt" => "Usage: rphsmtool sym-decrypt [reserved for a later firmware feature]".into(),
        _ => {
            if show_all_help {
                all_usage_text()
            } else {
                usage_text()
            }
        }
    }
}

#[must_use]
pub fn usage_text() -> String {
    [
        "Usage:",
        "  rphsmtool find [--baud 115200]",
        "  rphsmtool status [--device PATH] [--baud 115200]",
        "",
        "User Commands:",
        "  rphsmtool get-random [--device PATH] --bytes N --role administrator|key-manager --proof-env VAR [--baud 115200]",
        "  rphsmtool sign [--device PATH] --key-id ID --role key-manager --proof-env VAR [--baud 115200] < message.bin",
        "  rphsmtool verify [--device PATH] --algorithm ed25519|p256 --public-key-hex HEX --signature-hex HEX [--baud 115200] < message.bin",
        "  rphsmtool list-keys [--device PATH] --role key-manager --proof-env VAR [--baud 115200]",
        "  rphsmtool get-key-metadata [--device PATH] --key-id ID --role key-manager --proof-env VAR [--baud 115200]",
        "",
        "Admin Commands:",
        "  rphsmtool provision [--device PATH] --proof-env VAR [--label NAME] [--baud 115200]",
        "  rphsmtool reset [--device PATH] [--baud 115200]",
        "  rphsmtool lock [--device PATH] --role administrator --proof-env VAR [--baud 115200]",
        "  rphsmtool unlock [--device PATH] --role administrator --proof-env VAR [--baud 115200]",
        "  rphsmtool zeroize [--device PATH] --role administrator --proof-env VAR [--baud 115200]",
        "  rphsmtool logout [--device PATH] --role bootstrap|administrator|recovery|key-manager --proof-env VAR [--baud 115200]",
        "",
        "Advanced Commands:",
        "  rphsmtool get-audit-page [--device PATH] [--start-sequence N] --max-events N --role administrator|recovery --proof-env VAR [--baud 115200]",
        "  rphsmtool recovery enter [--device PATH] --role recovery --proof-env VAR [--baud 115200]",
        "  rphsmtool recovery recover [--device PATH] --role recovery --proof-env VAR [--baud 115200]",
        "  rphsmtool recovery reactivate [--device PATH] --transition-id ID --role recovery --proof-env VAR [--baud 115200]",
        "  rphsmtool key import-wrapped [--device PATH] --role key-manager --proof-env VAR [--baud 115200] < envelope.bin",
        "  rphsmtool key revoke [--device PATH] --key-id ID --role key-manager --proof-env VAR [--baud 115200]",
        "  rphsmtool key destroy [--device PATH] --key-id ID --role key-manager --proof-env VAR [--baud 115200]",
        "",
        "Developer Commands:",
        "  rphsmtool dev reset [--device PATH] [--baud 115200]",
        "  rphsmtool dev reboot [--device PATH] [--baud 115200]",
        "  rphsmtool dev store-fault [--device PATH] --action corrupt-persisted-store|rollback-persisted-store|corrupt-persisted-audit|rollback-persisted-audit [--baud 115200]",
        "  rphsmtool dev set-policy [--device PATH] --dual-control on|off [--baud 115200]",
        "",
        "Policy Notes:",
        "  bounded denials are reported as command-unavailable, state-denied, role/session-denied,",
        "  key-policy-denied, approval-required, approval-stale, or internal-policy-ambiguity",
        "",
        "More:",
        "  rphsmtool help --all",
    ]
    .join("\n")
}

#[must_use]
pub fn all_usage_text() -> String {
    [
        "Usage:",
        "  rphsmtool find [--baud 115200]",
        "  rphsmtool status [--device PATH] [--baud 115200]",
        "  rphsmtool reset [--device PATH] [--baud 115200]",
        "  rphsmtool developer-reset [--device PATH] [--baud 115200]",
        "  rphsmtool dev reset [--device PATH] [--baud 115200]",
        "  rphsmtool developer-reboot [--device PATH] [--baud 115200]",
        "  rphsmtool dev reboot [--device PATH] [--baud 115200]",
        "  rphsmtool developer-store-fault [--device PATH] --action corrupt-persisted-store|rollback-persisted-store|corrupt-persisted-audit|rollback-persisted-audit [--baud 115200]",
        "  rphsmtool dev store-fault [--device PATH] --action corrupt-persisted-store|rollback-persisted-store|corrupt-persisted-audit|rollback-persisted-audit [--baud 115200]",
        "  rphsmtool developer-set-policy [--device PATH] --dual-control on|off [--baud 115200]",
        "  rphsmtool dev set-policy [--device PATH] --dual-control on|off [--baud 115200]",
        "  rphsmtool provision [--device PATH] --proof-env VAR [--label NAME] [--baud 115200]",
        "  rphsmtool provision-bootstrap [--device PATH] --proof-env VAR [--label NAME] [--baud 115200]",
        "  rphsmtool auth-check [--device PATH] --role bootstrap|administrator|recovery|key-manager --proof-env VAR [--baud 115200]",
        "  rphsmtool lock [--device PATH] --role administrator --proof-env VAR [--baud 115200]",
        "  rphsmtool unlock [--device PATH] --role administrator --proof-env VAR [--baud 115200]",
        "  rphsmtool zeroize [--device PATH] --role administrator --proof-env VAR [--baud 115200]",
        "  rphsmtool logout [--device PATH] --role bootstrap|administrator|recovery|key-manager --proof-env VAR [--baud 115200]",
        "  rphsmtool enter-recovery [--device PATH] --role recovery --proof-env VAR [--baud 115200]",
        "  rphsmtool recovery enter [--device PATH] --role recovery --proof-env VAR [--baud 115200]",
        "  rphsmtool recover-to-provisioned [--device PATH] --role recovery --proof-env VAR [--baud 115200]",
        "  rphsmtool recovery recover [--device PATH] --role recovery --proof-env VAR [--baud 115200]",
        "  rphsmtool reactivate-recovered [--device PATH] --transition-id ID --role recovery --proof-env VAR [--baud 115200]",
        "  rphsmtool recovery reactivate [--device PATH] --transition-id ID --role recovery --proof-env VAR [--baud 115200]",
        "  rphsmtool get-random [--device PATH] --bytes N --role administrator|key-manager --proof-env VAR [--baud 115200]",
        "  rphsmtool get-audit-page [--device PATH] [--start-sequence N] --max-events N --role administrator|recovery --proof-env VAR [--baud 115200]",
        "  rphsmtool sign [--device PATH] --key-id ID --role key-manager --proof-env VAR [--baud 115200] < message.bin",
        "  rphsmtool key sign [--device PATH] --key-id ID --role key-manager --proof-env VAR [--baud 115200] < message.bin",
        "  rphsmtool verify [--device PATH] --algorithm ed25519|p256 --public-key-hex HEX --signature-hex HEX [--baud 115200] < message.bin",
        "  rphsmtool import-wrapped-key [--device PATH] --role key-manager --proof-env VAR [--baud 115200] < envelope.bin",
        "  rphsmtool key import-wrapped [--device PATH] --role key-manager --proof-env VAR [--baud 115200] < envelope.bin",
        "  rphsmtool list-keys [--device PATH] --role key-manager --proof-env VAR [--baud 115200]",
        "  rphsmtool key list [--device PATH] --role key-manager --proof-env VAR [--baud 115200]",
        "  rphsmtool get-key-metadata [--device PATH] --key-id ID --role key-manager --proof-env VAR [--baud 115200]",
        "  rphsmtool key metadata [--device PATH] --key-id ID --role key-manager --proof-env VAR [--baud 115200]",
        "  rphsmtool revoke-key [--device PATH] --key-id ID --role key-manager --proof-env VAR [--baud 115200]",
        "  rphsmtool key revoke [--device PATH] --key-id ID --role key-manager --proof-env VAR [--baud 115200]",
        "  rphsmtool destroy-key [--device PATH] --key-id ID --role key-manager --proof-env VAR [--baud 115200]",
        "  rphsmtool key destroy [--device PATH] --key-id ID --role key-manager --proof-env VAR [--baud 115200]",
        "  rphsmtool sym-encrypt",
        "  rphsmtool sym-decrypt",
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::{CommandSpec, ParsedArgs, parse_args};
    use crate::client::{PolicyProfileUpdate, Role};

    fn parse(parts: &[&str]) -> Result<ParsedArgs, super::CliError> {
        parse_args(parts.iter().map(|s| s.to_string()))
    }

    #[test]
    fn parses_find_with_default_baud() {
        let parsed = parse(&["rphsmtool", "find"]).expect("parse");
        assert!(matches!(parsed.command, CommandSpec::Find));
        assert_eq!(parsed.global.device, None);
        assert_eq!(parsed.global.baud, super::DEFAULT_BAUD);
    }

    #[test]
    fn parses_get_random_with_auth_options() {
        let parsed = parse(&[
            "rphsmtool",
            "get-random",
            "--device",
            "/dev/ttyACM0",
            "--bytes",
            "32",
            "--role",
            "administrator",
            "--proof-env",
            "RPHSM_PROOF",
        ])
        .expect("parse");
        match parsed.command {
            CommandSpec::GetRandom { bytes, auth } => {
                assert_eq!(bytes, 32);
                assert_eq!(auth.role, Role::Administrator);
                assert_eq!(auth.proof_env, "RPHSM_PROOF");
            }
            _ => panic!("wrong command"),
        }
    }

    #[test]
    fn parses_provision_bootstrap_with_defaults() {
        let parsed = parse(&[
            "rphsmtool",
            "provision-bootstrap",
            "--proof-env",
            "RPHSM_BOOT",
        ])
        .expect("parse");
        match parsed.command {
            CommandSpec::ProvisionBootstrap { proof_env, label } => {
                assert_eq!(proof_env, "RPHSM_BOOT");
                assert_eq!(label, "lab");
            }
            _ => panic!("wrong command"),
        }
    }

    #[test]
    fn parses_high_level_provision_with_defaults() {
        let parsed = parse(&["rphsmtool", "provision", "--proof-env", "RPHSM_BOOT"])
            .expect("parse");
        match parsed.command {
            CommandSpec::Provision { proof_env, label } => {
                assert_eq!(proof_env, "RPHSM_BOOT");
                assert_eq!(label, "lab");
            }
            _ => panic!("wrong command"),
        }
    }

    #[test]
    fn parses_developer_reset() {
        let parsed = parse(&["rphsmtool", "developer-reset"]).expect("parse");
        assert!(matches!(parsed.command, CommandSpec::DeveloperReset));
    }

    #[test]
    fn parses_grouped_developer_set_policy_alias() {
        let parsed = parse(&[
            "rphsmtool",
            "dev",
            "set-policy",
            "--dual-control",
            "on",
        ])
        .expect("parse");
        assert!(matches!(
            parsed.command,
            CommandSpec::DeveloperSetPolicy {
                update: PolicyProfileUpdate {
                    dual_control_enabled: true
                }
            }
        ));
    }

    #[test]
    fn parses_grouped_recovery_alias() {
        let parsed = parse(&[
            "rphsmtool",
            "recovery",
            "reactivate",
            "--transition-id",
            "7",
            "--role",
            "recovery",
            "--proof-env",
            "RPHSM_PROOF",
        ])
        .expect("parse");
        assert!(matches!(parsed.command, CommandSpec::ReactivateRecovered { .. }));
    }

    #[test]
    fn rejects_missing_auth_inputs() {
        let err = parse(&["rphsmtool", "get-random", "--bytes", "4"]).expect_err("must fail");
        assert!(err.message.contains("missing --role"));
    }

    #[test]
    fn marks_reserved_verbs_as_unsupported() {
        let parsed = parse(&["rphsmtool", "sym-encrypt"]).expect("parse");
        assert!(matches!(parsed.command, CommandSpec::Unsupported { .. }));
    }
}
