use host_tools::{CommandSpec, parse_args, usage_text};

fn parse(parts: &[&str]) -> CommandSpec {
    parse_args(parts.iter().map(|value| value.to_string()))
        .expect("parse")
        .command
}

#[test]
fn implemented_crypto_verbs_are_part_of_the_supported_surface() {
    assert!(matches!(
        parse(&[
            "rphsmtool",
            "sym-encrypt",
            "--key-id",
            "1",
            "--algorithm",
            "aes256gcm",
            "--role",
            "key-manager",
            "--proof-env",
            "RPHSM_KEYMG",
        ]),
        CommandSpec::SymEncrypt { .. }
    ));
}

#[test]
fn default_help_keeps_probe_out_of_operator_surface() {
    let text = usage_text();
    assert!(text.contains("cargo probe is an engineering validation tool"));
    assert!(!text.contains("probe_protocol"));
}
