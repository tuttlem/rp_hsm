use host_tools::{CommandSpec, parse_args, usage_text};

fn parse(parts: &[&str]) -> CommandSpec {
    parse_args(parts.iter().map(|value| value.to_string()))
        .expect("parse")
        .command
}

#[test]
fn reserved_future_verbs_remain_explicitly_unavailable() {
    assert!(matches!(
        parse(&["rphsmtool", "sym-encrypt"]),
        CommandSpec::Unsupported { .. }
    ));
}

#[test]
fn default_help_keeps_probe_out_of_operator_surface() {
    let text = usage_text();
    assert!(text.contains("cargo probe is an engineering validation tool"));
    assert!(!text.contains("probe_protocol"));
}
