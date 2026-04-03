#[test]
fn cargo_aliases_document_supported_entrypoints() {
    let config = include_str!("../../.cargo/config.toml");
    assert!(config.contains("rphsmtool = "));
    assert!(config.contains("probe = "));
    assert!(config.contains("firmware-run-developer = "));
}
