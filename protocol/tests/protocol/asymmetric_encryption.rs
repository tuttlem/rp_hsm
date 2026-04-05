use rp_hsm::protocol::{KeyAlgorithm, StatusCode, USAGE_DECRYPT, USAGE_ENCRYPT};

use super::crypto_fixtures::{
    begin_auth, complete_auth, generate_key_request, sym_encrypt_request,
    unauthenticated_operational_engine,
};

#[test]
fn generated_x25519_key_encrypts_with_bounded_envelope() {
    let mut engine = unauthenticated_operational_engine();
    let challenge = begin_auth(&mut engine, 0x06);
    let session = complete_auth(&mut engine, challenge, 1, b"KEYMG");

    let generated = engine.handle_bytes(&generate_key_request(
        session,
        2,
        KeyAlgorithm::X25519ChaCha20Poly1305,
        USAGE_ENCRYPT | USAGE_DECRYPT,
    ));
    assert_eq!(generated.code, StatusCode::Success.as_u8());
    let key_id = generated.payload[0];

    let encrypted = engine.handle_bytes(&sym_encrypt_request(
        session,
        3,
        key_id,
        KeyAlgorithm::X25519ChaCha20Poly1305,
        b"hello",
    ));
    assert_eq!(encrypted.code, StatusCode::Success.as_u8());
    let envelope_header_len = usize::from(encrypted.payload[0]);
    assert_eq!(envelope_header_len, 44);
    let ciphertext_len_index = 1 + envelope_header_len;
    let ciphertext_len = usize::from(u16::from_le_bytes([
        encrypted.payload[ciphertext_len_index],
        encrypted.payload[ciphertext_len_index + 1],
    ]));
    assert!(ciphertext_len >= 16);
}
