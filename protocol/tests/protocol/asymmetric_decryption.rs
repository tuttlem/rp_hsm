use rp_hsm::protocol::{KeyAlgorithm, StatusCode, USAGE_DECRYPT, USAGE_ENCRYPT};

use super::crypto_fixtures::{
    begin_auth, complete_auth, generate_key_request, sym_decrypt_request,
    sym_encrypt_request, unauthenticated_operational_engine,
};

#[test]
fn generated_x25519_key_round_trip_succeeds() {
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
    let envelope_header = &encrypted.payload.as_slice()[1..=envelope_header_len];
    let ciphertext_len_index = 1 + envelope_header_len;
    let ciphertext_len = usize::from(u16::from_le_bytes([
        encrypted.payload[ciphertext_len_index],
        encrypted.payload[ciphertext_len_index + 1],
    ]));
    let ciphertext =
        &encrypted.payload.as_slice()[ciphertext_len_index + 2..ciphertext_len_index + 2 + ciphertext_len];

    let decrypted = engine.handle_bytes(&sym_decrypt_request(
        session,
        4,
        key_id,
        KeyAlgorithm::X25519ChaCha20Poly1305,
        envelope_header,
        ciphertext,
    ));
    assert_eq!(decrypted.code, StatusCode::Success.as_u8());
    let plaintext_len = usize::from(u16::from_le_bytes([decrypted.payload[0], decrypted.payload[1]]));
    assert_eq!(&decrypted.payload.as_slice()[2..2 + plaintext_len], b"hello");
}

#[test]
fn tampered_x25519_envelope_is_denied() {
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
    let envelope_header = &encrypted.payload.as_slice()[1..=envelope_header_len];
    let ciphertext_len_index = 1 + envelope_header_len;
    let ciphertext_len = usize::from(u16::from_le_bytes([
        encrypted.payload[ciphertext_len_index],
        encrypted.payload[ciphertext_len_index + 1],
    ]));
    let mut ciphertext =
        encrypted.payload.as_slice()[ciphertext_len_index + 2..ciphertext_len_index + 2 + ciphertext_len]
            .to_vec();
    ciphertext[0] ^= 0x01;

    let denied = engine.handle_bytes(&sym_decrypt_request(
        session,
        4,
        key_id,
        KeyAlgorithm::X25519ChaCha20Poly1305,
        envelope_header,
        &ciphertext,
    ));
    assert_eq!(denied.code, StatusCode::ValidationError.as_u8());
}
