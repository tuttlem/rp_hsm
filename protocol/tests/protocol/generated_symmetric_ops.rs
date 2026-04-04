use rp_hsm::protocol::{KeyAlgorithm, StatusCode};

use super::crypto_fixtures::{
    GENERATED_SYM_USAGE, begin_auth, complete_auth, generate_key_request, sym_decrypt_request,
    sym_encrypt_request, unauthenticated_operational_engine,
};

#[test]
fn generated_symmetric_key_round_trip_succeeds() {
    let mut engine = unauthenticated_operational_engine();
    let challenge = begin_auth(&mut engine, 0x06);
    let session = complete_auth(&mut engine, challenge, 1, b"KEYMG");

    let generated = engine.handle_bytes(&generate_key_request(
        session,
        2,
        KeyAlgorithm::ChaCha20Poly1305,
        GENERATED_SYM_USAGE,
    ));
    assert_eq!(generated.code, StatusCode::Success.as_u8());
    let key_id = generated.payload[0];

    let encrypted = engine.handle_bytes(&sym_encrypt_request(
        session,
        3,
        key_id,
        KeyAlgorithm::ChaCha20Poly1305,
        b"hello",
    ));
    assert_eq!(encrypted.code, StatusCode::Success.as_u8());
    let nonce_len = usize::from(encrypted.payload[0]);
    let nonce = &encrypted.payload.as_slice()[1..=nonce_len];
    let ciphertext_len_index = 1 + nonce_len;
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
        KeyAlgorithm::ChaCha20Poly1305,
        nonce,
        ciphertext,
    ));
    assert_eq!(decrypted.code, StatusCode::Success.as_u8());
    let plaintext_len = usize::from(u16::from_le_bytes([decrypted.payload[0], decrypted.payload[1]]));
    assert_eq!(&decrypted.payload.as_slice()[2..2 + plaintext_len], b"hello");
}

#[test]
fn generated_aes256gcm_key_round_trip_succeeds() {
    let mut engine = unauthenticated_operational_engine();
    let challenge = begin_auth(&mut engine, 0x06);
    let session = complete_auth(&mut engine, challenge, 1, b"KEYMG");

    let generated = engine.handle_bytes(&generate_key_request(
        session,
        2,
        KeyAlgorithm::Aes256Gcm,
        GENERATED_SYM_USAGE,
    ));
    assert_eq!(generated.code, StatusCode::Success.as_u8());
    let key_id = generated.payload[0];

    let encrypted = engine.handle_bytes(&sym_encrypt_request(
        session,
        3,
        key_id,
        KeyAlgorithm::Aes256Gcm,
        b"hello",
    ));
    assert_eq!(encrypted.code, StatusCode::Success.as_u8());
    let nonce_len = usize::from(encrypted.payload[0]);
    let nonce = &encrypted.payload.as_slice()[1..=nonce_len];
    let ciphertext_len_index = 1 + nonce_len;
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
        KeyAlgorithm::Aes256Gcm,
        nonce,
        ciphertext,
    ));
    assert_eq!(decrypted.code, StatusCode::Success.as_u8());
    let plaintext_len = usize::from(u16::from_le_bytes([decrypted.payload[0], decrypted.payload[1]]));
    assert_eq!(&decrypted.payload.as_slice()[2..2 + plaintext_len], b"hello");
}

#[test]
fn generated_symmetric_key_rejects_wrong_usage_mask() {
    let mut engine = unauthenticated_operational_engine();
    let challenge = begin_auth(&mut engine, 0x06);
    let session = complete_auth(&mut engine, challenge, 1, b"KEYMG");

    let denied = engine.handle_bytes(&generate_key_request(
        session,
        2,
        KeyAlgorithm::ChaCha20Poly1305,
        rp_hsm::protocol::USAGE_SIGN,
    ));
    assert_eq!(denied.code, StatusCode::AuthorizationError.as_u8());
}
