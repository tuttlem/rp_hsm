use rp_hsm::protocol::{
    ALGORITHM_OP_DECRYPT, ALGORITHM_OP_ENCRYPT, ALGORITHM_OP_GENERATE, KeyAlgorithm,
    REVIEWED_ALGORITHM_PROFILES,
};

#[test]
fn x25519_profile_is_exposed_for_generate_encrypt_decrypt() {
    let profile = REVIEWED_ALGORITHM_PROFILES
        .iter()
        .find(|profile| profile.algorithm == KeyAlgorithm::X25519ChaCha20Poly1305);
    assert!(profile.is_some(), "profile present");
    let Some(profile) = profile else {
        unreachable!("asserted above");
    };
    assert_eq!(
        profile.operation_mask,
        ALGORITHM_OP_GENERATE | ALGORITHM_OP_ENCRYPT | ALGORITHM_OP_DECRYPT
    );
    assert_eq!(profile.public_material_len, 32);
}
