// Copyright (C) 2026 creampuffle
// SPDX-License-Identifier: LicenseRef-CARROT-Study-1.0

use carrot_hybrid_key_schedule_demo::derive_demo_material;
use fips203::traits::{Decaps as _, Encaps as _, KeyGen as _, SerDes as _};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

fn main() {
    let initiator_secret = StaticSecret::random_from_rng(OsRng);
    let responder_secret = StaticSecret::random_from_rng(OsRng);
    let initiator_public = PublicKey::from(&initiator_secret);
    let responder_public = PublicKey::from(&responder_secret);
    let classical_initiator = initiator_secret.diffie_hellman(&responder_public);
    let classical_responder = responder_secret.diffie_hellman(&initiator_public);
    assert_eq!(
        classical_initiator.as_bytes(),
        classical_responder.as_bytes()
    );
    assert!(classical_initiator.was_contributory());

    let (encapsulation_key, decapsulation_key) =
        fips203::ml_kem_768::KG::try_keygen_with_rng(&mut OsRng)
            .expect("ML-KEM key generation failed");
    let (post_quantum_responder, ciphertext) = encapsulation_key
        .try_encaps_with_rng(&mut OsRng)
        .expect("ML-KEM encapsulation failed");
    let post_quantum_initiator = decapsulation_key
        .try_decaps(&ciphertext)
        .expect("ML-KEM decapsulation failed");
    assert_eq!(post_quantum_initiator, post_quantum_responder);

    let transcript: [u8; 32] = Sha256::digest(b"CARROT portfolio hybrid demo").into();
    let mut initiator_pq = post_quantum_initiator.into_bytes();
    let mut responder_pq = post_quantum_responder.into_bytes();
    let initiator =
        derive_demo_material(classical_initiator.as_bytes(), &initiator_pq, &transcript)
            .expect("hybrid derivation failed");
    let responder =
        derive_demo_material(classical_responder.as_bytes(), &responder_pq, &transcript)
            .expect("hybrid derivation failed");
    initiator_pq.zeroize();
    responder_pq.zeroize();
    assert_eq!(initiator, responder);
    println!("CARROT hybrid base-feature demonstration passed");
}
