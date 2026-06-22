// Copyright (C) 2026 creampuffle
// SPDX-License-Identifier: LicenseRef-CARROT-Study-1.0

#![no_std]
#![doc = "An isolated proof of the hybrid key-derivation idea used by CARROT."]
#![doc = ""]
#![doc = "The labels and domain used here are portfolio-demo values, not the"]
#![doc = "unreleased CARROT transport schedule. This crate contains no packet"]
#![doc = "format, handshake, ratchet, stream, or network implementation."]

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

const DOMAIN: &[u8] = b"carrot:portfolio:hybrid-key-schedule:v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeriveError {
    ContextTooLong,
    ExpansionFailed,
}

#[derive(Debug, Eq, PartialEq)]
pub struct DerivedMaterial {
    pub initiator_key: [u8; 32],
    pub responder_key: [u8; 32],
    pub transcript_key: [u8; 32],
    pub initiator_nonce: [u8; 12],
    pub responder_nonce: [u8; 12],
}

impl Drop for DerivedMaterial {
    fn drop(&mut self) {
        self.initiator_key.zeroize();
        self.responder_key.zeroize();
        self.transcript_key.zeroize();
        self.initiator_nonce.zeroize();
        self.responder_nonce.zeroize();
    }
}

fn expand<const N: usize>(
    hkdf: &Hkdf<Sha256>,
    label: &[u8],
    output: &mut [u8; N],
) -> Result<(), DeriveError> {
    let mut info = [0u8; 96];
    let length = DOMAIN
        .len()
        .checked_add(label.len())
        .ok_or(DeriveError::ContextTooLong)?;
    if length > info.len() {
        return Err(DeriveError::ContextTooLong);
    }
    info[..DOMAIN.len()].copy_from_slice(DOMAIN);
    info[DOMAIN.len()..length].copy_from_slice(label);
    let result = hkdf
        .expand(&info[..length], output)
        .map_err(|_| DeriveError::ExpansionFailed);
    info.zeroize();
    result
}

pub fn derive_demo_material(
    classical_shared_secret: &[u8; 32],
    post_quantum_shared_secret: &[u8; 32],
    transcript_hash: &[u8; 32],
) -> Result<DerivedMaterial, DeriveError> {
    let mut hybrid_input = [0u8; 64];
    hybrid_input[..32].copy_from_slice(classical_shared_secret);
    hybrid_input[32..].copy_from_slice(post_quantum_shared_secret);
    let hkdf = Hkdf::<Sha256>::new(Some(transcript_hash), &hybrid_input);
    hybrid_input.zeroize();

    let mut material = DerivedMaterial {
        initiator_key: [0; 32],
        responder_key: [0; 32],
        transcript_key: [0; 32],
        initiator_nonce: [0; 12],
        responder_nonce: [0; 12],
    };
    expand(&hkdf, b":initiator:key", &mut material.initiator_key)?;
    expand(&hkdf, b":responder:key", &mut material.responder_key)?;
    expand(&hkdf, b":transcript:key", &mut material.transcript_key)?;
    expand(&hkdf, b":initiator:nonce", &mut material.initiator_nonce)?;
    expand(&hkdf, b":responder:nonce", &mut material.responder_nonce)?;
    Ok(material)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic_and_directional() {
        let classical = [0x11; 32];
        let post_quantum = [0x22; 32];
        let transcript = [0x33; 32];
        let first = derive_demo_material(&classical, &post_quantum, &transcript).unwrap();
        let second = derive_demo_material(&classical, &post_quantum, &transcript).unwrap();
        assert_eq!(first, second);
        assert_ne!(first.initiator_key, first.responder_key);
        assert_ne!(first.initiator_nonce, first.responder_nonce);
    }

    #[test]
    fn each_hybrid_input_changes_the_output() {
        let baseline = derive_demo_material(&[1; 32], &[2; 32], &[3; 32]).unwrap();
        let changed_classical = derive_demo_material(&[4; 32], &[2; 32], &[3; 32]).unwrap();
        let changed_pq = derive_demo_material(&[1; 32], &[4; 32], &[3; 32]).unwrap();
        let changed_transcript = derive_demo_material(&[1; 32], &[2; 32], &[4; 32]).unwrap();
        assert_ne!(baseline.initiator_key, changed_classical.initiator_key);
        assert_ne!(baseline.initiator_key, changed_pq.initiator_key);
        assert_ne!(baseline.initiator_key, changed_transcript.initiator_key);
    }
}
