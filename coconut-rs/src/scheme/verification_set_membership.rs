// Copyright 2021 Nym Technologies SA
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::HashMap;

use core::ops::Neg;
use std::convert::TryFrom;
use std::convert::TryInto;

use bls12_381::{multi_miller_loop, G1Affine, G1Projective, G2Prepared, G2Projective, Scalar};
use group::{Curve, Group};

use crate::error::{CoconutError, Result};
use crate::proofs::SetMembershipProof;
use crate::scheme::keygen::single_attribute_keygen;
use crate::scheme::setup::Parameters;
use crate::scheme::verification::compute_kappa;
use crate::scheme::Signature;
use crate::scheme::VerificationKey;
use crate::traits::{Base58, Bytable};
use crate::utils::{hash_g1, RawAttribute};
use crate::utils::{try_deserialize_g1_projective, try_deserialize_g2_projective};
use crate::Attribute;

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct SetMembershipTheta {
    pub kappa_1: G2Projective,
    pub a_prime: Signature,
    pub kappa_2: G2Projective,
    pub sigma_prime: Signature,
    pub pi: SetMembershipProof,
}

impl TryFrom<&[u8]> for SetMembershipTheta {
    type Error = CoconutError;

    fn try_from(bytes: &[u8]) -> Result<SetMembershipTheta> {
        if bytes.len() < 384 {
            return Err(
                CoconutError::Deserialization(
                    format!("Tried to deserialize theta with insufficient number of bytes, expected >= 384, got {}", bytes.len()),
                ));
        }

        let kappa_1_bytes = bytes[..96].try_into().unwrap();
        let kappa_1 = try_deserialize_g2_projective(
            &kappa_1_bytes,
            CoconutError::Deserialization("failed to deserialize kappa_1".to_string()),
        )?;

        let a_prime = Signature::try_from(&bytes[96..192])?;

        let kappa_2_bytes = bytes[192..288].try_into().unwrap();
        let kappa_2 = try_deserialize_g2_projective(
            &kappa_2_bytes,
            CoconutError::Deserialization("failed to deserialize kappa_2".to_string()),
        )?;

        let sigma_prime = Signature::try_from(&bytes[288..384])?;

        let pi = SetMembershipProof::from_bytes(&bytes[384..])?;

        Ok(SetMembershipTheta {
            kappa_1,
            a_prime,
            kappa_2,
            sigma_prime,
            pi,
        })
    }
}

impl SetMembershipTheta {
    fn verify_proof(
        &self,
        params: &Parameters,
        verification_key: &VerificationKey,
        sp_verification_key: &VerificationKey,
        kappa_1: &G2Projective,
        kappa_2: &G2Projective,
    ) -> bool {
        self.pi.verify(
            params,
            verification_key,
            &sp_verification_key,
            &kappa_1,
            &kappa_2,
        )
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let kappa_1_bytes = self.kappa_1.to_affine().to_compressed();
        let a_prime_bytes = self.a_prime.to_bytes();
        let kappa_2_bytes = self.kappa_2.to_affine().to_compressed();
        let sigma_prime_bytes = self.sigma_prime.to_bytes();
        let pi_bytes = self.pi.to_bytes();

        let mut bytes = Vec::with_capacity(
            kappa_1_bytes.len()
                + a_prime_bytes.len()
                + kappa_2_bytes.len()
                + sigma_prime_bytes.len()
                + pi_bytes.len(),
        );

        bytes.extend_from_slice(&kappa_1_bytes);
        bytes.extend_from_slice(&a_prime_bytes);
        bytes.extend_from_slice(&kappa_2_bytes);
        bytes.extend_from_slice(&sigma_prime_bytes);
        bytes.extend_from_slice(&pi_bytes);

        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<SetMembershipTheta> {
        SetMembershipTheta::try_from(bytes)
    }
}

impl Bytable for SetMembershipTheta {
    fn to_byte_vec(&self) -> Vec<u8> {
        self.to_bytes()
    }

    fn try_from_byte_slice(slice: &[u8]) -> Result<Self> {
        SetMembershipTheta::try_from(slice)
    }
}

impl Base58 for SetMembershipTheta {}

pub struct MembershipSignatures {
    pub signatures: HashMap<RawAttribute, Signature>,
    pub sp_verification_key: VerificationKey,
}

pub fn issue_membership_signatures(
    params: &Parameters,
    phi: &[RawAttribute],
) -> MembershipSignatures {
    let sp_key_pair = single_attribute_keygen(params);
    // is the h random ? the same for all signatures ?
    let h = hash_g1("SPh");

    // always only one attribute ?
    let sp_sk = sp_key_pair.secret_key();
    let h_sp_sky = h * sp_sk.ys[0];

    let signatures: HashMap<RawAttribute, Signature> = phi
        .iter()
        .zip(vec![h * sp_sk.x; phi.len()].iter())
        .map(|(attr, h_sp_skx)| {
            (
                attr.clone(), // is it possible to avoid clones ?
                Signature(h, h_sp_skx + (h_sp_sky * (Attribute::from(attr.clone())))),
            )
        })
        .collect();

    let sp_verification_key = sp_key_pair.verification_key();

    MembershipSignatures {
        signatures,
        sp_verification_key,
    }
}

pub fn prove_credential_and_set_membership(
    params: &Parameters,
    verification_key: &VerificationKey,
    sp_verification_key: &VerificationKey,
    signature: &Signature,
    membership_signature: &Signature,
    private_attributes: &[Attribute],
) -> Result<SetMembershipTheta> {
    if private_attributes.is_empty() {
        return Err(CoconutError::Verification(
            "Tried to prove a credential with an empty set of private attributes".to_string(),
        ));
    }

    if private_attributes.len() > verification_key.beta.len() {
        return Err(
            CoconutError::Verification(
                format!("Tried to prove a credential for higher than supported by the provided verification key number of attributes (max: {}, requested: {})",
                        verification_key.beta.len(),
                        private_attributes.len()
                )));
    }

    let (a_prime, r1) = membership_signature.randomise(&params);
    let (sigma_prime, r2) = signature.randomise(&params);

    let kappa_1 = compute_kappa(params, sp_verification_key, private_attributes, r1);

    let kappa_2 = compute_kappa(params, verification_key, private_attributes, r2);

    let pi = SetMembershipProof::construct(
        params,
        verification_key,
        sp_verification_key,
        private_attributes,
        &r1,
        &r2,
    );

    Ok(SetMembershipTheta {
        kappa_1,
        a_prime,
        kappa_2,
        sigma_prime,
        pi,
    })
}

// // TODO
// pub fn verify_set_membership_credential(
//     params: &Parameters,
//     verification_key: &VerificationKey,
//     theta: &SetMembershipTheta,
//     public_attributes: &[Attribute],
// ) -> bool {
//     false
// }
