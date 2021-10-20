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

use crate::error::{CoconutError, Result};
use crate::proofs::ProofKappaNu;
use crate::scheme::keygen::single_attribute_keygen;
use crate::scheme::setup::Parameters;
use crate::scheme::verification::compute_kappa;
use crate::scheme::Signature;
use crate::scheme::VerificationKey;
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

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct SetMembershipProof {
    cm_prime: Scalar,
    kappa_1_prime: G2Projective,
    kappa_2_prime: G2Projective,
    s_attributes: Vec<Scalar>,
    s_o: Scalar,
    s_r1: Scalar,
    s_r2: Scalar,
}

impl TryFrom<&[u8]> for SetMembershipTheta {
    type Error = CoconutError;

    fn try_from(bytes: &[u8]) -> Result<SetMembershipTheta> {
        if bytes.len() < 192 {
            return Err(
                CoconutError::Deserialization(
                    format!("Tried to deserialize theta with insufficient number of bytes, expected >= 240, got {}", bytes.len()),
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

        let pi = ProofKappaNu::from_bytes(&bytes[384..])?;

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
    fn verify_proof(&self, params: &Parameters, verification_key: &VerificationKey) -> bool {
        self.pi
            .verify(params, verification_key, &self.blinded_message)
    }

    // TODO: perhaps also include pi_v.len()?
    // to be determined once we implement serde to make sure its 1:1 compatible
    // with bincode
    // kappa || nu || credential || pi_v
    pub fn to_bytes(&self) -> Vec<u8> {
        let blinded_message_bytes = self.blinded_message.to_affine().to_compressed();
        let credential_bytes = self.credential.to_bytes();
        let proof_bytes = self.pi_v.to_bytes();

        let mut bytes = Vec::with_capacity(192 + proof_bytes.len());
        bytes.extend_from_slice(&blinded_message_bytes);
        bytes.extend_from_slice(&credential_bytes);
        bytes.extend_from_slice(&proof_bytes);

        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Theta> {
        Theta::try_from(bytes)
    }
}

pub fn issue_membership_signatures(
    params: &Parameters,
    phi: &[RawAttribute],
) -> HashMap<RawAttribute, Signature> {
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

    signatures
}

pub fn prove_credential(
    params: &Parameters,
    verification_key: &VerificationKey,
    signature: &Signature,
    private_attributes: &[Attribute],
) -> Result<Theta> {
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

    let kappa_1 = compute_kappa(params, verification_key, private_attributes, r1);

    let kappa_2 = compute_kappa(params, verification_key, private_attributes, r2);

    let pi_v = ProofKappaNu::construct(
        params,
        verification_key,
        private_attributes,
        &sign_blinding_factor,
        &blinded_message,
    );

    // Ok(Theta {
    //     blinded_message,
    //     credential: signature_prime,
    //     pi_v,
    // })
}
