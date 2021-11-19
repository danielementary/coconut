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

use std::convert::TryFrom;
use std::convert::TryInto;

use bls12_381::{G2Prepared, G2Projective};
use group::Curve;

use crate::error::{CoconutError, Result};
use crate::proofs::SetMembershipProof;

use crate::scheme::Signature;
use crate::scheme::VerificationKey;
use crate::traits::{Base58, Bytable};
use crate::utils::try_deserialize_g2_projective;
use crate::utils::RawAttribute;
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
    ) -> bool {
        self.pi.verify(
            params,
            verification_key,
            sp_verification_key,
            &self.kappa_1,
            &self.kappa_2,
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

pub fn verify_set_membership_credential(
    params: &Parameters,
    verification_key: &VerificationKey,
    sp_verification_key: &VerificationKey,
    theta: &SetMembershipTheta,
    public_attributes: &[Attribute],
) -> bool {
    if public_attributes.len() + theta.pi.private_attributes() > verification_key.beta.len() {
        return false;
    }

    if !theta.verify_proof(params, verification_key, sp_verification_key) {
        return false;
    }

    if bool::from(theta.a_prime.0.is_identity()) || bool::from(theta.sigma_prime.0.is_identity()) {
        return false;
    }

    let signed_public_attributes = public_attributes
        .iter()
        .zip(
            verification_key
                .beta
                .iter()
                .skip(theta.pi.private_attributes()),
        )
        .map(|(pub_attr, beta_i)| beta_i * pub_attr)
        .sum::<G2Projective>();

    let kappa_2_all = theta.kappa_2 + signed_public_attributes;

    check_bilinear_pairing(
        &theta.a_prime.0.to_affine(),
        &G2Prepared::from(theta.kappa_1.to_affine()),
        &(theta.a_prime.1).to_affine(),
        params.prepared_miller_g2(),
    ) && check_bilinear_pairing(
        &theta.sigma_prime.0.to_affine(),
        &G2Prepared::from(kappa_2_all.to_affine()),
        &(theta.sigma_prime.1).to_affine(),
        params.prepared_miller_g2(),
    )
}

#[cfg(test)]
mod tests {
    use crate::scheme::keygen::keygen;
    use crate::scheme::setup::setup;
    use crate::scheme::verification::check_bilinear_pairing;

    use super::*;

    #[test]
    fn issue_membership_signatures_len() {
        let params = setup(1).unwrap();

        let set_2 = [RawAttribute::Number(0), RawAttribute::Number(1)];
        let membership_signatures_2 = issue_membership_signatures(&params, &set_2);

        let set_3 = [
            RawAttribute::Number(0),
            RawAttribute::Number(1),
            RawAttribute::Number(2),
        ];
        let membership_signatures_3 = issue_membership_signatures(&params, &set_3);

        assert_eq!(set_2.len(), membership_signatures_2.signatures.len());
        assert_eq!(set_3.len(), membership_signatures_3.signatures.len());
    }

    #[test]
    #[should_panic(
        expected = "set must contain at least 2 distinct attributes to issue signatures"
    )]
    fn issue_membership_signatures_empty_set() {
        let params = setup(1).unwrap();

        let set_0 = [];
        issue_membership_signatures(&params, &set_0);
    }

    #[test]
    #[should_panic(
        expected = "set must contain at least 2 distinct attributes to issue signatures"
    )]
    fn issue_membership_signatures_small_set() {
        let params = setup(1).unwrap();

        let set_1 = [RawAttribute::Number(0)];
        issue_membership_signatures(&params, &set_1);
    }

    #[test]
    #[should_panic(
        expected = "set must contain at least 2 distinct attributes to issue signatures"
    )]
    fn issue_membership_signatures_small_set_dup() {
        let params = setup(1).unwrap();

        let set_2_dup = [RawAttribute::Number(0), RawAttribute::Number(0)];
        issue_membership_signatures(&params, &set_2_dup);
    }

    #[test]
    fn issue_membership_signatures_valid() {
        let params = setup(1).unwrap();

        let set_2 = [RawAttribute::Number(0), RawAttribute::Number(1)];
        let membership_signatures_2 = issue_membership_signatures(&params, &set_2);
        let sp_verification_key = membership_signatures_2.sp_verification_key;

        for (m, Signature(s1, s2)) in membership_signatures_2.signatures.iter() {
            let abm = sp_verification_key.alpha
                + sp_verification_key.beta[0] * (Attribute::from(m.clone()));

            assert!(check_bilinear_pairing(
                &s1.to_affine(),
                &G2Prepared::from(abm.to_affine()),
                &s2.to_affine(),
                params.prepared_miller_g2(),
            ));
        }
    }

    #[test]
    fn set_membership_theta_bytes_roundtrip_1() {
        let params = setup(1).unwrap();

        let verification_key = keygen(&params).verification_key();
        let sp_verification_key = single_attribute_keygen(&params).verification_key();
        let private_attributes = params.n_random_scalars(1);

        let signature = Signature(
            params.gen1() * params.random_scalar(),
            params.gen1() * params.random_scalar(),
        );

        let membership_signature = Signature(
            params.gen1() * params.random_scalar(),
            params.gen1() * params.random_scalar(),
        );

        let theta = prove_credential_and_set_membership(
            &params,
            &verification_key,
            &sp_verification_key,
            &signature,
            &membership_signature,
            &private_attributes,
        )
        .unwrap();

        assert_eq!(
            SetMembershipTheta::try_from(theta.to_bytes().as_slice()).unwrap(),
            theta
        );
    }

    #[test]
    fn set_membership_theta_bytes_roundtrip_10() {
        let params = setup(10).unwrap();

        let verification_key = keygen(&params).verification_key();
        let sp_verification_key = single_attribute_keygen(&params).verification_key();
        let private_attributes = params.n_random_scalars(10);

        let signature = Signature(
            params.gen1() * params.random_scalar(),
            params.gen1() * params.random_scalar(),
        );

        let membership_signature = Signature(
            params.gen1() * params.random_scalar(),
            params.gen1() * params.random_scalar(),
        );

        let theta = prove_credential_and_set_membership(
            &params,
            &verification_key,
            &sp_verification_key,
            &signature,
            &membership_signature,
            &private_attributes,
        )
        .unwrap();

        assert_eq!(
            SetMembershipTheta::try_from(theta.to_bytes().as_slice()).unwrap(),
            theta
        );
    }

    #[test]
    fn set_membership_theta_bytes_roundtrip_5_5() {
        let params = setup(10).unwrap();

        let verification_key = keygen(&params).verification_key();
        let sp_verification_key = single_attribute_keygen(&params).verification_key();
        let private_attributes = params.n_random_scalars(5);

        let signature = Signature(
            params.gen1() * params.random_scalar(),
            params.gen1() * params.random_scalar(),
        );

        let membership_signature = Signature(
            params.gen1() * params.random_scalar(),
            params.gen1() * params.random_scalar(),
        );

        let theta = prove_credential_and_set_membership(
            &params,
            &verification_key,
            &sp_verification_key,
            &signature,
            &membership_signature,
            &private_attributes,
        )
        .unwrap();

        assert_eq!(
            SetMembershipTheta::try_from(theta.to_bytes().as_slice()).unwrap(),
            theta
        );
    }
}
