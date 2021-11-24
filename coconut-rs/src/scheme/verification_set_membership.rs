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

use bls12_381::{G2Prepared, G2Projective};
use group::Curve;

use crate::error::{CoconutError, Result};
use crate::proofs::SetMembershipProof;
use crate::scheme::setup::Parameters;
use crate::scheme::verification::{check_bilinear_pairing, compute_kappa};
use crate::scheme::{Signature, VerificationKey};
use crate::traits::{Base58, Bytable};
use crate::utils::{
    deserialize_g2_projective, deserialize_set_membership_proof, deserialize_signature,
    pick_signature_for_element, serialize_g2_projective, serialize_set_membership_proof,
    serialize_signature, ServiceProviderSignatures,
};
use crate::Attribute;

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct SetMembershipTheta {
    // "randomized" signatures for picked element and credential
    // and corresponding material to verify them
    element_randomized_signature: Signature,
    element_kappa: G2Projective,
    credential_randomized_signature: Signature,
    credential_kappa: G2Projective,
    // non-interactive zero-knowledge proof for the set membership proof
    nizkp: SetMembershipProof,
}

impl TryFrom<&[u8]> for SetMembershipTheta {
    type Error = CoconutError;

    fn try_from(bytes: &[u8]) -> Result<SetMembershipTheta> {
        let mut pointer = 0;

        let element_randomized_signature = deserialize_signature(&bytes, &mut pointer);
        let element_kappa = deserialize_g2_projective(&bytes, &mut pointer);
        let credential_randomized_signature = deserialize_signature(&bytes, &mut pointer);
        let credential_kappa = deserialize_g2_projective(&bytes, &mut pointer);
        let nizkp = deserialize_set_membership_proof(&bytes, &mut pointer);

        Ok(SetMembershipTheta {
            element_randomized_signature,
            element_kappa,
            credential_randomized_signature,
            credential_kappa,
            nizkp,
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
        self.nizkp.verify(
            params,
            verification_key,
            sp_verification_key,
            &self.element_kappa,
            &self.credential_kappa,
        )
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        serialize_signature(&self.element_randomized_signature, &mut bytes);
        serialize_g2_projective(&self.element_kappa, &mut bytes);
        serialize_signature(&self.credential_randomized_signature, &mut bytes);
        serialize_g2_projective(&self.credential_kappa, &mut bytes);

        serialize_set_membership_proof(&self.nizkp, &mut bytes);

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
    // parameters
    params: &Parameters,
    // keys
    verification_key: &VerificationKey,
    sp_verification_key: &VerificationKey,
    // signatures
    credential: &Signature,
    sp_signatures: &ServiceProviderSignatures,
    // attributes
    private_attributes: &Vec<Attribute>,
) -> Result<SetMembershipTheta> {
    if private_attributes.is_empty() {
        return Err(CoconutError::Verification(
            "Tried to prove a credential with an empty set of private attributes".to_string(),
        ));
    }

    if private_attributes.len() > verification_key.beta.len() {
        return Err(
            CoconutError::Verification("Tried to prove a credential for higher than supported by the provided verification key number of attributes.".to_string()));
    }

    // use first private attribute for range proof and pick corresponding signature
    let private_attribute_for_proof = private_attributes[0];
    let element_signature =
        pick_signature_for_element(&private_attribute_for_proof, &sp_signatures);

    // randomise signatures
    let (element_randomized_signature, element_blinder) = element_signature.randomise(&params);
    let (credential_randomized_signature, credential_blinder) = credential.randomise(&params);

    // compute kappas
    let element_kappa = compute_kappa(
        params,
        sp_verification_key,
        private_attributes,
        element_blinder,
    );

    let credential_kappa = compute_kappa(
        params,
        verification_key,
        private_attributes,
        credential_blinder,
    );

    // derive non-interactive zero-knowledge proof
    let nizkp = SetMembershipProof::construct(
        &params,
        &verification_key,
        &sp_verification_key,
        &element_blinder,
        &credential_blinder,
        &private_attributes,
    );

    Ok(SetMembershipTheta {
        element_randomized_signature,
        element_kappa,
        credential_randomized_signature,
        credential_kappa,
        nizkp,
    })
}

pub fn verify_set_membership_credential(
    // parameters
    params: &Parameters,
    // keys
    verification_key: &VerificationKey,
    sp_verification_key: &VerificationKey,
    // proof and attributes
    theta: &SetMembershipTheta,
    public_attributes: &Vec<Attribute>,
) -> bool {
    if public_attributes.len() + theta.nizkp.private_attributes() > verification_key.beta.len() {
        return false;
    }

    if !theta.verify_proof(params, verification_key, sp_verification_key) {
        return false;
    }

    // check generator is not identity
    if bool::from(theta.element_randomized_signature.0.is_identity())
        || bool::from(theta.credential_randomized_signature.0.is_identity())
    {
        return false;
    }

    let signed_public_attributes = public_attributes
        .iter()
        .zip(
            verification_key
                .beta
                .iter()
                .skip(theta.nizkp.private_attributes()),
        )
        .map(|(pub_attr, beta_i)| beta_i * pub_attr)
        .sum::<G2Projective>();

    let kappa_2_all = theta.credential_kappa + signed_public_attributes;

    check_bilinear_pairing(
        &theta.element_randomized_signature.0.to_affine(),
        &G2Prepared::from(theta.element_kappa.to_affine()),
        &(theta.element_randomized_signature.1).to_affine(),
        params.prepared_miller_g2(),
    ) && check_bilinear_pairing(
        &theta.credential_randomized_signature.0.to_affine(),
        &G2Prepared::from(kappa_2_all.to_affine()),
        &(theta.credential_randomized_signature.1).to_affine(),
        params.prepared_miller_g2(),
    )
}

#[cfg(test)]
mod tests {
    use crate::scheme::keygen::{keygen, single_attribute_keygen};
    use crate::scheme::setup::setup;
    use crate::utils::{issue_set_signatures, RawAttribute};
    use bls12_381::Scalar;

    use super::*;

    // test that we can retrieve the original theta converting to and from bytes
    // 1 private attribute
    #[test]
    fn set_membership_theta_bytes_roundtrip_1() {
        let params = setup(1).unwrap();

        let verification_key = keygen(&params).verification_key();
        let sp_key_pair = single_attribute_keygen(&params);
        let sp_verification_key = sp_key_pair.verification_key();

        // genereate some random credential, we only check serialization not correctness
        let credential = Signature(
            params.gen1() * params.random_scalar(),
            params.gen1() * params.random_scalar(),
        );

        let sp_h = params.gen1() * params.random_scalar();
        let sp_private_key = sp_key_pair.secret_key();
        let set = (0..10).map(|i| RawAttribute::Number(i as u64)).collect();
        let membership_signature = issue_set_signatures(&sp_h, &sp_private_key, &set);

        let private_attributes = vec![Scalar::from(1)];

        let theta = prove_credential_and_set_membership(
            &params,
            &verification_key,
            &sp_verification_key,
            &credential,
            &membership_signature,
            &private_attributes,
        )
        .unwrap();

        assert_eq!(
            SetMembershipTheta::try_from(theta.to_bytes().as_slice()).unwrap(),
            theta
        );
    }

    // 10 private attributes
    #[test]
    fn set_membership_theta_bytes_roundtrip_10() {
        let params = setup(10).unwrap();

        let verification_key = keygen(&params).verification_key();
        let sp_key_pair = single_attribute_keygen(&params);
        let sp_verification_key = sp_key_pair.verification_key();

        // genereate some random credential, we only check serialization not correctness
        let credential = Signature(
            params.gen1() * params.random_scalar(),
            params.gen1() * params.random_scalar(),
        );

        let sp_h = params.gen1() * params.random_scalar();
        let sp_private_key = sp_key_pair.secret_key();
        let set = (0..10).map(|i| RawAttribute::Number(i as u64)).collect();
        let membership_signature = issue_set_signatures(&sp_h, &sp_private_key, &set);

        let private_attributes =
            vec![[Scalar::from(1)].to_vec(), params.n_random_scalars(9)].concat();

        let theta = prove_credential_and_set_membership(
            &params,
            &verification_key,
            &sp_verification_key,
            &credential,
            &membership_signature,
            &private_attributes,
        )
        .unwrap();

        assert_eq!(
            SetMembershipTheta::try_from(theta.to_bytes().as_slice()).unwrap(),
            theta
        );
    }

    // 5 private attributes and 5 public ones
    #[test]
    fn set_membership_theta_bytes_roundtrip_5_5() {
        let params = setup(10).unwrap();

        let verification_key = keygen(&params).verification_key();
        let sp_key_pair = single_attribute_keygen(&params);
        let sp_verification_key = sp_key_pair.verification_key();

        // genereate some random credential, we only check serialization not correctness
        let credential = Signature(
            params.gen1() * params.random_scalar(),
            params.gen1() * params.random_scalar(),
        );

        let sp_h = params.gen1() * params.random_scalar();
        let sp_private_key = sp_key_pair.secret_key();
        let set = (0..10).map(|i| RawAttribute::Number(i as u64)).collect();
        let membership_signature = issue_set_signatures(&sp_h, &sp_private_key, &set);

        let private_attributes =
            vec![[Scalar::from(1)].to_vec(), params.n_random_scalars(4)].concat();

        let theta = prove_credential_and_set_membership(
            &params,
            &verification_key,
            &sp_verification_key,
            &credential,
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
