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

use bls12_381::{G2Prepared, G2Projective, Scalar};
use group::Curve;

use crate::error::{CoconutError, Result};

use crate::proofs::RangeProof;

use crate::scheme::setup::Parameters;
use crate::scheme::verification::{check_bilinear_pairing, compute_kappa};
use crate::scheme::{Signature, VerificationKey};

use crate::traits::{Base58, Bytable};

use crate::utils::{
    compute_u_ary_decomposition, deserialize_g2_projective, deserialize_g2_projectives,
    deserialize_range_proof, deserialize_scalar, deserialize_signature, deserialize_signatures,
    deserialize_usize, pick_signatures_for_decomposition, scalar_to_u64, serialize_g2_projective,
    serialize_g2_projectives, serialize_proof, serialize_scalar, serialize_signature,
    serialize_signatures, serialize_usize, ServiceProviderSignatures,
};

use crate::Attribute;

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct RangeTheta {
    base_u: usize,
    number_of_base_elements_l: usize,
    lower_bound: Scalar,
    upper_bound: Scalar,
    // "randomized" signatures for decomposition and decomposition
    // and corresponding material to verify randomization
    // for lower bound and upper bound check
    // lower bound
    decomposition_randomized_signatures_lower_bound: Vec<Signature>,
    decomposition_kappas_lower_bound: Vec<G2Projective>,
    randomized_credential_lower_bound: Signature,
    credential_kappa_lower_bound: G2Projective,
    // upper bound
    decomposition_randomized_signatures_upper_bound: Vec<Signature>,
    decomposition_kappas_upper_bound: Vec<G2Projective>,
    randomized_credential_upper_bound: Signature,
    credential_kappa_upper_bound: G2Projective,
    // non-interactive zero-knowledge proof for lower and upper bound
    nizkp: RangeProof,
}
impl TryFrom<&[u8]> for RangeTheta {
    type Error = CoconutError;

    fn try_from(bytes: &[u8]) -> Result<RangeTheta> {
        let mut pointer = 0;

        let base_u = deserialize_usize(&bytes, &mut pointer);
        let number_of_base_elements_l = deserialize_usize(&bytes, &mut pointer);

        let lower_bound = deserialize_scalar(&bytes, &mut pointer);
        let upper_bound = deserialize_scalar(&bytes, &mut pointer);

        let decomposition_randomized_signatures_lower_bound =
            deserialize_signatures(&bytes, &mut pointer, number_of_base_elements_l);
        let decomposition_kappas_lower_bound =
            deserialize_g2_projectives(&bytes, &mut pointer, number_of_base_elements_l);
        let randomized_credential_lower_bound = deserialize_signature(&bytes, &mut pointer);
        let credential_kappa_lower_bound = deserialize_g2_projective(&bytes, &mut pointer);

        let decomposition_randomized_signatures_upper_bound =
            deserialize_signatures(&bytes, &mut pointer, number_of_base_elements_l);
        let decomposition_kappas_upper_bound =
            deserialize_g2_projectives(&bytes, &mut pointer, number_of_base_elements_l);
        let randomized_credential_upper_bound = deserialize_signature(&bytes, &mut pointer);
        let credential_kappa_upper_bound = deserialize_g2_projective(&bytes, &mut pointer);

        let nizkp = deserialize_range_proof(&bytes, &mut pointer);

        Ok(RangeTheta {
            base_u,
            number_of_base_elements_l,
            lower_bound,
            upper_bound,
            decomposition_randomized_signatures_lower_bound,
            decomposition_kappas_lower_bound,
            randomized_credential_lower_bound,
            credential_kappa_lower_bound,
            decomposition_randomized_signatures_upper_bound,
            decomposition_kappas_upper_bound,
            randomized_credential_upper_bound,
            credential_kappa_upper_bound,
            nizkp,
        })
    }
}

impl RangeTheta {
    fn verify_proof(
        &self,
        params: &Parameters,
        verification_key: &VerificationKey,
        sp_verification_key: &VerificationKey,
    ) -> bool {
        self.nizkp.verify(
            &params,
            &verification_key,
            &sp_verification_key,
            &self.decomposition_kappas_lower_bound,
            &self.credential_kappa_lower_bound,
            &self.decomposition_kappas_upper_bound,
            &self.credential_kappa_upper_bound,
        )
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        serialize_usize(&self.base_u, &mut bytes);
        serialize_usize(&self.number_of_base_elements_l, &mut bytes);

        serialize_scalar(&self.lower_bound, &mut bytes);
        serialize_scalar(&self.upper_bound, &mut bytes);

        serialize_signatures(
            &self.decomposition_randomized_signatures_lower_bound,
            &mut bytes,
        );
        serialize_g2_projectives(&self.decomposition_kappas_lower_bound, &mut bytes);
        serialize_signature(&self.randomized_credential_lower_bound, &mut bytes);
        serialize_g2_projective(&self.credential_kappa_lower_bound, &mut bytes);

        serialize_signatures(
            &self.decomposition_randomized_signatures_upper_bound,
            &mut bytes,
        );
        serialize_g2_projectives(&self.decomposition_kappas_upper_bound, &mut bytes);
        serialize_signature(&self.randomized_credential_upper_bound, &mut bytes);
        serialize_g2_projective(&self.credential_kappa_upper_bound, &mut bytes);

        serialize_proof(&self.nizkp, &mut bytes);

        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<RangeTheta> {
        RangeTheta::try_from(bytes)
    }
}

impl Bytable for RangeTheta {
    fn to_byte_vec(&self) -> Vec<u8> {
        self.to_bytes()
    }

    fn try_from_byte_slice(slice: &[u8]) -> Result<Self> {
        RangeTheta::try_from(slice)
    }
}

impl Base58 for RangeTheta {}

pub fn prove_credential_and_range(
    // parameters
    params: &Parameters,
    base_u: usize,
    number_of_base_elements_l: usize,
    lower_bound: Scalar,
    upper_bound: Scalar,
    // keys
    verification_key: &VerificationKey,
    sp_verification_key: &VerificationKey,
    // signatures
    credential: &Signature,
    sp_signatures: &ServiceProviderSignatures,
    // attributes
    private_attributes: &Vec<Attribute>,
) -> Result<RangeTheta> {
    if private_attributes.is_empty() {
        return Err(CoconutError::Verification(
            "Tried to prove a credential with an empty set of private attributes".to_string(),
        ));
    }

    if private_attributes.len() > verification_key.beta.len() {
        return Err(
            CoconutError::Verification("Tried to prove a credential for higher than supported by the provided verification key number of attributes.".to_string()));
    }

    if scalar_to_u64(&upper_bound) < scalar_to_u64(&lower_bound) {
        return Err(CoconutError::Verification(
                "Tried to prove a credential with inadequate bounds, make sure that upper_bound >= lower_bound.".to_string()));
    }

    // use first private attribute for range proof
    let private_attribute_for_proof = private_attributes[0];

    // lower bound run
    let decomposition_lower_bound = compute_u_ary_decomposition(
        &(private_attribute_for_proof - lower_bound),
        base_u,
        number_of_base_elements_l,
    );
    let decomposition_signatures_lower_bound =
        pick_signatures_for_decomposition(&decomposition_lower_bound, &sp_signatures);
    let (decomposition_randomized_signatures_lower_bound, decomposition_blinders_lower_bound): (
        Vec<_>,
        Vec<_>,
    ) = decomposition_signatures_lower_bound
        .iter()
        .map(|s| s.randomise(&params))
        .unzip();
    let (randomized_credential_lower_bound, credential_blinder_lower_bound) =
        credential.randomise(&params);
    let decomposition_kappas_lower_bound = decomposition_blinders_lower_bound
        .iter()
        .enumerate()
        .map(|(i, b)| {
            compute_kappa(
                params,
                sp_verification_key,
                &decomposition_lower_bound[i..],
                *b,
            )
        })
        .collect();
    let credential_kappa_lower_bound = compute_kappa(
        params,
        verification_key,
        private_attributes,
        credential_blinder_lower_bound,
    );

    // upper bound run
    let decomposition_upper_bound = compute_u_ary_decomposition(
        &(private_attribute_for_proof - upper_bound
            + Scalar::from((base_u as u64).pow(number_of_base_elements_l as u32))),
        base_u,
        number_of_base_elements_l,
    );
    let decomposition_signatures_upper_bound =
        pick_signatures_for_decomposition(&decomposition_upper_bound, &sp_signatures);
    let (decomposition_randomized_signatures_upper_bound, decomposition_blinders_upper_bound): (
        Vec<_>,
        Vec<_>,
    ) = decomposition_signatures_upper_bound
        .iter()
        .map(|s| s.randomise(&params))
        .unzip();
    let (randomized_credential_upper_bound, credential_blinder_upper_bound) =
        credential.randomise(&params);
    let decomposition_kappas_upper_bound = decomposition_blinders_upper_bound
        .iter()
        .enumerate()
        .map(|(i, b)| {
            compute_kappa(
                params,
                sp_verification_key,
                &decomposition_upper_bound[i..],
                *b,
            )
        })
        .collect();
    let credential_kappa_upper_bound = compute_kappa(
        params,
        verification_key,
        private_attributes,
        credential_blinder_upper_bound,
    );

    let nizkp = RangeProof::construct(
        params,
        base_u,
        number_of_base_elements_l,
        lower_bound,
        upper_bound,
        &verification_key,
        &sp_verification_key,
        &decomposition_lower_bound,
        &decomposition_blinders_lower_bound,
        &credential_blinder_lower_bound,
        &decomposition_upper_bound,
        &decomposition_blinders_upper_bound,
        &credential_blinder_upper_bound,
        &private_attributes,
    );

    Ok(RangeTheta {
        base_u,
        number_of_base_elements_l,
        lower_bound,
        upper_bound,
        decomposition_randomized_signatures_lower_bound,
        decomposition_kappas_lower_bound,
        randomized_credential_lower_bound,
        credential_kappa_lower_bound,
        decomposition_randomized_signatures_upper_bound,
        decomposition_kappas_upper_bound,
        randomized_credential_upper_bound,
        credential_kappa_upper_bound,
        nizkp,
    })
}

pub fn verify_range_credential(
    params: &Parameters,
    verification_key: &VerificationKey,
    sp_verification_key: &VerificationKey,
    theta: &RangeTheta,
    public_attributes: &[Attribute],
) -> bool {
    if public_attributes.len() + theta.nizkp.private_attributes() > verification_key.beta.len() {
        return false;
    }

    if !theta.verify_proof(params, verification_key, sp_verification_key) {
        return false;
    }

    for a in &theta.decomposition_randomized_signatures_lower_bound {
        if bool::from(a.0.is_identity()) {
            return false;
        }
    }

    for a in &theta.decomposition_randomized_signatures_upper_bound {
        if bool::from(a.0.is_identity()) {
            return false;
        }
    }

    if bool::from(theta.randomized_credential_lower_bound.0.is_identity())
        || bool::from(theta.randomized_credential_upper_bound.0.is_identity())
    {
        return false;
    }

    for (a, k) in theta
        .decomposition_randomized_signatures_lower_bound
        .iter()
        .zip(&theta.decomposition_kappas_lower_bound)
    {
        if !check_bilinear_pairing(
            &a.0.to_affine(),
            &G2Prepared::from(k.to_affine()),
            &(a.1).to_affine(),
            params.prepared_miller_g2(),
        ) {
            return false;
        }
    }

    for (a, k) in theta
        .decomposition_randomized_signatures_upper_bound
        .iter()
        .zip(&theta.decomposition_kappas_upper_bound)
    {
        if !check_bilinear_pairing(
            &a.0.to_affine(),
            &G2Prepared::from(k.to_affine()),
            &(a.1).to_affine(),
            params.prepared_miller_g2(),
        ) {
            return false;
        }
    }

    check_bilinear_pairing(
        &theta.randomized_credential_lower_bound.0.to_affine(),
        &G2Prepared::from(theta.credential_kappa_lower_bound.to_affine()),
        &(theta.randomized_credential_lower_bound.1).to_affine(),
        params.prepared_miller_g2(),
    ) && check_bilinear_pairing(
        &theta.randomized_credential_upper_bound.0.to_affine(),
        &G2Prepared::from(theta.credential_kappa_upper_bound.to_affine()),
        &(theta.randomized_credential_upper_bound.1).to_affine(),
        params.prepared_miller_g2(),
    )
}

#[cfg(test)]
mod tests {
    use crate::scheme::keygen::{keygen, single_attribute_keygen};
    use crate::scheme::setup::setup;
    use crate::utils::issue_range_signatures;

    use super::*;

    // tests are performed for base u and 8 base elements
    const U: usize = 4;
    const L: usize = 8;

    #[test]
    fn range_theta_bytes_roundtrip_1() {
        let params = setup(1).unwrap();
        let sp_h = params.gen1() * params.random_scalar();
        let sp_key_pair = single_attribute_keygen(&params);
        let sp_private_key = sp_key_pair.secret_key();
        let sp_verification_key = sp_key_pair.verification_key();

        let verification_key = keygen(&params).verification_key();
        let private_attributes = vec![Scalar::from(10)];

        let signature = Signature(
            params.gen1() * params.random_scalar(),
            params.gen1() * params.random_scalar(),
        );

        let range_signatures = issue_range_signatures(&sp_h, &sp_private_key, 0, U);

        let a = Scalar::from(0);
        let b = Scalar::from(15);

        let theta = prove_credential_and_range(
            &params,
            U,
            L,
            a,
            b,
            &verification_key,
            &sp_verification_key,
            &signature,
            &range_signatures,
            &private_attributes,
        )
        .unwrap();

        assert_eq!(
            RangeTheta::try_from(theta.to_bytes().as_slice()).unwrap(),
            theta
        );
    }

    #[test]
    fn range_theta_bytes_roundtrip_10() {
        let params = setup(10).unwrap();
        let sp_h = params.gen1() * params.random_scalar();
        let sp_key_pair = single_attribute_keygen(&params);
        let sp_private_key = sp_key_pair.secret_key();
        let sp_verification_key = sp_key_pair.verification_key();

        let verification_key = keygen(&params).verification_key();
        let private_attributes =
            vec![[Scalar::from(10)].to_vec(), params.n_random_scalars(9)].concat();

        let signature = Signature(
            params.gen1() * params.random_scalar(),
            params.gen1() * params.random_scalar(),
        );

        let range_signatures = issue_range_signatures(&sp_h, &sp_private_key, 0, U);

        let a = Scalar::from(0);
        let b = Scalar::from(15);

        let theta = prove_credential_and_range(
            &params,
            U,
            L,
            a,
            b,
            &verification_key,
            &sp_verification_key,
            &signature,
            &range_signatures,
            &private_attributes,
        )
        .unwrap();

        assert_eq!(
            RangeTheta::try_from(theta.to_bytes().as_slice()).unwrap(),
            theta
        );
    }

    #[test]
    fn range_theta_bytes_roundtrip_5_5() {
        let params = setup(10).unwrap();
        let sp_h = params.gen1() * params.random_scalar();
        let sp_key_pair = single_attribute_keygen(&params);
        let sp_private_key = sp_key_pair.secret_key();
        let sp_verification_key = sp_key_pair.verification_key();

        let verification_key = keygen(&params).verification_key();
        let private_attributes =
            vec![[Scalar::from(10)].to_vec(), params.n_random_scalars(4)].concat();

        let signature = Signature(
            params.gen1() * params.random_scalar(),
            params.gen1() * params.random_scalar(),
        );

        let range_signatures = issue_range_signatures(&sp_h, &sp_private_key, 0, U);

        let a = Scalar::from(0);
        let b = Scalar::from(15);

        let theta = prove_credential_and_range(
            &params,
            U,
            L,
            a,
            b,
            &verification_key,
            &sp_verification_key,
            &signature,
            &range_signatures,
            &private_attributes,
        )
        .unwrap();

        assert_eq!(
            RangeTheta::try_from(theta.to_bytes().as_slice()).unwrap(),
            theta
        );
    }
}
