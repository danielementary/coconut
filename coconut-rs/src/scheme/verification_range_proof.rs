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

use std::convert::TryFrom;

use bls12_381::{G2Prepared, G2Projective, Scalar};
use group::Curve;

use crate::error::{CoconutError, Result};

use crate::proofs::RangeProof;

use crate::scheme::setup::Parameters;
use crate::scheme::verification::{check_bilinear_pairing, compute_kappa};
use crate::scheme::verification_set_membership::{issue_membership_signatures, SpSignatures};
use crate::scheme::{Signature, VerificationKey};

use crate::traits::{Base58, Bytable};

use crate::utils::RawAttribute;
use crate::utils::{
    deserialize_g2_projective, deserialize_g2_projectives, deserialize_range_proof,
    deserialize_scalar, deserialize_signature, deserialize_signatures, deserialize_usize,
    serialize_g2_projective, serialize_g2_projectives, serialize_proof, serialize_scalar,
    serialize_signature, serialize_signatures, serialize_usize,
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

pub fn issue_range_signatures(params: &Parameters) -> SpSignatures {
    // TODO: remove U and L
    const U: usize = 4;

    let set: Vec<usize> = (0..U).collect();
    let set: Vec<RawAttribute> = set
        .iter()
        .map(|e| RawAttribute::Number(*e as u64))
        .collect();

    issue_membership_signatures(params, &set[..])
}

fn scalar_fits_in_u64(number: &Scalar) -> bool {
    let bytes = number.to_bytes();

    // check that only first 64 bits are set
    for byte in bytes[8..].iter() {
        if *byte != 0 {
            return false;
        }
    }

    true
}

fn scalar_to_u64(number: &Scalar) -> u64 {
    if !scalar_fits_in_u64(&number) {
        panic!("This scalar does not fit in u64");
    }

    // keep 8 first bytes ~= 64 first bits for u64
    let mut u64_bytes: [u8; 8] = [0; 8];
    let number_bytes = number.to_bytes();

    u64_bytes.clone_from_slice(&number_bytes[..8]);

    u64::from_le_bytes(u64_bytes)
}

pub fn compute_u_ary_decomposition(
    number: &Scalar,
    base_u: usize,
    number_of_base_elements_l: usize,
) -> Vec<Scalar> {
    // these casts are necessary to compute powers and divisions
    // may panic if number does not fit in u64
    // or if number_of_base_elements_l doest not fit in u32
    // but this should usually not happen
    let number = scalar_to_u64(&number);
    let base_u = u64::try_from(base_u).unwrap();
    let number_of_base_elements_l = u32::try_from(number_of_base_elements_l).unwrap();

    // the decomposition can only be computed for numbers in [0, base_u^number_of_base_elements_l)
    // otherwise it panics
    let upper_bound = base_u.pow(number_of_base_elements_l);
    if upper_bound <= number {
        panic!("this number is out of range to compute {}-ary decomposition on {} base elements ([0, {})).", base_u, number_of_base_elements_l, upper_bound);
    }

    let mut decomposition: Vec<Scalar> = Vec::new();
    let mut remainder = number;

    for i in (0..number_of_base_elements_l).rev() {
        let i_th_pow = base_u.pow(i);
        let i_th_base_element = remainder / i_th_pow;

        decomposition.push(Scalar::from(i_th_base_element));
        remainder %= i_th_pow;
    }

    // make sure that returned vec has actually number_of_base_elements_l elements"
    let number_of_base_elements_l = usize::try_from(number_of_base_elements_l).unwrap();
    assert_eq!(number_of_base_elements_l, decomposition.len());

    // decomposition is little endian: base_u^0 | base_u^1 | ... | base_u^(number_of_base_elements_l - 1)
    decomposition.reverse();
    decomposition
}

fn pick_signature_for_base_element(
    m: &Scalar,
    signatures: &HashMap<RawAttribute, Signature>,
) -> Signature {
    signatures
        .get(&RawAttribute::Number(scalar_to_u64(m)))
        .unwrap()
        .clone()
}

pub fn pick_signatures_for_decomposition(
    decomposition: &Vec<Scalar>,
    signatures: &HashMap<RawAttribute, Signature>,
) -> Vec<Signature> {
    decomposition
        .iter()
        .map(|base_elements_i| pick_signature_for_base_element(base_elements_i, signatures))
        .collect()
}

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
    sp_signatures: &HashMap<RawAttribute, Signature>,
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

    // TODO: turn this into a function
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
        verification_key,
        sp_verification_key,
        &decomposition_lower_bound,
        &decomposition_blinders_lower_bound,
        &credential_blinder_lower_bound,
        &decomposition_upper_bound,
        &decomposition_blinders_upper_bound,
        &credential_blinder_upper_bound,
        private_attributes,
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
    use crate::scheme::keygen::keygen;
    use crate::scheme::setup::setup;

    use super::*;

    // tests are performed for base u and 8 base elements
    const U: usize = 4;
    const L: usize = 8;
    const MAX: u64 = (U as u64).pow(L as u32);

    #[test]
    fn compute_u_ary_decomposition_scalar_fits_in_u64_tests() {
        assert!(scalar_fits_in_u64(&Scalar::from(0)));
        assert!(scalar_fits_in_u64(&Scalar::from(256)));
        assert!(scalar_fits_in_u64(&Scalar::from(65535)));
        assert!(scalar_fits_in_u64(&Scalar::from(u64::MAX)));

        assert!(!scalar_fits_in_u64(
            &(Scalar::from(u64::MAX) + Scalar::from(1))
        ));
        assert!(!scalar_fits_in_u64(
            &(Scalar::from(u64::MAX) * Scalar::from(2))
        ));
    }

    #[test]
    fn compute_u_ary_decomposition_scalar_to_u64_tests() {
        let values = [0, 1, 2, 3, 254, 255, 256, 65534, 65535, u64::MAX];

        for v in values {
            assert_eq!(v as u64, scalar_to_u64(&Scalar::from(v)));
        }
    }

    #[test]
    #[should_panic(expected = "This scalar does not fit in u64")]
    fn compute_u_ary_decomposition_scalara_to_u64_overflow_panic() {
        scalar_to_u64(&(Scalar::from(u64::MAX) + Scalar::from(1)));
    }

    #[test]
    fn compute_u_ary_decomposition_0() {
        let decomposition = compute_u_ary_decomposition(&Scalar::from(0), U, L);

        assert_eq!([Scalar::from(0); L].to_vec(), decomposition);
    }

    #[test]
    fn compute_u_ary_decomposition_1() {
        let decomposition_1 = compute_u_ary_decomposition(&Scalar::from(1), U, L);
        let decomposition_2 = compute_u_ary_decomposition(&Scalar::from(2), U, L);
        let decomposition_3 = compute_u_ary_decomposition(&Scalar::from(3), U, L);

        let mut decomposition = [Scalar::from(0); L];

        decomposition[0] = Scalar::from(1);
        assert_eq!(decomposition.to_vec(), decomposition_1);

        decomposition[0] = Scalar::from(2);
        assert_eq!(decomposition.to_vec(), decomposition_2);

        decomposition[0] = Scalar::from(3);
        assert_eq!(decomposition.to_vec(), decomposition_3);
    }

    #[test]
    fn compute_u_ary_decomposition_2() {
        let decomposition_4 = compute_u_ary_decomposition(&Scalar::from(4), U, L);
        let decomposition_9 = compute_u_ary_decomposition(&Scalar::from(9), U, L);
        let decomposition_14 = compute_u_ary_decomposition(&Scalar::from(14), U, L);

        let mut decomposition = [Scalar::from(0); L];

        decomposition[0] = Scalar::from(0);
        decomposition[1] = Scalar::from(1);
        assert_eq!(decomposition.to_vec(), decomposition_4);

        decomposition[0] = Scalar::from(1);
        decomposition[1] = Scalar::from(2);
        assert_eq!(decomposition.to_vec(), decomposition_9);

        decomposition[0] = Scalar::from(2);
        decomposition[1] = Scalar::from(3);
        assert_eq!(decomposition.to_vec(), decomposition_14);
    }

    #[test]
    fn compute_u_ary_decomposition_other() {
        let decomposition_max = compute_u_ary_decomposition(&Scalar::from(MAX - 1), U, L);

        let random = 23456;
        let decomposition_random = compute_u_ary_decomposition(&Scalar::from(random), U, L);

        let decomposition = [Scalar::from(3); L];
        assert_eq!(decomposition.to_vec(), decomposition_max);

        let decomposition = [
            Scalar::from(0),
            Scalar::from(0),
            Scalar::from(2),
            Scalar::from(2),
            Scalar::from(3),
            Scalar::from(2),
            Scalar::from(1),
            Scalar::from(1),
        ];
        assert_eq!(decomposition.to_vec(), decomposition_random);
    }

    #[test]
    #[should_panic(
        expected = "this number is out of range to compute 4-ary decomposition on 8 base elements ([0, 65536))."
    )]
    fn compute_u_ary_decomposition_overflow_panic() {
        compute_u_ary_decomposition(&Scalar::from(MAX), U, L);
    }

    #[test]
    fn issue_range_signatures_len() {
        let params = setup(1).unwrap();
        let range_signatures = issue_range_signatures(&params);

        assert_eq!(U, range_signatures.signatures.len());
    }

    #[test]
    fn range_theta_bytes_roundtrip_1() {
        let params = setup(1).unwrap();

        let verification_key = keygen(&params).verification_key();
        let private_attributes = vec![Scalar::from(10)];

        let signature = Signature(
            params.gen1() * params.random_scalar(),
            params.gen1() * params.random_scalar(),
        );

        let all_range_signatures = issue_range_signatures(&params);
        let sp_verification_key = &all_range_signatures.sp_verification_key;

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
            &all_range_signatures.signatures,
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

        let verification_key = keygen(&params).verification_key();
        let private_attributes =
            vec![[Scalar::from(10)].to_vec(), params.n_random_scalars(9)].concat();

        let signature = Signature(
            params.gen1() * params.random_scalar(),
            params.gen1() * params.random_scalar(),
        );

        let all_range_signatures = issue_range_signatures(&params);
        let sp_verification_key = &all_range_signatures.sp_verification_key;

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
            &all_range_signatures.signatures,
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

        let verification_key = keygen(&params).verification_key();
        let private_attributes = [[Scalar::from(10)].to_vec(), params.n_random_scalars(4)].concat();

        let signature = Signature(
            params.gen1() * params.random_scalar(),
            params.gen1() * params.random_scalar(),
        );

        let all_range_signatures = issue_range_signatures(&params);
        let sp_verification_key = &all_range_signatures.sp_verification_key;

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
            &all_range_signatures.signatures,
            &private_attributes,
        )
        .unwrap();

        assert_eq!(
            RangeTheta::try_from(theta.to_bytes().as_slice()).unwrap(),
            theta
        );
    }
}
