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
use std::convert::TryInto;

use bls12_381::{G2Affine, G2Prepared, G2Projective, Scalar};
use group::Curve;

use crate::error::{CoconutError, Result};

use crate::proofs::RangeProof;

use crate::scheme::setup::Parameters;
use crate::scheme::verification::{check_bilinear_pairing, compute_kappa};
use crate::scheme::verification_set_membership::{issue_membership_signatures, SpSignatures};
use crate::scheme::Signature;
use crate::scheme::VerificationKey;

use crate::traits::{Base58, Bytable};

use crate::utils::RawAttribute;
use crate::utils::{G2PCOMPRESSED_SIZE, SCALAR_SIZE, SIGNATURE_SIZE, USIZE_SIZE};

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

fn serialize_usize(u: &usize, bytes: &Vec<u8>) {
    bytes.extend_from_slice(&u.to_be_bytes());
}

fn deserialize_usize(bytes: &[u8], pointer: &usize) -> usize {
    let pointer_end = *pointer + USIZE_SIZE;
    let u = usize::from_be_bytes(bytes[*pointer..pointer_end].try_into().unwrap());
    *pointer = pointer_end;

    u
}

fn serialize_scalar(s: &Scalar, bytes: &Vec<u8>) {
    bytes.extend_from_slice(&s.to_bytes());
}

fn deserialize_scalar(bytes: &[u8], pointer: &usize) -> Scalar {
    let pointer_end = *pointer + SCALAR_SIZE;
    let s = Scalar::from_bytes(&bytes[*pointer..pointer_end].try_into().unwrap()).unwrap();
    *pointer = pointer_end;

    s
}

fn serialize_signature(s: &Signature, bytes: &Vec<u8>) {
    bytes.extend_from_slice(&s.to_bytes());
}

fn deserialize_signature(bytes: &[u8], pointer: &usize) -> Signature {
    let pointer_end = *pointer + SIGNATURE_SIZE;
    let s = Signature::try_from(&bytes[*pointer..pointer_end]).unwrap();
    *pointer = pointer_end;

    s
}

fn serialize_signatures(s: &Vec<Signature>, bytes: &Vec<u8>) {
    s.iter().for_each(|s| serialize_signature(&s, &bytes));
}

fn deserialize_signatures(
    bytes: &[u8],
    pointer: &usize,
    number_of_signatures: usize,
) -> Vec<Signature> {
    (0..number_of_signatures)
        .map(|i| deserialize_signature(&bytes, pointer))
        .collect()
}

fn serialize_g2_projective(g: &G2Projective, bytes: &Vec<u8>) {
    bytes.extend_from_slice(&g.to_affine().to_compressed());
}

fn deserialize_g2_projective(bytes: &[u8], pointer: &usize) -> G2Projective {
    let pointer_end = *pointer + G2PCOMPRESSED_SIZE;
    let g = G2Projective::from(
        G2Affine::from_compressed(bytes[*pointer..pointer_end].try_into().unwrap()).unwrap(),
    );
    *pointer = pointer_end;

    g
}

fn serialize_g2_projectives(g: &Vec<G2Projective>, bytes: &Vec<u8>) {
    g.iter().for_each(|g| serialize_g2_projective(&g, &bytes));
}

fn deserialize_g2_projectives(
    bytes: &[u8],
    pointer: &usize,
    number_of_g2_projectives: usize,
) -> Vec<G2Projective> {
    (0..number_of_g2_projectives)
        .map(|i| deserialize_g2_projective(&bytes, pointer))
        .collect()
}

fn serialize_proof(p: &RangeProof, bytes: &Vec<u8>) {
    bytes.extend_from_slice(&p.to_bytes());
}

fn deserialize_range_proof(bytes: &[u8], pointer: &usize) -> RangeProof {
    RangeProof::from_bytes(&bytes[*pointer..]).unwrap()
}

impl TryFrom<&[u8]> for RangeTheta {
    type Error = CoconutError;

    fn try_from(bytes: &[u8]) -> Result<RangeTheta> {
        let mut pointer = 0;

        let base_u = deserialize_usize(&bytes, &pointer);
        let number_of_base_elements_l = deserialize_usize(&bytes, &pointer);

        let lower_bound = deserialize_scalar(&bytes, &pointer);
        let upper_bound = deserialize_scalar(&bytes, &pointer);

        let decomposition_randomized_signatures_lower_bound =
            deserialize_signatures(&bytes, &pointer, number_of_base_elements_l);
        let decomposition_kappas_lower_bound =
            deserialize_g2_projectives(&bytes, &pointer, number_of_base_elements_l);
        let randomized_credential_lower_bound = deserialize_signature(&bytes, &pointer);
        let credential_kappa_lower_bound = deserialize_g2_projective(&bytes, &pointer);

        let decomposition_randomized_signatures_upper_bound =
            deserialize_signatures(&bytes, &pointer, number_of_base_elements_l);
        let decomposition_kappas_upper_bound =
            deserialize_g2_projectives(&bytes, &pointer, number_of_base_elements_l);
        let randomized_credential_upper_bound = deserialize_signature(&bytes, &pointer);
        let credential_kappa_upper_bound = deserialize_g2_projective(&bytes, &pointer);

        let nizkp = deserialize_range_proof(&bytes, &pointer);

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
        self.pi.verify(
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

        serialize_usize(&self.base_u, &bytes);
        serialize_usize(&self.number_of_base_elements_l, &bytes);

        serialize_scalar(&self.lower_bound, &bytes);
        serialize_scalar(&self.upper_bound, &bytes);

        serialize_signatures(
            &self.decomposition_randomized_signatures_lower_bound,
            &bytes,
        );
        serialize_g2_projectives(&self.decomposition_kappas_lower_bound, &bytes);
        serialize_signature(&self.randomized_credential_lower_bound, &bytes);
        serialize_g2_projective(&self.credential_kappa_lower_bound, &bytes);

        serialize_signatures(
            &self.decomposition_randomized_signatures_upper_bound,
            &bytes,
        );
        serialize_g2_projectives(&self.decomposition_kappas_upper_bound, &bytes);
        serialize_signature(&self.randomized_credential_upper_bound, &bytes);
        serialize_g2_projective(&self.credential_kappa_upper_bound, &bytes);

        serialize_proof(&self.nizkp, &bytes);

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
    const L: usize = 8;

    let set: Vec<usize> = (0..U).collect();
    let set: Vec<RawAttribute> = set
        .iter()
        .map(|e| RawAttribute::Number(*e as u64))
        .collect();

    issue_membership_signatures(params, &set[..])
}

fn scalar_fits_in_u64(number: Scalar) -> bool {
    let bytes = number.to_bytes();

    // check that only first 64 bits are set
    for byte in bytes[8..].iter() {
        if *byte != 0 {
            return false;
        }
    }

    true
}

fn scalar_to_u64(number: Scalar) -> u64 {
    if !scalar_fits_in_u64(number) {
        panic!("This scalar does not fit in u64");
    }

    // keep 8 first bytes ~= 64 first bits for u64
    let mut u64_bytes: [u8; 8] = [0; 8];
    let number_bytes = number.to_bytes();

    u64_bytes.clone_from_slice(&number_bytes[..8]);

    u64::from_le_bytes(u64_bytes)
}

pub fn compute_u_ary_decomposition(
    number: Scalar,
    base_u: usize,
    base_elements_l: usize,
) -> Vec<Scalar> {
    // these casts are necessary to compute powers and divisions
    // may panic if number does not fit in u64
    // or if base_elements_l doest not fit in u32
    // but this should usually not happen
    let number = scalar_to_u64(number);
    let base_u = u64::try_from(base_u).unwrap();
    let base_elements_l = u32::try_from(base_elements_l).unwrap();

    // the decomposition can only be computed for numbers in [0, base_u^base_elements_l)
    // otherwise it panics
    let upper_bound = base_u.pow(base_elements_l);
    if upper_bound <= number {
        panic!("this number is out of range to compute {}-ary decomposition on {} base elements ([0, {})).", base_u, base_elements_l, upper_bound);
    }

    let mut decomposition: Vec<Scalar> = Vec::new();
    let mut remainder = number;

    for i in (0..base_elements_l).rev() {
        let i_th_pow = base_u.pow(i);
        let i_th_base_element = remainder / i_th_pow;

        decomposition.push(Scalar::from(i_th_base_element));
        remainder %= i_th_pow;
    }

    // make sure that returned vec has actually base_elements_l elements"
    let base_elements_l = usize::try_from(base_elements_l).unwrap();
    assert_eq!(base_elements_l, decomposition.len());

    // decomposition is big endian: base_u^(base_elements_l - 1) | ... | base_u^1 | base_u^0
    decomposition
}

fn pick_signature_for_decomposition_base_element(
    m: &Scalar,
    signatures: &HashMap<RawAttribute, Signature>,
) -> Signature {
    signatures
        .get(&RawAttribute::Number(scalar_to_u64(*m)))
        .unwrap()
        .clone()
}

pub fn pick_signatures_for_decomposition_base_elements(
    decomposition: &Vec<Scalar>,
    signatures: &HashMap<RawAttribute, Signature>,
) -> Vec<Signature> {
    decomposition
        .iter()
        .map(|base_elements_i| {
            pick_signature_for_decomposition_base_element(base_elements_i, signatures)
        })
        .collect()
}

pub fn prove_credential_and_range(
    params: &Parameters,
    verification_key: &VerificationKey,
    sp_verification_key: &VerificationKey,
    signature: &Signature,
    all_range_signatures: &SpSignatures,
    base_u: usize,
    base_elements_l: usize,
    a: Scalar, // lower bound
    b: Scalar, // upper bound
    private_attributes: &[Attribute],
) -> Result<RangeTheta> {
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

    if scalar_to_u64(b) < scalar_to_u64(a) {
        return Err(CoconutError::Verification(
                "Tried to prove a credential with inadequate bounds, make sure a and b are in the correct range and that b is greater or equal to a.".to_string()));
    }

    // use first private attribute for range proof
    let m = private_attributes[0];

    // compute decompositon for m - a and m - b + U^L
    let m_a = compute_u_ary_decomposition(m - a, base_u, base_elements_l);
    let m_b = compute_u_ary_decomposition(
        m - b + Scalar::from((base_u as u64).pow(base_elements_l as u32)),
        base_u,
        base_elements_l,
    );

    let a_a =
        pick_signatures_for_decomposition_base_elements(&m_a, &all_range_signatures.signatures);
    let a_b =
        pick_signatures_for_decomposition_base_elements(&m_b, &all_range_signatures.signatures);

    let (a_prime_a, r_a): (Vec<_>, Vec<_>) = a_a.iter().map(|a| a.randomise(&params)).unzip();
    let (a_prime_b, r_b): (Vec<_>, Vec<_>) = a_b.iter().map(|a| a.randomise(&params)).unzip();

    let (sigma_prime_a, r1) = signature.randomise(&params);
    let (sigma_prime_b, r2) = signature.randomise(&params);

    let kappas_a: Vec<_> = r_a
        .iter()
        .enumerate()
        .map(|(i, r)| compute_kappa(params, sp_verification_key, &m_a[i..], *r))
        .collect();
    let kappas_a = kappas_a.try_into().unwrap();

    let kappas_b: Vec<_> = r_b
        .iter()
        .enumerate()
        .map(|(i, r)| compute_kappa(params, sp_verification_key, &m_b[i..], *r))
        .collect();
    let kappas_b = kappas_b.try_into().unwrap();

    let kappa_a = compute_kappa(params, verification_key, private_attributes, r1);
    let kappa_b = compute_kappa(params, verification_key, private_attributes, r2);

    let pi = RangeProof::construct(
        params,
        verification_key,
        sp_verification_key,
        private_attributes,
        base_u,
        base_elements_l,
        a,
        b,
        &m_a,
        &m_b,
        &r_a,
        &r_b,
        &r1,
        &r2,
    );

    Ok(RangeTheta {
        a,
        b,
        kappas_a,
        kappas_b,
        a_prime_a,
        a_prime_b,
        kappa_a,
        kappa_b,
        sigma_prime_a,
        sigma_prime_b,
        pi,
    })
}

pub fn verify_range_credential(
    params: &Parameters,
    verification_key: &VerificationKey,
    sp_verification_key: &VerificationKey,
    theta: &RangeTheta,
    public_attributes: &[Attribute],
) -> bool {
    if public_attributes.len() + theta.pi.private_attributes() > verification_key.beta.len() {
        return false;
    }

    if !theta.verify_proof(params, verification_key, sp_verification_key) {
        return false;
    }

    for a in &theta.a_prime_a {
        if bool::from(a.0.is_identity()) {
            return false;
        }
    }

    for a in &theta.a_prime_b {
        if bool::from(a.0.is_identity()) {
            return false;
        }
    }

    if bool::from(theta.sigma_prime_a.0.is_identity())
        || bool::from(theta.sigma_prime_b.0.is_identity())
    {
        return false;
    }

    for (a, k) in theta.a_prime_a.iter().zip(&theta.kappas_a) {
        if !check_bilinear_pairing(
            &a.0.to_affine(),
            &G2Prepared::from(k.to_affine()),
            &(a.1).to_affine(),
            params.prepared_miller_g2(),
        ) {
            return false;
        }
    }

    for (a, k) in theta.a_prime_b.iter().zip(&theta.kappas_b) {
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
        &theta.sigma_prime_a.0.to_affine(),
        &G2Prepared::from(theta.kappa_a.to_affine()),
        &(theta.sigma_prime_a.1).to_affine(),
        params.prepared_miller_g2(),
    ) && check_bilinear_pairing(
        &theta.sigma_prime_b.0.to_affine(),
        &G2Prepared::from(theta.kappa_b.to_affine()),
        &(theta.sigma_prime_b.1).to_affine(),
        params.prepared_miller_g2(),
    )
}

#[cfg(test)]
mod tests {
    use crate::scheme::keygen::keygen;
    use crate::scheme::setup::setup;

    use super::*;

    #[test]
    fn compute_u_ary_decomposition_0() {
        let decomposition = compute_u_ary_decomposition(Scalar::from(0));

        assert_eq!([Scalar::from(0); L], decomposition);
    }

    #[test]
    fn compute_u_ary_decomposition_1() {
        let decomposition_1 = compute_u_ary_decomposition(Scalar::from(1));
        let decomposition_2 = compute_u_ary_decomposition(Scalar::from(2));
        let decomposition_3 = compute_u_ary_decomposition(Scalar::from(3));

        let mut decomposition = [Scalar::from(0); L];

        decomposition[0] = Scalar::from(1);
        assert_eq!(decomposition_1, decomposition);

        decomposition[0] = Scalar::from(2);
        assert_eq!(decomposition_2, decomposition);

        decomposition[0] = Scalar::from(3);
        assert_eq!(decomposition_3, decomposition);
    }

    #[test]
    fn compute_u_ary_decomposition_2() {
        let decomposition_4 = compute_u_ary_decomposition(Scalar::from(4));
        let decomposition_9 = compute_u_ary_decomposition(Scalar::from(9));
        let decomposition_14 = compute_u_ary_decomposition(Scalar::from(14));

        let mut decomposition = [Scalar::from(0); L];

        decomposition[0] = Scalar::from(0);
        decomposition[1] = Scalar::from(1);
        assert_eq!(decomposition_4, decomposition);

        decomposition[0] = Scalar::from(1);
        decomposition[1] = Scalar::from(2);
        assert_eq!(decomposition_9, decomposition);

        decomposition[0] = Scalar::from(2);
        decomposition[1] = Scalar::from(3);
        assert_eq!(decomposition_14, decomposition);
    }

    #[test]
    fn compute_u_ary_decomposition_other() {
        let max = (U as u64).pow(L as u32) - 1;

        let decomposition_max = compute_u_ary_decomposition(Scalar::from(max));

        let random = 23456;
        let decomposition_random = compute_u_ary_decomposition(Scalar::from(random));

        let decomposition = [Scalar::from(3); L];
        assert_eq!(decomposition_max, decomposition);

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
        assert_eq!(decomposition_random, decomposition);
    }

    #[test]
    #[should_panic(expected = "number must be in range [0, 2^16)")]
    fn compute_u_ary_decomposition_overflow_panic() {
        let max = (U as u64).pow(L as u32);

        compute_u_ary_decomposition(Scalar::from(max));
    }

    #[test]
    fn compute_u_ary_decomposition_scalar_smaller_than_2_16_tests() {
        assert!(scalar_smaller_than_2_16(Scalar::from(0)));
        assert!(scalar_smaller_than_2_16(Scalar::from(1)));
        assert!(scalar_smaller_than_2_16(Scalar::from(2)));
        assert!(scalar_smaller_than_2_16(Scalar::from(256)));
        assert!(scalar_smaller_than_2_16(Scalar::from(65535)));

        assert!(!scalar_smaller_than_2_16(Scalar::from(65536)));
        assert!(!scalar_smaller_than_2_16(Scalar::from(65537)));
        assert!(!scalar_smaller_than_2_16(Scalar::from(65538)));
        assert!(!scalar_smaller_than_2_16(Scalar::from(u64::MAX)));
    }

    #[test]
    fn compute_u_ary_decomposition_scalar_to_u64_tests() {
        let values = [0, 1, 2, 3, 254, 255, 256, 65534, 65535];

        for v in values {
            assert_eq!(v as u64, scalar_to_u64(Scalar::from(v)));
        }
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
        let private_attributes = [Scalar::from(10)];

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
            &verification_key,
            &sp_verification_key,
            &signature,
            &all_range_signatures,
            a,
            b,
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
        let private_attributes = [[Scalar::from(10)].to_vec(), params.n_random_scalars(9)].concat();

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
            &verification_key,
            &sp_verification_key,
            &signature,
            &all_range_signatures,
            a,
            b,
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
            &verification_key,
            &sp_verification_key,
            &signature,
            &all_range_signatures,
            a,
            b,
            &private_attributes,
        )
        .unwrap();

        assert_eq!(
            RangeTheta::try_from(theta.to_bytes().as_slice()).unwrap(),
            theta
        );
    }
}
