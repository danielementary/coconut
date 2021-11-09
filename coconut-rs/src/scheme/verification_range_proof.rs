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

use bls12_381::{G1Projective, G2Prepared, G2Projective, Scalar};
use group::Curve;
use std::mem::size_of;

use crate::error::{CoconutError, Result};
use crate::proofs::RangeProof;
use crate::scheme::keygen::single_attribute_keygen;
use crate::scheme::setup::Parameters;
use crate::scheme::verification::{check_bilinear_pairing, compute_kappa};
use crate::scheme::verification_set_membership::{issue_membership_signatures, SpSignatures};
use crate::scheme::Signature;
use crate::scheme::VerificationKey;
use crate::traits::{Base58, Bytable};
use crate::utils::RawAttribute;
use crate::utils::{try_deserialize_g2_projective, try_deserialize_scalar};
use crate::Attribute;

// values for u-ary decomposition
// computed according to paper for [0; 2^16) range
// tests depend on these values
pub const U: usize = 4;
pub const L: usize = 8;

const G2PCOMPRESSED_SIZE: usize = 96;
const USIZE_SIZE: usize = size_of::<usize>();
const SCALAR_SIZE: usize = size_of::<Scalar>();
const SIGNATURE_SIZE: usize = 96;

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct RangeTheta {
    pub a: Scalar, // lower bound
    pub b: Scalar, // upper bound
    pub kappas_a: Vec<G2Projective>,
    pub kappas_b: Vec<G2Projective>,
    pub a_prime_a: Vec<Signature>,
    pub a_prime_b: Vec<Signature>,
    pub kappa_a: G2Projective,
    pub kappa_b: G2Projective,
    pub sigma_prime_a: Signature,
    pub sigma_prime_b: Signature,
    pub pi: RangeProof,
}

impl TryFrom<&[u8]> for RangeTheta {
    type Error = CoconutError;

    fn try_from(bytes: &[u8]) -> Result<RangeTheta> {
        let min_size = 2 * SCALAR_SIZE
            + 2 * L * G2PCOMPRESSED_SIZE
            + 2 * L * SIGNATURE_SIZE
            + G2PCOMPRESSED_SIZE
            + SIGNATURE_SIZE;

        let mut p = 0;

        let a_bytes = bytes[p..p + SCALAR_SIZE].try_into().unwrap();
        p += SCALAR_SIZE;

        let a = try_deserialize_scalar(
            &a_bytes,
            CoconutError::Deserialization("failed to deserialize the a".to_string()),
        )?;

        let b_bytes = bytes[p..p + SCALAR_SIZE].try_into().unwrap();
        p += SCALAR_SIZE;

        let b = try_deserialize_scalar(
            &b_bytes,
            CoconutError::Deserialization("failed to deserialize the b".to_string()),
        )?;

        let mut kappas_a: [G2Projective; L] = [G2Projective::default(); L];
        for i in 0..L {
            let kappas_a_i_bytes = bytes[p..p + G2PCOMPRESSED_SIZE].try_into().unwrap();
            kappas_a[i] = try_deserialize_g2_projective(
                &kappas_a_i_bytes,
                CoconutError::Deserialization("failed to deserialize kappas_a".to_string()),
            )?;

            p += G2PCOMPRESSED_SIZE;
        }
        let kappas_a = kappas_a.to_vec();

        let mut kappas_b: [G2Projective; L] = [G2Projective::default(); L];
        for i in 0..L {
            let kappas_b_i_bytes = bytes[p..p + G2PCOMPRESSED_SIZE].try_into().unwrap();
            kappas_b[i] = try_deserialize_g2_projective(
                &kappas_b_i_bytes,
                CoconutError::Deserialization("failed to deserialize kappas_a".to_string()),
            )?;

            p += G2PCOMPRESSED_SIZE;
        }
        let kappas_b = kappas_b.to_vec();

        let mut a_prime_a: [Signature; L] =
            [Signature(G1Projective::default(), G1Projective::default()); L];
        for i in 0..L {
            a_prime_a[i] = Signature::try_from(&bytes[p..p + SIGNATURE_SIZE])?;

            p += G2PCOMPRESSED_SIZE;
        }
        let a_prime_a = a_prime_a.to_vec();

        let mut a_prime_b: [Signature; L] =
            [Signature(G1Projective::default(), G1Projective::default()); L];
        for i in 0..L {
            a_prime_b[i] = Signature::try_from(&bytes[p..p + SIGNATURE_SIZE])?;

            p += G2PCOMPRESSED_SIZE;
        }
        let a_prime_b = a_prime_b.to_vec();

        let kappa_a_bytes = bytes[p..p + SCALAR_SIZE].try_into().unwrap();
        p += SCALAR_SIZE;

        let kappa_a = try_deserialize_g2_projective(
            &kappa_a_bytes,
            CoconutError::Deserialization("failed to deserialize kappa_a".to_string()),
        )?;

        let kappa_b_bytes = bytes[p..p + SCALAR_SIZE].try_into().unwrap();
        p += SCALAR_SIZE;

        let kappa_b = try_deserialize_g2_projective(
            &kappa_b_bytes,
            CoconutError::Deserialization("failed to deserialize kappa_b".to_string()),
        )?;

        let sigma_prime_a = Signature::try_from(&bytes[p..p + SIGNATURE_SIZE])?;
        p += SIGNATURE_SIZE;

        let sigma_prime_b = Signature::try_from(&bytes[p..p + SIGNATURE_SIZE])?;
        p += SIGNATURE_SIZE;

        let pi = RangeProof::from_bytes(&bytes[p..])?;

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
}

impl RangeTheta {
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
            self.a,
            self.b,
            &self.kappas_a,
            &self.kappas_b,
            &self.kappa_a,
            &self.kappa_b,
        )
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let a_bytes = self.a.to_bytes();
        let b_bytes = self.b.to_bytes();
        let kappas_a_bytes = self
            .kappas_a
            .iter()
            .map(|k| k.to_affine().to_compressed())
            .collect::<Vec<_>>();
        let kappas_b_bytes = self
            .kappas_b
            .iter()
            .map(|k| k.to_affine().to_compressed())
            .collect::<Vec<_>>();
        let a_prime_a_bytes = self
            .a_prime_a
            .iter()
            .map(|a| a.to_bytes())
            .collect::<Vec<_>>();
        let a_prime_b_bytes = self
            .a_prime_b
            .iter()
            .map(|a| a.to_bytes())
            .collect::<Vec<_>>();
        let kappa_a_bytes = self.kappa_a.to_affine().to_compressed();
        let kappa_b_bytes = self.kappa_b.to_affine().to_compressed();
        let sigma_prime_a_bytes = self.sigma_prime_a.to_bytes();
        let sigma_prime_b_bytes = self.sigma_prime_b.to_bytes();
        let pi_bytes = self.pi.to_bytes();

        let kappas_a_bytes_len: usize = kappas_a_bytes.iter().map(|e| e.len()).sum();
        let kappas_b_bytes_len: usize = kappas_b_bytes.iter().map(|e| e.len()).sum();
        let a_prime_a_bytes_len: usize = a_prime_a_bytes.iter().map(|e| e.len()).sum();
        let a_prime_b_bytes_len: usize = a_prime_b_bytes.iter().map(|e| e.len()).sum();

        let mut bytes = Vec::with_capacity(
            a_bytes.len()
                + b_bytes.len()
                + kappas_a_bytes_len
                + kappas_b_bytes_len
                + a_prime_a_bytes_len
                + a_prime_b_bytes_len
                + kappa_a_bytes.len()
                + kappa_b_bytes.len()
                + sigma_prime_a_bytes.len()
                + sigma_prime_b_bytes.len()
                + pi_bytes.len(),
        );

        bytes.extend_from_slice(&a_bytes);
        bytes.extend_from_slice(&b_bytes);

        for b in kappas_a_bytes.iter() {
            bytes.extend_from_slice(b);
        }

        for b in kappas_b_bytes.iter() {
            bytes.extend_from_slice(b);
        }

        for b in a_prime_a_bytes.iter() {
            bytes.extend_from_slice(b);
        }

        for b in a_prime_b_bytes.iter() {
            bytes.extend_from_slice(b);
        }

        bytes.extend_from_slice(&kappa_a_bytes);
        bytes.extend_from_slice(&kappa_b_bytes);
        bytes.extend_from_slice(&sigma_prime_a_bytes);
        bytes.extend_from_slice(&sigma_prime_b_bytes);
        bytes.extend_from_slice(&pi_bytes);

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
    let set: Vec<usize> = (0..U).collect();
    let set: Vec<RawAttribute> = set
        .iter()
        .map(|e| RawAttribute::Number(*e as u64))
        .collect();

    issue_membership_signatures(params, &set[..])
}

fn scalar_smaller_than_2_16(number: Scalar) -> bool {
    let number_bytes = number.to_bytes();

    // check that only first 16 bits can be set
    for byte in number_bytes[2..].iter() {
        if *byte != 0 {
            return false;
        }
    }

    true
}

// not the most elegant way of casting a scalar into a single u64
fn scalar_to_u64(number: Scalar) -> u64 {
    let mut u64_bytes: [u8; 8] = [0; 8];
    let number_bytes = number.to_bytes();

    u64_bytes.clone_from_slice(&number_bytes[..8]);

    u64::from_le_bytes(u64_bytes)
}

pub fn compute_u_ary_decomposition(number: Scalar) -> [Scalar; L] {
    let u = U as u64;

    if !scalar_smaller_than_2_16(number) {
        panic!("number must be in range [0, 2^16)");
    }

    let number = scalar_to_u64(number);

    let mut remainder = number;
    let mut decomposition: [Scalar; L] = [Scalar::from(0); L];

    for i in (0..L).rev() {
        let curr_pow = u.pow(i as u32);
        let i_th = remainder / curr_pow as u64;

        remainder %= curr_pow;
        decomposition[i] = Scalar::from(i_th as u64);
    }

    // little-endian
    decomposition
}

#[cfg(test)]
mod tests {
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
}
