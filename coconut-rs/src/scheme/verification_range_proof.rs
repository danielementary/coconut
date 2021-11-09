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

// use std::collections::HashMap;

// use std::convert::TryFrom;
// use std::convert::TryInto;

use bls12_381::{G2Prepared, G2Projective, Scalar};
// use group::Curve;

// use crate::error::{CoconutError, Result};
// use crate::proofs::SetMembershipProof;
// use crate::scheme::keygen::single_attribute_keygen;
// use crate::scheme::setup::Parameters;
// use crate::scheme::verification::{check_bilinear_pairing, compute_kappa};
// use crate::scheme::Signature;
// use crate::scheme::VerificationKey;
// use crate::traits::{Base58, Bytable};
// use crate::utils::try_deserialize_g2_projective;
// use crate::utils::RawAttribute;
// use crate::Attribute;

// values for u-ary decomposition
// computed according to paper for [0; 2^16) range
// tests depend on these values
pub const U: usize = 4;
pub const L: usize = 8;

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
