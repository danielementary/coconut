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

// use bls12_381::{G2Prepared, G2Projective};
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
const U: usize = 4;
const L: usize = 8;

pub fn compute_u_ary_decomposition(number: u64) -> [u8; L] {
    let u = U as u64;

    let max = u.pow(L as u32);
    if number >= max {
        panic!("number cannot exceed U^L: {}", max);
    }

    let mut remainder = number;
    let mut decomposition = [0; L];

    for i in (0..L).rev() {
        let curr_pow = u.pow(i as u32);
        let i_th = remainder / curr_pow as u64;

        remainder %= curr_pow;
        decomposition[i] = i_th as u8;
    }

    // little-endian
    decomposition
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_u_ary_decomposition_0() {
        let decomposition = compute_u_ary_decomposition(0);

        assert_eq!([0; L], decomposition);
    }

    #[test]
    fn compute_u_ary_decomposition_1() {
        let decomposition_1 = compute_u_ary_decomposition(1);
        let decomposition_2 = compute_u_ary_decomposition(2);
        let decomposition_3 = compute_u_ary_decomposition(3);

        let mut decomposition = [0; L];

        decomposition[0] = 1;
        assert_eq!(decomposition_1, decomposition);

        decomposition[0] = 2;
        assert_eq!(decomposition_2, decomposition);

        decomposition[0] = 3;
        assert_eq!(decomposition_3, decomposition);
    }

    #[test]
    fn compute_u_ary_decomposition_2() {
        let decomposition_4 = compute_u_ary_decomposition(4);
        let decomposition_9 = compute_u_ary_decomposition(9);
        let decomposition_14 = compute_u_ary_decomposition(14);

        let mut decomposition = [0; L];

        decomposition[0] = 0;
        decomposition[1] = 1;
        assert_eq!(decomposition_4, decomposition);

        decomposition[0] = 1;
        decomposition[1] = 2;
        assert_eq!(decomposition_9, decomposition);

        decomposition[0] = 2;
        decomposition[1] = 3;
        assert_eq!(decomposition_14, decomposition);
    }

    #[test]
    fn compute_u_ary_decomposition_other() {
        let max = (U as u64).pow(L as u32) - 1;
        let decomposition_max = compute_u_ary_decomposition(max);

        let random = 23456;
        let decomposition_random = compute_u_ary_decomposition(random);

        let decomposition = [3; L];
        assert_eq!(decomposition_max, decomposition);

        let decomposition = [0, 0, 2, 2, 3, 2, 1, 1];
        assert_eq!(decomposition_random, decomposition);
    }

    #[test]
    #[should_panic(expected = "number cannot exceed U^L: 65536")]
    fn compute_u_ary_decomposition_overflow_panic() {
        let max = (U as u64).pow(L as u32);

        compute_u_ary_decomposition(max);
    }
}
