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

use crate::scheme::keygen::single_attribute_keygen;
use crate::scheme::setup::Parameters;
use crate::scheme::Signature;
use crate::utils::{hash_g1, RawAttribute};
use crate::Attribute;

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
