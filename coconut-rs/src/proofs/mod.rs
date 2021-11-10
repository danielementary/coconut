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

// TODO: look at https://crates.io/crates/merlin to perhaps use it instead?

use std::borrow::Borrow;
use std::convert::TryInto;

use bls12_381::{G1Projective, G2Projective, Scalar};
use group::{Curve, GroupEncoding};

use std::mem::size_of;

use digest::generic_array::typenum::Unsigned;
use digest::Digest;
use itertools::izip;
use sha2::Sha256;

use crate::elgamal::Ciphertext;
use crate::error::{CoconutError, Result};
use crate::scheme::setup::Parameters;
use crate::scheme::verification_range_proof::{compute_u_ary_decomposition, L, U};
use crate::scheme::VerificationKey;
use crate::utils::{
    hash_g1, try_deserialize_g2_projective, try_deserialize_scalar, try_deserialize_scalar_vec,
    RawAttribute,
};
use crate::{elgamal, Attribute, ElGamalKeyPair};

// as per the reference python implementation
pub type ChallengeDigest = Sha256;

const G2PCOMPRESSED_SIZE: usize = 96;
const USIZE_SIZE: usize = size_of::<usize>();
const SCALAR_SIZE: usize = size_of::<Scalar>();

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct ProofCmCs {
    challenge: Scalar,
    response_opening: Scalar,
    response_private_elgamal_key: Scalar,
    response_keys: Vec<Scalar>,
    response_attributes: Vec<Scalar>,
}

// note: this is slightly different from the reference python implementation
// as we omit the unnecessary string conversion. Instead we concatenate byte
// representations together and hash that.
// note2: G1 and G2 elements are using their compressed representations
// and as per the bls12-381 library all elements are using big-endian form
/// Generates a Scalar [or Fp] challenge by hashing a number of elliptic curve points.  
pub fn compute_challenge<D, I, B>(iter: I) -> Scalar
where
    D: Digest,
    I: Iterator<Item = B>,
    B: AsRef<[u8]>,
{
    let mut h = D::new();
    for point_representation in iter {
        h.update(point_representation);
    }
    let digest = h.finalize();

    // TODO: I don't like the 0 padding here (though it's what we've been using before,
    // but we never had a security audit anyway...)
    // instead we could maybe use the `from_bytes` variant and adding some suffix
    // when computing the digest until we produce a valid scalar.
    let mut bytes = [0u8; 64];
    let pad_size = 64usize
        .checked_sub(D::OutputSize::to_usize())
        .unwrap_or_default();

    bytes[pad_size..].copy_from_slice(&digest);

    Scalar::from_bytes_wide(&bytes)
}

fn produce_response(witness: &Scalar, challenge: &Scalar, secret: &Scalar) -> Scalar {
    witness - challenge * secret
}

// note: it's caller's responsibility to ensure witnesses.len() = secrets.len()
fn produce_responses<S>(witnesses: &[Scalar], challenge: &Scalar, secrets: &[S]) -> Vec<Scalar>
where
    S: Borrow<Scalar>,
{
    debug_assert_eq!(witnesses.len(), secrets.len());

    witnesses
        .iter()
        .zip(secrets.iter())
        .map(|(w, x)| produce_response(w, challenge, x.borrow()))
        .collect()
}

impl ProofCmCs {
    /// Construct non-interactive zero-knowledge proof of correctness of the ciphertexts and the commitment
    /// using thw Fiat-Shamir heuristic.
    pub(crate) fn construct(
        params: &Parameters,
        elgamal_keypair: &ElGamalKeyPair,
        ephemeral_keys: &[elgamal::EphemeralKey],
        commitment: &G1Projective,
        commitment_opening: &Scalar,
        private_attributes: &[Attribute],
        priv_attributes_ciphertexts: &[Ciphertext],
    ) -> Self {
        // note: this is only called from `prepare_blind_sign` that already checks
        // whether private attributes are non-empty and whether we don't have too many
        // attributes in total to sign.
        // we also know, due to the single call place, that ephemeral_keys.len() == private_attributes.len()

        // witness creation

        let witness_commitment_opening = params.random_scalar();
        let witness_private_elgamal_key = params.random_scalar();
        let witness_keys = params.n_random_scalars(ephemeral_keys.len());
        let witness_attributes = params.n_random_scalars(private_attributes.len());

        // recompute h
        let h = hash_g1(commitment.to_bytes());
        let hs_bytes = params
            .gen_hs()
            .iter()
            .map(|h| h.to_bytes())
            .collect::<Vec<_>>();

        let g1 = params.gen1();

        // compute commitments
        let commitment_private_key_elgamal = g1 * witness_private_elgamal_key;

        // Aw[i] = (wk[i] * g1)
        let commitment_keys1_bytes = witness_keys
            .iter()
            .map(|wk_i| g1 * wk_i)
            .map(|witness| witness.to_bytes())
            .collect::<Vec<_>>();

        // Bw[i] = (wm[i] * h) + (wk[i] * gamma)
        let commitment_keys2_bytes = witness_keys
            .iter()
            .zip(witness_attributes.iter())
            .map(|(wk_i, wm_i)| elgamal_keypair.public_key() * wk_i + h * wm_i)
            .map(|witness| witness.to_bytes())
            .collect::<Vec<_>>();

        // zkp commitment for the attributes commitment cm
        // Ccm = (wr * g1) + (wm[0] * hs[0]) + ... + (wm[i] * hs[i])
        let commitment_attributes = g1 * witness_commitment_opening
            + witness_attributes
                .iter()
                .zip(params.gen_hs().iter())
                .map(|(wm_i, hs_i)| hs_i * wm_i)
                .sum::<G1Projective>();

        let ciphertexts_bytes = priv_attributes_ciphertexts
            .iter()
            .map(|c| c.to_bytes())
            .collect::<Vec<_>>();

        // compute challenge
        let challenge = compute_challenge::<ChallengeDigest, _, _>(
            std::iter::once(params.gen1().to_bytes().as_ref())
                .chain(hs_bytes.iter().map(|hs| hs.as_ref()))
                .chain(std::iter::once(h.to_bytes().as_ref()))
                .chain(std::iter::once(
                    elgamal_keypair.public_key().to_bytes().as_ref(),
                ))
                .chain(std::iter::once(commitment.to_bytes().as_ref()))
                .chain(std::iter::once(commitment_attributes.to_bytes().as_ref()))
                .chain(std::iter::once(
                    commitment_private_key_elgamal.to_bytes().as_ref(),
                ))
                .chain(commitment_keys1_bytes.iter().map(|aw| aw.as_ref()))
                .chain(commitment_keys2_bytes.iter().map(|bw| bw.as_ref()))
                .chain(ciphertexts_bytes.iter().map(|c| c.as_ref())),
        );

        // Responses
        let response_opening =
            produce_response(&witness_commitment_opening, &challenge, &commitment_opening);
        let response_private_elgamal_key = produce_response(
            &witness_private_elgamal_key,
            &challenge,
            &elgamal_keypair.private_key().0,
        );
        let response_keys = produce_responses(&witness_keys, &challenge, ephemeral_keys);
        let response_attributes = produce_responses(
            &witness_attributes,
            &challenge,
            &private_attributes.iter().collect::<Vec<_>>(),
        );

        ProofCmCs {
            challenge,
            response_opening,
            response_private_elgamal_key,
            response_keys,
            response_attributes,
        }
    }

    pub(crate) fn verify(
        &self,
        params: &Parameters,
        pub_key: &elgamal::PublicKey,
        commitment: &G1Projective,
        attributes_ciphertexts: &[elgamal::Ciphertext],
    ) -> bool {
        if self.response_keys.len() != attributes_ciphertexts.len() {
            return false;
        }

        // recompute h
        let h = hash_g1(commitment.to_bytes());
        let g1 = params.gen1();

        let hs_bytes = params
            .gen_hs()
            .iter()
            .map(|h| h.to_bytes())
            .collect::<Vec<_>>();

        // recompute witnesses commitments
        let commitment_private_key_elgamal =
            pub_key * &self.challenge + g1 * self.response_private_elgamal_key;

        // Aw[i] = (c * c1[i]) + (rk[i] * g1)
        let commitment_keys1_bytes = attributes_ciphertexts
            .iter()
            .map(|ciphertext| ciphertext.c1())
            .zip(self.response_keys.iter())
            .map(|(c1, res_k)| c1 * self.challenge + g1 * res_k)
            .map(|witness| witness.to_bytes())
            .collect::<Vec<_>>();

        // Bw[i] = (c * c2[i]) + (rk[i] * gamma) + (rm[i] * h)
        let commitment_keys2_bytes = izip!(
            attributes_ciphertexts
                .iter()
                .map(|ciphertext| ciphertext.c2()),
            self.response_keys.iter(),
            self.response_attributes.iter()
        )
        .map(|(c2, res_key, res_attr)| c2 * self.challenge + pub_key * res_key + h * res_attr)
        .map(|witness| witness.to_bytes())
        .collect::<Vec<_>>();

        // Cw = (cm * c) + (rr * g1) + (rm[0] * hs[0]) + ... + (rm[n] * hs[n])
        let commitment_attributes = commitment * self.challenge
            + g1 * self.response_opening
            + self
                .response_attributes
                .iter()
                .zip(params.gen_hs().iter())
                .map(|(res_attr, hs)| hs * res_attr)
                .sum::<G1Projective>();

        let ciphertexts_bytes = attributes_ciphertexts
            .iter()
            .map(|c| c.to_bytes())
            .collect::<Vec<_>>();

        // re-compute the challenge
        let challenge = compute_challenge::<ChallengeDigest, _, _>(
            std::iter::once(params.gen1().to_bytes().as_ref())
                .chain(hs_bytes.iter().map(|hs| hs.as_ref()))
                .chain(std::iter::once(h.to_bytes().as_ref()))
                .chain(std::iter::once(pub_key.to_bytes().as_ref()))
                .chain(std::iter::once(commitment.to_bytes().as_ref()))
                .chain(std::iter::once(commitment_attributes.to_bytes().as_ref()))
                .chain(std::iter::once(
                    commitment_private_key_elgamal.to_bytes().as_ref(),
                ))
                .chain(commitment_keys1_bytes.iter().map(|aw| aw.as_ref()))
                .chain(commitment_keys2_bytes.iter().map(|bw| bw.as_ref()))
                .chain(ciphertexts_bytes.iter().map(|c| c.as_ref())),
        );

        challenge == self.challenge
    }

    // challenge || rr || rk.len() || rk || rm.len() || rm
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let keys_len = self.response_keys.len() as u64;
        let attributes_len = self.response_attributes.len() as u64;

        let mut bytes = Vec::with_capacity(16 + (keys_len + attributes_len + 3) as usize * 32);

        bytes.extend_from_slice(&self.challenge.to_bytes());
        bytes.extend_from_slice(&self.response_opening.to_bytes());
        bytes.extend_from_slice(&self.response_private_elgamal_key.to_bytes());
        bytes.extend_from_slice(&keys_len.to_le_bytes());

        for rk in &self.response_keys {
            bytes.extend_from_slice(&rk.to_bytes());
        }

        bytes.extend_from_slice(&attributes_len.to_le_bytes());

        for rm in &self.response_attributes {
            bytes.extend_from_slice(&rm.to_bytes());
        }

        bytes
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // at the very minimum there must be a single attribute being proven
        if bytes.len() < 32 * 4 + 16 || (bytes.len() - 16) % 32 != 0 {
            return Err(
                CoconutError::Deserialization(
                    "tried to deserialize proof of ciphertexts and commitment with bytes of invalid length".to_string())
            );
        }

        let mut idx = 0;
        let challenge_bytes = bytes[idx..idx + 32].try_into().unwrap();
        idx += 32;
        let response_opening_bytes = bytes[idx..idx + 32].try_into().unwrap();
        idx += 32;
        let response_private_elgamal_key_bytes = bytes[idx..idx + 32].try_into().unwrap();
        idx += 32;

        let challenge = try_deserialize_scalar(
            &challenge_bytes,
            CoconutError::Deserialization("Failed to deserialize challenge".to_string()),
        )?;
        let response_opening = try_deserialize_scalar(
            &response_opening_bytes,
            CoconutError::Deserialization(
                "Failed to deserialize the response to the random".to_string(),
            ),
        )?;
        let response_private_elgamal_key = try_deserialize_scalar(
            &response_private_elgamal_key_bytes,
            CoconutError::Deserialization(
                "Failed to deserialize the response to the private ElGamal key".to_string(),
            ),
        )?;

        let rk_len = u64::from_le_bytes(bytes[idx..idx + 8].try_into().unwrap());
        idx += 8;
        if bytes[idx..].len() < rk_len as usize * 32 + 8 {
            return Err(
                CoconutError::Deserialization(
                    "tried to deserialize proof of ciphertexts and commitment with insufficient number of bytes provided".to_string()),
            );
        }

        let rk_end = idx + rk_len as usize * 32;
        let response_keys = try_deserialize_scalar_vec(
            rk_len,
            &bytes[idx..rk_end],
            CoconutError::Deserialization("Failed to deserialize keys response".to_string()),
        )?;

        let rm_len = u64::from_le_bytes(bytes[rk_end..rk_end + 8].try_into().unwrap());
        let response_attributes = try_deserialize_scalar_vec(
            rm_len,
            &bytes[rk_end + 8..],
            CoconutError::Deserialization("Failed to deserialize attributes response".to_string()),
        )?;

        Ok(ProofCmCs {
            challenge,
            response_opening,
            response_private_elgamal_key,
            response_keys,
            response_attributes,
        })
    }
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct ProofKappaNu {
    // c
    challenge: Scalar,

    // rm
    response_attributes: Vec<Scalar>,

    // TODO NAMING: blinder or blinding factor?
    // rt
    response_blinder: Scalar,
}

impl ProofKappaNu {
    pub(crate) fn construct(
        params: &Parameters,
        verification_key: &VerificationKey,
        private_attributes: &[Attribute],
        blinding_factor: &Scalar,
        blinded_message: &G2Projective,
    ) -> Self {
        // create the witnesses
        let witness_blinder = params.random_scalar();
        let witness_attributes = params.n_random_scalars(private_attributes.len());

        let beta_bytes = verification_key
            .beta
            .iter()
            .map(|beta_i| beta_i.to_bytes())
            .collect::<Vec<_>>();

        // witnesses commitments
        // Aw = g2 * wt + alpha + beta[0] * wm[0] + ... + beta[i] * wm[i]
        let commitment_kappa = params.gen2() * witness_blinder
            + verification_key.alpha
            + witness_attributes
                .iter()
                .zip(verification_key.beta.iter())
                .map(|(wm_i, beta_i)| beta_i * wm_i)
                .sum::<G2Projective>();

        let challenge = compute_challenge::<ChallengeDigest, _, _>(
            std::iter::once(params.gen2().to_bytes().as_ref())
                .chain(std::iter::once(blinded_message.to_bytes().as_ref())) //kappa
                .chain(std::iter::once(verification_key.alpha.to_bytes().as_ref()))
                .chain(beta_bytes.iter().map(|b| b.as_ref()))
                .chain(std::iter::once(commitment_kappa.to_bytes().as_ref())),
        );

        // responses
        let response_blinder = produce_response(&witness_blinder, &challenge, &blinding_factor);
        let response_attributes =
            produce_responses(&witness_attributes, &challenge, private_attributes);

        ProofKappaNu {
            challenge,
            response_attributes,
            response_blinder,
        }
    }

    pub(crate) fn private_attributes(&self) -> usize {
        self.response_attributes.len()
    }

    pub(crate) fn verify(
        &self,
        params: &Parameters,
        verification_key: &VerificationKey,
        kappa: &G2Projective,
    ) -> bool {
        let beta_bytes = verification_key
            .beta
            .iter()
            .map(|beta_i| beta_i.to_bytes())
            .collect::<Vec<_>>();

        // re-compute witnesses commitments
        // Aw = (c * kappa) + (rt * g2) + ((1 - c) * alpha) + (rm[0] * beta[0]) + ... + (rm[i] * beta[i])
        let commitment_kappa = kappa * self.challenge
            + params.gen2() * self.response_blinder
            + verification_key.alpha * (Scalar::one() - self.challenge)
            + self
                .response_attributes
                .iter()
                .zip(verification_key.beta.iter())
                .map(|(priv_attr, beta_i)| beta_i * priv_attr)
                .sum::<G2Projective>();

        // Bw = (c * nu) + (rt * h)
        // let commitment_blinder = nu * self.challenge + signature.sig1() * self.response_blinder;

        // compute the challenge
        let challenge = compute_challenge::<ChallengeDigest, _, _>(
            std::iter::once(params.gen2().to_bytes().as_ref())
                .chain(std::iter::once(kappa.to_bytes().as_ref())) //kappa
                .chain(std::iter::once(verification_key.alpha.to_bytes().as_ref()))
                .chain(beta_bytes.iter().map(|b| b.as_ref()))
                .chain(std::iter::once(commitment_kappa.to_bytes().as_ref())),
        );

        challenge == self.challenge
    }

    // challenge || rm.len() || rm || rt
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let attributes_len = self.response_attributes.len() as u64;

        let mut bytes = Vec::with_capacity(8 + (attributes_len + 1) as usize * 32);

        bytes.extend_from_slice(&self.challenge.to_bytes());

        bytes.extend_from_slice(&attributes_len.to_le_bytes());
        for rm in &self.response_attributes {
            bytes.extend_from_slice(&rm.to_bytes());
        }

        bytes.extend_from_slice(&self.response_blinder.to_bytes());

        bytes
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // at the very minimum there must be a single attribute being proven
        if bytes.len() < 32 * 3 + 8 || (bytes.len() - 8) % 32 != 0 {
            return Err(CoconutError::DeserializationInvalidLength {
                actual: bytes.len(),
                modulus_target: bytes.len() - 8,
                modulus: 32,
                object: "kappa and nu".to_string(),
                target: 32 * 3 + 8,
            });
        }

        let challenge_bytes = bytes[..32].try_into().unwrap();
        let challenge = try_deserialize_scalar(
            &challenge_bytes,
            CoconutError::Deserialization("Failed to deserialize challenge".to_string()),
        )?;

        let rm_len = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
        if bytes[40..].len() != (rm_len + 1) as usize * 32 {
            return Err(
                CoconutError::Deserialization(
                    format!("Tried to deserialize proof of kappa and nu with insufficient number of bytes provided, expected {} got {}.", (rm_len + 1) as usize * 32, bytes[40..].len())
                )
            );
        }

        let rm_end = 40 + rm_len as usize * 32;
        let response_attributes = try_deserialize_scalar_vec(
            rm_len,
            &bytes[40..rm_end],
            CoconutError::Deserialization("Failed to deserialize attributes response".to_string()),
        )?;

        let blinder_bytes = bytes[rm_end..].try_into().unwrap();
        let response_blinder = try_deserialize_scalar(
            &blinder_bytes,
            CoconutError::Deserialization("failed to deserialize the blinder".to_string()),
        )?;

        Ok(ProofKappaNu {
            challenge,
            response_attributes,
            response_blinder,
        })
    }
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct SetMembershipProof {
    challenge: Scalar, // to remove later after testing
    kappa_1_prime: G2Projective,
    kappa_2_prime: G2Projective,
    s_mi: Vec<Scalar>,
    s_r1: Scalar,
    s_r2: Scalar,
}

impl SetMembershipProof {
    pub(crate) fn construct(
        params: &Parameters,
        verification_key: &VerificationKey,
        sp_verification_key: &VerificationKey,
        private_attributes: &[Attribute],
        r1: &Scalar,
        r2: &Scalar,
    ) -> Self {
        // pick random witnesses
        let r_r1 = params.random_scalar();
        let r_r2 = params.random_scalar();
        let r_mi = params.n_random_scalars(private_attributes.len());

        // kappa_1' = g2 * r_r1 + alpha_P + beta_P * r_mi[0]
        let kappa_1_prime = params.gen2() * r_r1
            + sp_verification_key.alpha
            + sp_verification_key.beta[0] * r_mi[0];

        // kappa_2' = g2 * r_r2 + alpha + beta[0] * r_mi[0] + ... + beta[i] * r_mi[i]
        let kappa_2_prime = params.gen2() * r_r2
            + verification_key.alpha
            + r_mi
                .iter()
                .zip(verification_key.beta.iter())
                .map(|(r_mi, beta_i)| beta_i * r_mi)
                .sum::<G2Projective>();

        let beta_bytes = verification_key
            .beta
            .iter()
            .map(|beta_i| beta_i.to_bytes())
            .collect::<Vec<_>>();

        // compute challenge: H(kappa_1', kappa_2', g2, alpha_P, beta_P, alpha, betas)
        let challenge = compute_challenge::<ChallengeDigest, _, _>(
            std::iter::once(kappa_1_prime.to_bytes().as_ref())
                .chain(std::iter::once(kappa_2_prime.to_bytes().as_ref()))
                .chain(std::iter::once(params.gen2().to_bytes().as_ref()))
                .chain(std::iter::once(
                    sp_verification_key.alpha.to_bytes().as_ref(),
                ))
                .chain(std::iter::once(
                    sp_verification_key.beta[0].to_bytes().as_ref(),
                ))
                .chain(std::iter::once(verification_key.alpha.to_bytes().as_ref()))
                .chain(beta_bytes.iter().map(|b| b.as_ref())),
        );

        // responses
        let s_r1 = produce_response(&r_r1, &challenge, &r1);
        let s_r2 = produce_response(&r_r2, &challenge, &r2);
        let s_mi = produce_responses(&r_mi, &challenge, private_attributes);

        SetMembershipProof {
            challenge,
            kappa_1_prime,
            kappa_2_prime,
            s_mi,
            s_r1,
            s_r2,
        }
    }

    pub(crate) fn private_attributes(&self) -> usize {
        self.s_mi.len()
    }

    pub(crate) fn verify(
        &self,
        params: &Parameters,
        verification_key: &VerificationKey,
        sp_verification_key: &VerificationKey,
        kappa_1: &G2Projective,
        kappa_2: &G2Projective,
    ) -> bool {
        let beta_bytes = verification_key
            .beta
            .iter()
            .map(|beta_i| beta_i.to_bytes())
            .collect::<Vec<_>>();

        // recompute challenge: H(kappa_1', kappa_2', g2, alpha_P, beta_P, alpha, betas)
        let challenge = compute_challenge::<ChallengeDigest, _, _>(
            std::iter::once(self.kappa_1_prime.to_bytes().as_ref())
                .chain(std::iter::once(self.kappa_2_prime.to_bytes().as_ref()))
                .chain(std::iter::once(params.gen2().to_bytes().as_ref()))
                .chain(std::iter::once(
                    sp_verification_key.alpha.to_bytes().as_ref(),
                ))
                .chain(std::iter::once(
                    sp_verification_key.beta[0].to_bytes().as_ref(),
                ))
                .chain(std::iter::once(verification_key.alpha.to_bytes().as_ref()))
                .chain(beta_bytes.iter().map(|b| b.as_ref())),
        );

        // to remove after test
        assert_eq!(challenge, self.challenge);

        let kappa_1_lhs = sp_verification_key.alpha * (-Scalar::one()) + self.kappa_1_prime;
        let kappa_1_rhs = (sp_verification_key.alpha * (-Scalar::one()) + kappa_1) * challenge
            + params.gen2() * self.s_r1
            + sp_verification_key.beta[0] * self.s_mi[0];

        let kappa_2_lhs = verification_key.alpha * (-Scalar::one()) + self.kappa_2_prime;
        let kappa_2_rhs = (verification_key.alpha * (-Scalar::one()) + kappa_2) * challenge
            + params.gen2() * self.s_r2
            + verification_key
                .beta
                .iter()
                .zip(self.s_mi.iter())
                .map(|(beta, s_m)| beta * s_m)
                .sum::<G2Projective>();

        kappa_1_lhs == kappa_1_rhs && kappa_2_lhs == kappa_2_rhs
    }

    // kappa_1_prime || kappa_2_prime || s_mi.len() || s_mi || s_r1 || s_r2 || challenge
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let total_size = 2 * G2PCOMPRESSED_SIZE
            + USIZE_SIZE
            + self.s_mi.len() * SCALAR_SIZE
            + 2 * SCALAR_SIZE
            + SCALAR_SIZE;

        let mut bytes = Vec::with_capacity(total_size);

        bytes.extend_from_slice(&self.kappa_1_prime.to_affine().to_compressed());
        bytes.extend_from_slice(&self.kappa_2_prime.to_affine().to_compressed());

        bytes.extend_from_slice(&self.s_mi.len().to_le_bytes());
        for s_mi in &self.s_mi {
            bytes.extend_from_slice(&s_mi.to_bytes());
        }

        bytes.extend_from_slice(&self.s_r1.to_bytes());
        bytes.extend_from_slice(&self.s_r2.to_bytes());

        bytes.extend_from_slice(&self.challenge.to_bytes());

        bytes
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let min_size =
            2 * G2PCOMPRESSED_SIZE + USIZE_SIZE + SCALAR_SIZE + 2 * SCALAR_SIZE + SCALAR_SIZE;

        if bytes.len() < min_size || (bytes.len() - min_size) % SCALAR_SIZE != 0 {
            return Err(CoconutError::DeserializationInvalidLength {
                actual: bytes.len(),
                modulus_target: bytes.len() - min_size,
                modulus: SCALAR_SIZE,
                object: "kappa_1', kappa_2', s_mi, s_r1, s_r2".to_string(),
                target: min_size,
            });
        }

        let kappa_1_prime_bytes = bytes[..G2PCOMPRESSED_SIZE].try_into().unwrap();
        let mut p = G2PCOMPRESSED_SIZE;

        let kappa_1_prime = try_deserialize_g2_projective(
            &kappa_1_prime_bytes,
            CoconutError::Deserialization("failed to deserialize kappa_1'".to_string()),
        )?;

        let kappa_2_prime_bytes = bytes[p..p + G2PCOMPRESSED_SIZE].try_into().unwrap();
        p += G2PCOMPRESSED_SIZE;

        let kappa_2_prime = try_deserialize_g2_projective(
            &kappa_2_prime_bytes,
            CoconutError::Deserialization("failed to deserialize kappa_2'".to_string()),
        )?;

        let s_mi_len = u64::from_le_bytes(bytes[p..p + USIZE_SIZE].try_into().unwrap());
        p += USIZE_SIZE;

        let p_temp = p + (s_mi_len as usize) * SCALAR_SIZE;
        let s_mi = try_deserialize_scalar_vec(
            s_mi_len,
            &bytes[p..p_temp],
            CoconutError::Deserialization("Failed to deserialize s_mi".to_string()),
        )?;
        p = p_temp;

        let s_r1_bytes = bytes[p..p + SCALAR_SIZE].try_into().unwrap();
        p += SCALAR_SIZE;

        let s_r1 = try_deserialize_scalar(
            &s_r1_bytes,
            CoconutError::Deserialization("failed to deserialize the s_r1".to_string()),
        )?;

        let s_r2_bytes = bytes[p..p + SCALAR_SIZE].try_into().unwrap();
        p += SCALAR_SIZE;

        let s_r2 = try_deserialize_scalar(
            &s_r2_bytes,
            CoconutError::Deserialization("failed to deserialize the s_r2".to_string()),
        )?;

        let challenge_bytes = bytes[p..].try_into().unwrap();

        let challenge = try_deserialize_scalar(
            &challenge_bytes,
            CoconutError::Deserialization("failed to deserialize the challenge".to_string()),
        )?;

        Ok(SetMembershipProof {
            challenge,
            kappa_1_prime,
            kappa_2_prime,
            s_mi,
            s_r1,
            s_r2,
        })
    }
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct RangeProof {
    challenge: Scalar, // to remove later after testing
    kappas_a_prime: Vec<G2Projective>,
    kappas_b_prime: Vec<G2Projective>,
    kappa_a_prime: G2Projective,
    kappa_b_prime: G2Projective,
    s_m_a: Vec<Scalar>,
    s_m_b: Vec<Scalar>,
    s_r_a: Vec<Scalar>,
    s_r_b: Vec<Scalar>,
    s_m: Vec<Scalar>,
    s_r1: Scalar,
    s_r2: Scalar,
}

impl RangeProof {
    pub(crate) fn construct(
        params: &Parameters,
        verification_key: &VerificationKey,
        sp_verification_key: &VerificationKey,
        private_attributes: &[Attribute],
        a: Scalar, // lower bound
        b: Scalar, // upper bound
        m_a: &[Scalar; L],
        m_b: &[Scalar; L],
        r_a: &[Scalar; L],
        r_b: &[Scalar; L],
        r1: &Scalar,
        r2: &Scalar,
    ) -> Self {
        // pick random values for each witness
        let r_m = params.n_random_scalars(private_attributes.len() - 1);

        let r_m_a = params.n_random_scalars(L);
        let r_m_b = params.n_random_scalars(L);

        let r_r_a = params.n_random_scalars(L);
        let r_r_b = params.n_random_scalars(L);
        let r_r1 = params.random_scalar();
        let r_r2 = params.random_scalar();

        // recompute values with corresponding random values
        let kappas_a_prime: Vec<G2Projective> = r_r_a
            .iter()
            .zip(r_m_a.iter())
            .map(|(r, m)| {
                params.gen2() * r + sp_verification_key.alpha + sp_verification_key.beta[0] * m
            })
            .collect();

        let kappas_b_prime: Vec<G2Projective> = r_r_b
            .iter()
            .zip(r_m_b.iter())
            .map(|(r, m)| {
                params.gen2() * r + sp_verification_key.alpha + sp_verification_key.beta[0] * m
            })
            .collect();

        let beta1 = verification_key.beta[0];

        let mut kappa_a_prime: G2Projective = params.gen2() * r_r1
            + verification_key.alpha
            + beta1 * a
            + r_m_a
                .iter()
                .enumerate()
                .map(|(i, r_m)| beta1 * r_m * (Scalar::from((U as u64).pow(i as u32))))
                .sum::<G2Projective>();

        let mut kappa_b_prime: G2Projective = params.gen2() * r_r2
            + verification_key.alpha
            + beta1 * (b - Scalar::from((U as u64).pow(L as u32)))
            + r_m_b
                .iter()
                .enumerate()
                .map(|(i, r_m)| beta1 * r_m * (Scalar::from((U as u64).pow(i as u32))))
                .sum::<G2Projective>();

        if private_attributes.len() > 1 {
            let partial_kappa: G2Projective = r_m[1..]
                .iter()
                .zip(verification_key.beta[1..].iter())
                .map(|(r_mi, beta_i)| beta_i * r_mi)
                .sum();

            kappa_a_prime += partial_kappa;
            kappa_b_prime += partial_kappa;
        }

        let kappas_a_prime_bytes = kappas_a_prime
            .iter()
            .map(|k| k.to_bytes())
            .collect::<Vec<_>>();

        let kappas_b_prime_bytes = kappas_b_prime
            .iter()
            .map(|k| k.to_bytes())
            .collect::<Vec<_>>();

        let beta_bytes = verification_key.beta[1..]
            .iter()
            .map(|b| b.to_bytes())
            .collect::<Vec<_>>();

        // derive challenge
        let challenge = compute_challenge::<ChallengeDigest, _, _>(
            kappas_a_prime_bytes
                .iter()
                .map(|b| b.as_ref())
                .chain(kappas_b_prime_bytes.iter().map(|b| b.as_ref()))
                .chain(std::iter::once(kappa_a_prime.to_bytes().as_ref()))
                .chain(std::iter::once(kappa_b_prime.to_bytes().as_ref()))
                .chain(std::iter::once(params.gen2().to_bytes().as_ref()))
                .chain(std::iter::once(
                    sp_verification_key.alpha.to_bytes().as_ref(),
                ))
                .chain(std::iter::once(
                    sp_verification_key.beta[0].to_bytes().as_ref(),
                ))
                .chain(std::iter::once(verification_key.alpha.to_bytes().as_ref()))
                .chain(beta_bytes.iter().map(|b| b.as_ref())),
        );

        // compute responses
        let s_m_a = produce_responses(&r_m_a, &challenge, m_a);
        let s_m_b = produce_responses(&r_m_b, &challenge, m_b);

        let s_r_a = produce_responses(&r_r_a, &challenge, r_a);
        let s_r_b = produce_responses(&r_r_b, &challenge, r_b);

        let s_m = produce_responses(&r_m, &challenge, &private_attributes[1..]);
        let s_r1 = produce_response(&r_r1, &challenge, r1);
        let s_r2 = produce_response(&r_r2, &challenge, r2);

        RangeProof {
            challenge,
            kappas_a_prime,
            kappas_b_prime,
            kappa_a_prime,
            kappa_b_prime,
            s_m_a,
            s_m_b,
            s_r_a,
            s_r_b,
            s_m,
            s_r1,
            s_r2,
        }
    }

    pub(crate) fn private_attributes(&self) -> usize {
        self.s_m.len()
    }

    pub(crate) fn verify(
        &self,
        params: &Parameters,
        verification_key: &VerificationKey,
        sp_verification_key: &VerificationKey,
        a: Scalar, // lower bound
        b: Scalar, // upper bound
        kappas_a: &[G2Projective],
        kappas_b: &[G2Projective],
        kappa_a: &G2Projective,
        kappa_b: &G2Projective,
    ) -> bool {
        let kappas_a_prime_bytes = self
            .kappas_a_prime
            .iter()
            .map(|k| k.to_bytes())
            .collect::<Vec<_>>();

        let kappas_b_prime_bytes = self
            .kappas_b_prime
            .iter()
            .map(|k| k.to_bytes())
            .collect::<Vec<_>>();

        let beta_bytes = verification_key.beta[1..]
            .iter()
            .map(|b| b.to_bytes())
            .collect::<Vec<_>>();

        // recompute challenge
        let challenge = compute_challenge::<ChallengeDigest, _, _>(
            kappas_a_prime_bytes
                .iter()
                .map(|b| b.as_ref())
                .chain(kappas_b_prime_bytes.iter().map(|b| b.as_ref()))
                .chain(std::iter::once(self.kappa_a_prime.to_bytes().as_ref()))
                .chain(std::iter::once(self.kappa_b_prime.to_bytes().as_ref()))
                .chain(std::iter::once(params.gen2().to_bytes().as_ref()))
                .chain(std::iter::once(
                    sp_verification_key.alpha.to_bytes().as_ref(),
                ))
                .chain(std::iter::once(
                    sp_verification_key.beta[0].to_bytes().as_ref(),
                ))
                .chain(std::iter::once(verification_key.alpha.to_bytes().as_ref()))
                .chain(beta_bytes.iter().map(|b| b.as_ref())),
        );

        // to remove after test
        assert_eq!(challenge, self.challenge);

        let kappas_a_lhs = self
            .kappas_a_prime
            .iter()
            .map(|k| sp_verification_key.alpha * (-Scalar::one()) + k)
            .collect::<Vec<_>>();

        let kappas_b_lhs = self
            .kappas_b_prime
            .iter()
            .map(|k| sp_verification_key.alpha * (-Scalar::one()) + k)
            .collect::<Vec<_>>();

        let kappas_a_rhs = izip!(kappas_a, &self.s_r_a, &self.s_m_a)
            .map(|(k, r, m)| {
                (sp_verification_key.alpha * (-Scalar::one()) + k) * challenge
                    + params.gen2() * r
                    + sp_verification_key.beta[0] * m
            })
            .collect::<Vec<_>>();

        let kappas_b_rhs = izip!(kappas_b, &self.s_r_b, &self.s_m_b)
            .map(|(k, r, m)| {
                (sp_verification_key.alpha * (-Scalar::one()) + k) * challenge
                    + params.gen2() * r
                    + sp_verification_key.beta[0] * m
            })
            .collect::<Vec<_>>();

        let beta1 = verification_key.beta[0];

        let kappa_a_lhs = sp_verification_key.alpha * (-Scalar::one()) + self.kappa_a_prime;
        let mut kappa_a_rhs = (sp_verification_key.alpha * (-Scalar::one()) + kappa_a) * challenge
            + params.gen2() * self.s_r1
            + beta1 * a
            + beta1
            + beta1 * (-challenge)
            + self
                .s_m_a
                .iter()
                .enumerate()
                .map(|(i, s_m)| beta1 * s_m * (Scalar::from((U as u64).pow(i as u32))))
                .sum::<G2Projective>();

        let beta1_b_ul = beta1 * b + beta1 * (-Scalar::from((U as u64).pow(L as u32)));

        let kappa_b_lhs = sp_verification_key.alpha * (-Scalar::one()) + self.kappa_b_prime;
        let mut kappa_b_rhs = (sp_verification_key.alpha * (-Scalar::one()) + kappa_b) * challenge
            + params.gen2() * self.s_r2
            + beta1_b_ul
            + beta1_b_ul * (-challenge)
            + self
                .s_m_b
                .iter()
                .enumerate()
                .map(|(i, s_m)| beta1 * s_m * (Scalar::from((U as u64).pow(i as u32))))
                .sum::<G2Projective>();

        if self.s_m.len() > 1 {
            let partial_kappa: G2Projective = self.s_m[1..]
                .iter()
                .zip(verification_key.beta[1..].iter())
                .map(|(s_mi, beta_i)| beta_i * s_mi)
                .sum();

            kappa_a_rhs += partial_kappa;
            kappa_b_rhs += partial_kappa;
        }

        kappas_a_lhs == kappas_a_rhs
            && kappas_b_lhs == kappas_b_rhs
            && kappa_a_lhs == kappa_a_rhs
            && kappa_b_lhs == kappa_b_rhs
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let total_size = 2 * (L + 1) * G2PCOMPRESSED_SIZE
            + 4 * L * SCALAR_SIZE
            + self.s_m.len() * SCALAR_SIZE
            + SCALAR_SIZE
            + SCALAR_SIZE;

        let mut bytes = Vec::with_capacity(total_size);

        for k in &self.kappas_a_prime {
            bytes.extend_from_slice(&k.to_affine().to_compressed());
        }

        for k in &self.kappas_b_prime {
            bytes.extend_from_slice(&k.to_affine().to_compressed());
        }

        bytes.extend_from_slice(&self.kappa_a_prime.to_affine().to_compressed());
        bytes.extend_from_slice(&self.kappa_b_prime.to_affine().to_compressed());

        for s in &self.s_m_a {
            bytes.extend_from_slice(&s.to_bytes());
        }

        for s in &self.s_m_b {
            bytes.extend_from_slice(&s.to_bytes());
        }

        for s in &self.s_r_a {
            bytes.extend_from_slice(&s.to_bytes());
        }

        for s in &self.s_r_b {
            bytes.extend_from_slice(&s.to_bytes());
        }

        bytes.extend_from_slice(&self.s_m.len().to_le_bytes());
        for m in &self.s_m {
            bytes.extend_from_slice(&m.to_bytes());
        }

        bytes.extend_from_slice(&self.s_r1.to_bytes());
        bytes.extend_from_slice(&self.s_r2.to_bytes());

        bytes
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let min_size = 2 * (L + 1) * G2PCOMPRESSED_SIZE
            + 4 * L * SCALAR_SIZE
            + SCALAR_SIZE
            + SCALAR_SIZE
            + SCALAR_SIZE
            + SCALAR_SIZE;

        if bytes.len() < min_size || (bytes.len() - min_size) % SCALAR_SIZE != 0 {
            return Err(CoconutError::DeserializationInvalidLength {
                actual: bytes.len(),
                modulus_target: bytes.len() - min_size,
                modulus: SCALAR_SIZE,
                object:
                    "kappas_a', kappas_b', kappa_a', kappa_b', s_m_a, s_m_b, s_r_a, s_r_b, s_m, s_r1, s_r2"
                        .to_string(),
                target: min_size,
            });
        }

        let mut p = 0;

        let mut kappas_a_prime: [G2Projective; L] = [G2Projective::default(); L];
        for i in 0..L {
            let kappas_a_prime_i_bytes = bytes[p..p + G2PCOMPRESSED_SIZE].try_into().unwrap();
            kappas_a_prime[i] = try_deserialize_g2_projective(
                &kappas_a_prime_i_bytes,
                CoconutError::Deserialization("failed to deserialize kappas_a_prime".to_string()),
            )?;

            p += G2PCOMPRESSED_SIZE;
        }
        let kappas_a_prime = kappas_a_prime.to_vec();

        let mut kappas_b_prime: [G2Projective; L] = [G2Projective::default(); L];
        for i in 0..L {
            let kappas_b_prime_i_bytes = bytes[p..p + G2PCOMPRESSED_SIZE].try_into().unwrap();
            kappas_b_prime[i] = try_deserialize_g2_projective(
                &kappas_b_prime_i_bytes,
                CoconutError::Deserialization("failed to deserialize kappas_b_prime".to_string()),
            )?;

            p += G2PCOMPRESSED_SIZE;
        }
        let kappas_b_prime = kappas_b_prime.to_vec();

        let kappa_a_prime_bytes = bytes[p..p + G2PCOMPRESSED_SIZE].try_into().unwrap();
        p += G2PCOMPRESSED_SIZE;

        let kappa_a_prime = try_deserialize_g2_projective(
            &kappa_a_prime_bytes,
            CoconutError::Deserialization("failed to deserialize kappa_a'".to_string()),
        )?;

        let kappa_b_prime_bytes = bytes[p..p + G2PCOMPRESSED_SIZE].try_into().unwrap();
        p += G2PCOMPRESSED_SIZE;

        let kappa_b_prime = try_deserialize_g2_projective(
            &kappa_b_prime_bytes,
            CoconutError::Deserialization("failed to deserialize kappa_b'".to_string()),
        )?;

        let p_next = p + L * SCALAR_SIZE;
        let s_m_a = try_deserialize_scalar_vec(
            L as u64,
            &bytes[p..p_next],
            CoconutError::Deserialization("Failed to deserialize s_m_a".to_string()),
        )?;
        p = p_next;

        let p_next = p + L * SCALAR_SIZE;
        let s_m_b = try_deserialize_scalar_vec(
            L as u64,
            &bytes[p..p_next],
            CoconutError::Deserialization("Failed to deserialize s_m_b".to_string()),
        )?;
        p = p_next;

        let p_next = p + L * SCALAR_SIZE;
        let s_r_a = try_deserialize_scalar_vec(
            L as u64,
            &bytes[p..p_next],
            CoconutError::Deserialization("Failed to deserialize s_r_a".to_string()),
        )?;
        p = p_next;

        let p_next = p + L * SCALAR_SIZE;
        let s_r_b = try_deserialize_scalar_vec(
            L as u64,
            &bytes[p..p_next],
            CoconutError::Deserialization("Failed to deserialize s_r_b".to_string()),
        )?;
        p = p_next;

        let s_m_len = u64::from_le_bytes(bytes[p..p + USIZE_SIZE].try_into().unwrap());
        p += USIZE_SIZE;

        let p_temp = p + (s_m_len as usize) * SCALAR_SIZE;
        let s_m = try_deserialize_scalar_vec(
            s_m_len,
            &bytes[p..p_temp],
            CoconutError::Deserialization("Failed to deserialize s_m".to_string()),
        )?;
        p = p_temp;

        let s_r1_bytes = bytes[p..p + SCALAR_SIZE].try_into().unwrap();
        p += SCALAR_SIZE;

        let s_r1 = try_deserialize_scalar(
            &s_r1_bytes,
            CoconutError::Deserialization("failed to deserialize the s_r1".to_string()),
        )?;

        let s_r2_bytes = bytes[p..p + SCALAR_SIZE].try_into().unwrap();
        p += SCALAR_SIZE;

        let s_r2 = try_deserialize_scalar(
            &s_r2_bytes,
            CoconutError::Deserialization("failed to deserialize the s_r2".to_string()),
        )?;

        let challenge_bytes = bytes[p..].try_into().unwrap();
        let challenge = try_deserialize_scalar(
            &challenge_bytes,
            CoconutError::Deserialization("failed to deserialize the challenge".to_string()),
        )?;

        Ok(RangeProof {
            challenge,
            kappas_a_prime,
            kappas_b_prime,
            kappa_a_prime,
            kappa_b_prime,
            s_m_a,
            s_m_b,
            s_r_a,
            s_r_b,
            s_m,
            s_r1,
            s_r2,
        })
    }
}

// proof builder:
// - commitment
// - challenge
// - responses

#[cfg(test)]
mod tests {
    use crate::Signature;
    use group::Group;
    use rand::thread_rng;

    use crate::scheme::issuance::{compute_attribute_encryption, compute_commitment_hash};
    use crate::scheme::keygen::{keygen, single_attribute_keygen};
    use crate::scheme::setup::setup;
    use crate::scheme::verification::compute_kappa;
    use crate::scheme::verification_set_membership::issue_membership_signatures;

    use crate::utils::RawAttribute;

    use super::*;

    #[test]
    fn proof_cm_cs_bytes_roundtrip() {
        let mut rng = thread_rng();
        let mut params = setup(1).unwrap();

        let elgamal_keypair = elgamal::elgamal_keygen(&params);
        let private_attributes = params.n_random_scalars(1);
        let _public_attributes = params.n_random_scalars(0);

        // we don't care about 'correctness' of the proof. only whether we can correctly recover it from bytes
        let cm = G1Projective::random(&mut rng);
        let r = params.random_scalar();

        let commitment_hash = compute_commitment_hash(cm);
        let (attributes_ciphertexts, _ephemeral_keys): (Vec<_>, Vec<_>) =
            compute_attribute_encryption(
                &params,
                private_attributes.as_ref(),
                elgamal_keypair.public_key(),
                commitment_hash,
            );
        let ephemeral_keys = params.n_random_scalars(1);

        // 0 public 1 private
        let pi_s = ProofCmCs::construct(
            &mut params,
            &elgamal_keypair,
            &ephemeral_keys,
            &cm,
            &r,
            &private_attributes,
            &*attributes_ciphertexts,
        );

        let bytes = pi_s.to_bytes();
        assert_eq!(ProofCmCs::from_bytes(&bytes).unwrap(), pi_s);

        // 2 public 2 private
        let private_attributes = params.n_random_scalars(2);
        let _public_attributes = params.n_random_scalars(2);
        let ephemeral_keys = params.n_random_scalars(2);

        let pi_s = ProofCmCs::construct(
            &mut params,
            &elgamal_keypair,
            &ephemeral_keys,
            &cm,
            &r,
            &private_attributes,
            &*attributes_ciphertexts,
        );

        let bytes = pi_s.to_bytes();
        assert_eq!(ProofCmCs::from_bytes(&bytes).unwrap(), pi_s);
    }

    #[test]
    fn proof_kappa_nu_bytes_roundtrip() {
        let mut params = setup(1).unwrap();

        let keypair = keygen(&mut params);
        let r = params.random_scalar();
        let s = params.random_scalar();

        // we don't care about 'correctness' of the proof. only whether we can correctly recover it from bytes
        let _signature = Signature(params.gen1() * r, params.gen1() * s);
        let private_attributes = params.n_random_scalars(1);
        let r = params.random_scalar();
        let kappa = compute_kappa(&params, &keypair.verification_key(), &private_attributes, r);

        // 0 public 1 private
        let pi_v = ProofKappaNu::construct(
            &mut params,
            &keypair.verification_key(),
            &private_attributes,
            &r,
            &kappa,
        );

        let bytes = pi_v.to_bytes();
        assert_eq!(ProofKappaNu::from_bytes(&bytes).unwrap(), pi_v);

        // 2 public 2 private
        let mut params = setup(4).unwrap();
        let keypair = keygen(&mut params);
        let private_attributes = params.n_random_scalars(2);

        let pi_v = ProofKappaNu::construct(
            &mut params,
            &keypair.verification_key(),
            &private_attributes,
            &r,
            &kappa,
        );

        let bytes = pi_v.to_bytes();
        assert_eq!(ProofKappaNu::from_bytes(&bytes).unwrap(), pi_v);
    }

    #[test]
    fn set_membership_proof_correctness_1() {
        let params = setup(1).unwrap();

        // define one single private attribute
        let private_attribute = 0;
        let private_attributes = [Scalar::from(private_attribute)];

        // issue signatures for the values of the set
        let phi = [
            RawAttribute::Number(0),
            RawAttribute::Number(1),
            RawAttribute::Number(2),
        ];
        let membership_signatures = issue_membership_signatures(&params, &phi);

        // pick the right signature for attribute
        let membership_signature = membership_signatures
            .signatures
            .get(&RawAttribute::Number(private_attribute))
            .unwrap();
        let sp_verification_key = membership_signatures.sp_verification_key;

        let h = hash_g1("h");
        let key_pair = keygen(&params);

        // simulate a valid signature on attribute
        let signature = Signature(
            h,
            h * key_pair.secret_key().x
                + h * (key_pair.secret_key().ys[0] * (Attribute::from(private_attribute))),
        );

        let (_a_prime, r1) = membership_signature.randomise(&params);
        let (_sigma_prime, r2) = signature.randomise(&params);

        let pi = SetMembershipProof::construct(
            &params,
            &key_pair.verification_key(),
            &sp_verification_key,
            &private_attributes,
            &r1,
            &r2,
        );

        let kappa_1 = compute_kappa(&params, &sp_verification_key, &private_attributes, r1);
        let kappa_2 = compute_kappa(
            &params,
            &key_pair.verification_key(),
            &private_attributes,
            r2,
        );

        // this only checks that signatures are "randomized" as they should
        assert!(pi.verify(
            &params,
            &key_pair.verification_key(),
            &sp_verification_key,
            &kappa_1,
            &kappa_2
        ));
    }

    #[test]
    fn set_membership_proof_correctness_2() {
        let params = setup(2).unwrap();

        // define two private attributes but only first is used for set membership
        let private_attribute = 0;
        let private_attributes = [Scalar::from(private_attribute), params.random_scalar()];

        // issue signatures for the values of the set
        let phi = [
            RawAttribute::Number(0),
            RawAttribute::Number(1),
            RawAttribute::Number(2),
        ];
        let membership_signatures = issue_membership_signatures(&params, &phi);

        // pick the right signature for attribute
        let membership_signature = membership_signatures
            .signatures
            .get(&RawAttribute::Number(private_attribute))
            .unwrap();
        let sp_verification_key = membership_signatures.sp_verification_key;

        let h = hash_g1("h");
        let key_pair = keygen(&params);

        // simulate a valid signature on attribute
        let signature = Signature(
            h,
            h * key_pair.secret_key().x
                + h * (key_pair.secret_key().ys[0] * (Attribute::from(private_attributes[0]))
                    + key_pair.secret_key().ys[1] * (Attribute::from(private_attributes[1]))),
        );

        let (_a_prime, r1) = membership_signature.randomise(&params);
        let (_sigma_prime, r2) = signature.randomise(&params);

        let pi = SetMembershipProof::construct(
            &params,
            &key_pair.verification_key(),
            &sp_verification_key,
            &private_attributes,
            &r1,
            &r2,
        );

        let kappa_1 = compute_kappa(&params, &sp_verification_key, &private_attributes, r1);
        let kappa_2 = compute_kappa(
            &params,
            &key_pair.verification_key(),
            &private_attributes,
            r2,
        );

        // this only checks that signatures are "randomized" as they should
        assert!(pi.verify(
            &params,
            &key_pair.verification_key(),
            &sp_verification_key,
            &kappa_1,
            &kappa_2
        ));
    }

    #[test]
    fn set_membership_proof_bytes_roundtrip_1() {
        let params = setup(1).unwrap();

        let verification_key = keygen(&params).verification_key();
        let sp_verification_key = single_attribute_keygen(&params).verification_key();
        let private_attributes = params.n_random_scalars(1);

        let r1 = params.random_scalar();
        let r2 = params.random_scalar();

        let pi = SetMembershipProof::construct(
            &params,
            &verification_key,
            &sp_verification_key,
            &private_attributes,
            &r1,
            &r2,
        );

        let bytes = pi.to_bytes();
        assert_eq!(SetMembershipProof::from_bytes(&bytes).unwrap(), pi);
    }

    #[test]
    fn set_membership_proof_bytes_roundtrip_10() {
        let params = setup(10).unwrap();

        let verification_key = keygen(&params).verification_key();
        let sp_verification_key = single_attribute_keygen(&params).verification_key();
        let private_attributes = params.n_random_scalars(10);

        let r1 = params.random_scalar();
        let r2 = params.random_scalar();

        let pi = SetMembershipProof::construct(
            &params,
            &verification_key,
            &sp_verification_key,
            &private_attributes,
            &r1,
            &r2,
        );

        let bytes = pi.to_bytes();
        assert_eq!(SetMembershipProof::from_bytes(&bytes).unwrap(), pi);
    }

    #[test]
    fn set_membership_proof_bytes_roundtrip_5_5() {
        let params = setup(10).unwrap();

        let verification_key = keygen(&params).verification_key();
        let sp_verification_key = single_attribute_keygen(&params).verification_key();
        let private_attributes = params.n_random_scalars(5);

        let r1 = params.random_scalar();
        let r2 = params.random_scalar();

        let pi = SetMembershipProof::construct(
            &params,
            &verification_key,
            &sp_verification_key,
            &private_attributes,
            &r1,
            &r2,
        );

        let bytes = pi.to_bytes();
        assert_eq!(SetMembershipProof::from_bytes(&bytes).unwrap(), pi);
    }
}
