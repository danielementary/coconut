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
use group::GroupEncoding;

use digest::generic_array::typenum::Unsigned;
use digest::Digest;
use itertools::izip;
use sha2::Sha256;

use crate::elgamal::Ciphertext;
use crate::error::{CoconutError, Result};
use crate::scheme::setup::Parameters;
use crate::scheme::VerificationKey;
use crate::utils::{
    deserialize_g2_projective, deserialize_g2_projectives, deserialize_scalar, deserialize_scalars,
    deserialize_usize,
};
use crate::utils::{hash_g1, try_deserialize_scalar, try_deserialize_scalar_vec};
use crate::utils::{
    serialize_g2_projective, serialize_g2_projectives, serialize_scalar, serialize_scalars,
    serialize_usize,
};
use crate::{elgamal, Attribute, ElGamalKeyPair};

// as per the reference python implementation
pub type ChallengeDigest = Sha256;

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
    // commitments
    commitment_element_kappa: G2Projective,
    commitment_credential_kappa: G2Projective,
    // responses
    response_element_blinder: Scalar,
    response_credential_blinder: Scalar,
    responses_private_attributes: Vec<Scalar>,
}

impl SetMembershipProof {
    pub(crate) fn construct(
        // parameters
        params: &Parameters,
        // keys
        verification_key: &VerificationKey,
        sp_verification_key: &VerificationKey,
        // element and credential blinders
        element_blinder: &Scalar,
        credential_blinder: &Scalar,
        // private attributes
        private_attributes: &Vec<Attribute>,
    ) -> Self {
        // pick random values for each witness
        let random_element_blinder = params.random_scalar();
        let random_credential_blinder = params.random_scalar();
        let random_private_attributes = params.n_random_scalars(private_attributes.len());

        // compute commitments
        let commitment_element_kappa = params.gen2() * random_element_blinder
            + sp_verification_key.alpha
            + sp_verification_key.beta[0] * random_private_attributes[0];

        let commitment_credential_kappa = params.gen2() * random_credential_blinder
            + verification_key.alpha
            + random_private_attributes
                .iter()
                .zip(verification_key.beta.iter())
                .map(|(rpa_i, beta_i)| beta_i * rpa_i)
                .sum::<G2Projective>();

        // compute challenge
        let challenge = SetMembershipProof::compute_challenge(
            &params,
            &verification_key,
            &sp_verification_key,
            &commitment_element_kappa,
            &commitment_credential_kappa,
        );

        // responses
        let response_element_blinder =
            produce_response(&random_element_blinder, &challenge, &element_blinder);
        let response_credential_blinder =
            produce_response(&random_credential_blinder, &challenge, &credential_blinder);
        let responses_private_attributes =
            produce_responses(&random_private_attributes, &challenge, private_attributes);

        SetMembershipProof {
            commitment_element_kappa,
            commitment_credential_kappa,
            response_element_blinder,
            response_credential_blinder,
            responses_private_attributes,
        }
    }

    pub(crate) fn private_attributes(&self) -> usize {
        self.responses_private_attributes.len()
    }

    fn compute_challenge(
        params: &Parameters,
        verification_key: &VerificationKey,
        sp_verification_key: &VerificationKey,
        commitment_element_kappa: &G2Projective,
        commitment_credential_kappa: &G2Projective,
    ) -> Scalar {
        let beta_bytes = verification_key
            .beta
            .iter()
            .map(|b| b.to_bytes())
            .collect::<Vec<_>>();

        compute_challenge::<ChallengeDigest, _, _>(
            std::iter::once(commitment_element_kappa.to_bytes().as_ref())
                .chain(std::iter::once(
                    commitment_credential_kappa.to_bytes().as_ref(),
                ))
                .chain(std::iter::once(params.gen2().to_bytes().as_ref()))
                .chain(std::iter::once(
                    sp_verification_key.alpha.to_bytes().as_ref(),
                ))
                .chain(std::iter::once(
                    sp_verification_key.beta[0].to_bytes().as_ref(),
                ))
                .chain(std::iter::once(verification_key.alpha.to_bytes().as_ref()))
                .chain(beta_bytes.iter().map(|b| b.as_ref())),
        )
    }

    fn recompute_challenge(
        &self,
        params: &Parameters,
        verification_key: &VerificationKey,
        sp_verification_key: &VerificationKey,
    ) -> Scalar {
        SetMembershipProof::compute_challenge(
            &params,
            &verification_key,
            &sp_verification_key,
            &self.commitment_element_kappa,
            &self.commitment_credential_kappa,
        )
    }

    pub(crate) fn verify(
        &self,
        params: &Parameters,
        verification_key: &VerificationKey,
        sp_verification_key: &VerificationKey,
        element_kappa: &G2Projective,
        credential_kappa: &G2Projective,
    ) -> bool {
        let challenge = self.recompute_challenge(&params, &verification_key, &sp_verification_key);

        let element_lhs =
            sp_verification_key.alpha * (-Scalar::one()) + self.commitment_element_kappa;
        let element_rhs = (sp_verification_key.alpha * (-Scalar::one()) + element_kappa)
            * challenge
            + params.gen2() * self.response_element_blinder
            + sp_verification_key.beta[0] * self.responses_private_attributes[0];

        let credential_lhs =
            verification_key.alpha * (-Scalar::one()) + self.commitment_credential_kappa;
        let credential_rhs = (verification_key.alpha * (-Scalar::one()) + credential_kappa)
            * challenge
            + params.gen2() * self.response_credential_blinder
            + verification_key
                .beta
                .iter()
                .zip(self.responses_private_attributes.iter())
                .map(|(beta, s_m)| beta * s_m)
                .sum::<G2Projective>();

        element_lhs == element_rhs && credential_lhs == credential_rhs
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        serialize_usize(&self.private_attributes(), &mut bytes);

        serialize_g2_projective(&self.commitment_element_kappa, &mut bytes);
        serialize_g2_projective(&self.commitment_credential_kappa, &mut bytes);
        serialize_scalar(&self.response_element_blinder, &mut bytes);
        serialize_scalar(&self.response_credential_blinder, &mut bytes);
        serialize_scalars(&self.responses_private_attributes, &mut bytes);

        bytes
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut pointer = 0;

        let private_attributes_len = deserialize_usize(&bytes, &mut pointer);

        let commitment_element_kappa = deserialize_g2_projective(&bytes, &mut pointer);
        let commitment_credential_kappa = deserialize_g2_projective(&bytes, &mut pointer);
        let response_element_blinder = deserialize_scalar(&bytes, &mut pointer);
        let response_credential_blinder = deserialize_scalar(&bytes, &mut pointer);
        let responses_private_attributes =
            deserialize_scalars(&bytes, &mut pointer, private_attributes_len);

        Ok(SetMembershipProof {
            commitment_element_kappa,
            commitment_credential_kappa,
            response_element_blinder,
            response_credential_blinder,
            responses_private_attributes,
        })
    }
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct RangeProof {
    // parameters
    base_u: usize,
    number_of_base_elements_l: usize,
    lower_bound: Scalar,
    upper_bound: Scalar,
    // lower bound
    commitments_decomposition_kappas_lower_bound: Vec<G2Projective>,
    commitment_credential_kappa_lower_bound: G2Projective,
    responses_decomposition_blinders_lower_bound: Vec<Scalar>,
    responses_decomposition_lower_bound: Vec<Scalar>,
    response_credential_blinder_lower_bound: Scalar,
    responses_private_attributes_lower_bound: Vec<Scalar>,
    // upper bound
    commitments_decomposition_kappas_upper_bound: Vec<G2Projective>,
    commitment_credential_blinder_upper_bound: G2Projective,
    responses_decomposition_blinders_upper_bound: Vec<Scalar>,
    responses_decomposition_upper_bound: Vec<Scalar>,
    response_credential_blinder_upper_bound: Scalar,
    responses_private_attributes_upper_bound: Vec<Scalar>,
}

impl RangeProof {
    pub(crate) fn construct(
        // parameters
        params: &Parameters,
        base_u: usize,
        number_of_base_elements_l: usize,
        lower_bound: Scalar,
        upper_bound: Scalar,
        // keys
        verification_key: &VerificationKey,
        sp_verification_key: &VerificationKey,
        // decompositions and blinders
        // lower bounder
        decomposition_lower_bound: &Vec<Scalar>,
        decomposition_blinders_lower_bound: &Vec<Scalar>,
        credential_blinder_lower_bound: &Scalar,
        // upper bound
        decomposition_upper_bound: &Vec<Scalar>,
        decomposition_blinders_upper_bound: &Vec<Scalar>,
        credential_blinder_upper_bound: &Scalar,
        // private attributes
        private_attributes: &Vec<Attribute>,
    ) -> Self {
        // pick random values for each witness
        let random_decomposition_lower_bound = params.n_random_scalars(number_of_base_elements_l);
        let random_decomposition_upper_bound = params.n_random_scalars(number_of_base_elements_l);

        let random_decomposition_blinders_lower_bound =
            params.n_random_scalars(number_of_base_elements_l);
        let random_decomposition_blinders_upper_bound =
            params.n_random_scalars(number_of_base_elements_l);

        let random_credential_blinder_lower_bound = params.random_scalar();
        let random_credential_blinder_upper_bound = params.random_scalar();

        // ignore first attribute as we use its decomposition so no need for a witness
        let random_private_attributes_lower_bound =
            params.n_random_scalars(private_attributes.len() - 1);
        let random_private_attributes_upper_bound =
            params.n_random_scalars(private_attributes.len() - 1);

        // compute commitments
        let commitments_decomposition_kappas_lower_bound: Vec<G2Projective> =
            random_decomposition_blinders_lower_bound
                .iter()
                .zip(random_decomposition_lower_bound.iter())
                .map(|(r, m)| {
                    params.gen2() * r + sp_verification_key.alpha + sp_verification_key.beta[0] * m
                })
                .collect();

        let commitments_decomposition_kappas_upper_bound: Vec<G2Projective> =
            random_decomposition_blinders_upper_bound
                .iter()
                .zip(random_decomposition_upper_bound.iter())
                .map(|(r, m)| {
                    params.gen2() * r + sp_verification_key.alpha + sp_verification_key.beta[0] * m
                })
                .collect();

        let commitment_credential_kappa_lower_bound: G2Projective = params.gen2()
            * random_credential_blinder_lower_bound
            + verification_key.alpha
            + verification_key.beta[0] * lower_bound
            + random_decomposition_lower_bound
                .iter()
                .enumerate()
                .map(|(i, r_m)| {
                    verification_key.beta[0] * r_m * (Scalar::from((base_u as u64).pow(i as u32)))
                })
                .sum::<G2Projective>()
            + random_private_attributes_lower_bound
                .iter()
                .zip(verification_key.beta[1..].iter())
                .map(|(r_mi, beta_i)| beta_i * r_mi)
                .sum::<G2Projective>();

        let commitment_credential_blinder_upper_bound: G2Projective = params.gen2()
            * random_credential_blinder_upper_bound
            + verification_key.alpha
            + verification_key.beta[0]
                * (upper_bound
                    - Scalar::from((base_u as u64).pow(number_of_base_elements_l as u32)))
            + random_decomposition_upper_bound
                .iter()
                .enumerate()
                .map(|(i, r_m)| {
                    verification_key.beta[0] * r_m * (Scalar::from((base_u as u64).pow(i as u32)))
                })
                .sum::<G2Projective>()
            + random_private_attributes_upper_bound
                .iter()
                .zip(verification_key.beta[1..].iter())
                .map(|(r_mi, beta_i)| beta_i * r_mi)
                .sum::<G2Projective>();

        // compute challenge
        let challenge = RangeProof::compute_challenge(
            &params,
            &verification_key,
            &sp_verification_key,
            &commitments_decomposition_kappas_lower_bound,
            &commitment_credential_kappa_lower_bound,
            &commitments_decomposition_kappas_upper_bound,
            &commitment_credential_blinder_upper_bound,
        );

        // compute responses
        let responses_decomposition_lower_bound = produce_responses(
            &random_decomposition_lower_bound,
            &challenge,
            decomposition_lower_bound,
        );

        let responses_decomposition_upper_bound = produce_responses(
            &random_decomposition_upper_bound,
            &challenge,
            decomposition_upper_bound,
        );

        let responses_decomposition_blinders_lower_bound = produce_responses(
            &random_decomposition_blinders_lower_bound,
            &challenge,
            decomposition_blinders_lower_bound,
        );

        let responses_decomposition_blinders_upper_bound = produce_responses(
            &random_decomposition_blinders_upper_bound,
            &challenge,
            decomposition_blinders_upper_bound,
        );

        let responses_private_attributes_lower_bound = produce_responses(
            &random_private_attributes_lower_bound,
            &challenge,
            &private_attributes[1..],
        );
        let responses_private_attributes_upper_bound = produce_responses(
            &random_private_attributes_upper_bound,
            &challenge,
            &private_attributes[1..],
        );
        let response_credential_blinder_lower_bound = produce_response(
            &random_credential_blinder_lower_bound,
            &challenge,
            credential_blinder_lower_bound,
        );
        let response_credential_blinder_upper_bound = produce_response(
            &random_credential_blinder_upper_bound,
            &challenge,
            credential_blinder_upper_bound,
        );

        RangeProof {
            // parameters
            base_u,
            number_of_base_elements_l,
            lower_bound,
            upper_bound,
            // lower bound
            commitments_decomposition_kappas_lower_bound,
            commitment_credential_kappa_lower_bound,
            responses_decomposition_blinders_lower_bound,
            responses_decomposition_lower_bound,
            response_credential_blinder_lower_bound,
            responses_private_attributes_lower_bound,
            // upper bound
            commitments_decomposition_kappas_upper_bound,
            commitment_credential_blinder_upper_bound,
            responses_decomposition_blinders_upper_bound,
            responses_decomposition_upper_bound,
            response_credential_blinder_upper_bound,
            responses_private_attributes_upper_bound,
        }
    }

    pub(crate) fn private_attributes(&self) -> usize {
        self.responses_private_attributes_lower_bound.len()
    }

    fn compute_challenge(
        params: &Parameters,
        verification_key: &VerificationKey,
        sp_verification_key: &VerificationKey,
        commitments_decomposition_kappas_lower_bound: &Vec<G2Projective>,
        commitment_credential_kappa_lower_bound: &G2Projective,
        commitments_decomposition_kappas_upper_bound: &Vec<G2Projective>,
        commitment_credential_blinder_upper_bound: &G2Projective,
    ) -> Scalar {
        let commitments_decomposition_kappas_lower_bound_bytes =
            commitments_decomposition_kappas_lower_bound
                .iter()
                .map(|k| k.to_bytes())
                .collect::<Vec<_>>();

        let commitments_decomposition_kappas_upper_bound_bytes =
            commitments_decomposition_kappas_upper_bound
                .iter()
                .map(|k| k.to_bytes())
                .collect::<Vec<_>>();

        let beta_bytes = verification_key.beta[1..]
            .iter()
            .map(|b| b.to_bytes())
            .collect::<Vec<_>>();

        compute_challenge::<ChallengeDigest, _, _>(
            commitments_decomposition_kappas_lower_bound_bytes
                .iter()
                .map(|b| b.as_ref())
                .chain(
                    commitments_decomposition_kappas_upper_bound_bytes
                        .iter()
                        .map(|b| b.as_ref()),
                )
                .chain(std::iter::once(
                    commitment_credential_kappa_lower_bound.to_bytes().as_ref(),
                ))
                .chain(std::iter::once(
                    commitment_credential_blinder_upper_bound
                        .to_bytes()
                        .as_ref(),
                ))
                .chain(std::iter::once(params.gen2().to_bytes().as_ref()))
                .chain(std::iter::once(
                    sp_verification_key.alpha.to_bytes().as_ref(),
                ))
                .chain(std::iter::once(
                    sp_verification_key.beta[0].to_bytes().as_ref(),
                ))
                .chain(std::iter::once(verification_key.alpha.to_bytes().as_ref()))
                .chain(beta_bytes.iter().map(|b| b.as_ref())),
        )
    }

    fn recompute_challenge(
        &self,
        params: &Parameters,
        verification_key: &VerificationKey,
        sp_verification_key: &VerificationKey,
    ) -> Scalar {
        RangeProof::compute_challenge(
            &params,
            &verification_key,
            &sp_verification_key,
            &self.commitments_decomposition_kappas_lower_bound,
            &self.commitment_credential_kappa_lower_bound,
            &self.commitments_decomposition_kappas_upper_bound,
            &self.commitment_credential_blinder_upper_bound,
        )
    }

    pub(crate) fn verify(
        &self,
        params: &Parameters,
        // keys
        verification_key: &VerificationKey,
        sp_verification_key: &VerificationKey,
        // lower bound
        decomposition_kappas_lower_bound: &Vec<G2Projective>,
        credential_kappa_lower_bound: &G2Projective,
        // upper bound
        decomposition_kappas_upper_bound: &Vec<G2Projective>,
        credential_kappa_upper_bound: &G2Projective,
    ) -> bool {
        // recompute challenge
        let challenge = self.recompute_challenge(&params, &verification_key, &sp_verification_key);

        // check decomposition kappas
        // lower bound
        let decomposition_kappas_lower_bound_lhs = self
            .commitments_decomposition_kappas_lower_bound
            .iter()
            .map(|k| sp_verification_key.alpha * (-Scalar::one()) + k)
            .collect::<Vec<_>>();

        let decomposition_kappas_upper_bound_rhs = izip!(
            decomposition_kappas_lower_bound,
            &self.responses_decomposition_blinders_lower_bound,
            &self.responses_decomposition_lower_bound
        )
        .map(|(k, r, m)| {
            (sp_verification_key.alpha * (-Scalar::one()) + k) * challenge
                + params.gen2() * r
                + sp_verification_key.beta[0] * m
        })
        .collect::<Vec<_>>();

        // upper bound
        let decomposition_kappas_upper_bound_lhs = self
            .commitments_decomposition_kappas_upper_bound
            .iter()
            .map(|k| sp_verification_key.alpha * (-Scalar::one()) + k)
            .collect::<Vec<_>>();

        let decomposition_kappas_lower_bound_rhs = izip!(
            decomposition_kappas_upper_bound,
            &self.responses_decomposition_blinders_upper_bound,
            &self.responses_decomposition_upper_bound
        )
        .map(|(k, r, m)| {
            (sp_verification_key.alpha * (-Scalar::one()) + k) * challenge
                + params.gen2() * r
                + sp_verification_key.beta[0] * m
        })
        .collect::<Vec<_>>();

        // check credential kappas
        // lower bound
        let credential_kappa_lower_bound_lhs = verification_key.alpha * (-Scalar::one())
            + self.commitment_credential_kappa_lower_bound;
        let credential_kappa_lower_bound_rhs = (verification_key.alpha * (-Scalar::one())
            + credential_kappa_lower_bound
            + verification_key.beta[0] * -self.lower_bound)
            * challenge
            + params.gen2() * self.response_credential_blinder_lower_bound
            + verification_key.beta[0] * self.lower_bound
            + self
                .responses_decomposition_lower_bound
                .iter()
                .enumerate()
                .map(|(i, s_m)| {
                    verification_key.beta[0]
                        * s_m
                        * (Scalar::from((self.base_u as u64).pow(i as u32)))
                })
                .sum::<G2Projective>()
            + self
                .responses_private_attributes_lower_bound
                .iter()
                .zip(verification_key.beta[1..].iter())
                .map(|(s_mi, beta_i)| beta_i * s_mi)
                .sum::<G2Projective>();

        // upper bound
        let credential_kappa_upper_bound_lhs = verification_key.alpha * (-Scalar::one())
            + self.commitment_credential_blinder_upper_bound;
        let credential_kappa_upper_bound_rhs = (verification_key.alpha * (-Scalar::one())
            + credential_kappa_upper_bound
            + verification_key.beta[0]
                * -(self.upper_bound
                    - Scalar::from(
                        (self.base_u as u64).pow(self.number_of_base_elements_l as u32),
                    )))
            * challenge
            + params.gen2() * self.response_credential_blinder_upper_bound
            + verification_key.beta[0]
                * (self.upper_bound
                    - Scalar::from(
                        (self.base_u as u64).pow(self.number_of_base_elements_l as u32),
                    ))
            + self
                .responses_decomposition_upper_bound
                .iter()
                .enumerate()
                .map(|(i, s_m)| {
                    verification_key.beta[0]
                        * s_m
                        * (Scalar::from((self.base_u as u64).pow(i as u32)))
                })
                .sum::<G2Projective>()
            + self
                .responses_private_attributes_upper_bound
                .iter()
                .zip(verification_key.beta[1..].iter())
                .map(|(s_mi, beta_i)| beta_i * s_mi)
                .sum::<G2Projective>();

        decomposition_kappas_lower_bound_lhs == decomposition_kappas_upper_bound_rhs
            && decomposition_kappas_upper_bound_lhs == decomposition_kappas_lower_bound_rhs
            && credential_kappa_lower_bound_lhs == credential_kappa_lower_bound_rhs
            && credential_kappa_upper_bound_lhs == credential_kappa_upper_bound_rhs
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // also serialiaze the number of private attributes
        serialize_usize(&self.private_attributes(), &mut bytes);

        serialize_usize(&self.base_u, &mut bytes);
        serialize_usize(&self.number_of_base_elements_l, &mut bytes);

        serialize_scalar(&self.lower_bound, &mut bytes);
        serialize_scalar(&self.upper_bound, &mut bytes);

        serialize_g2_projectives(
            &self.commitments_decomposition_kappas_lower_bound,
            &mut bytes,
        );
        serialize_g2_projective(&self.commitment_credential_kappa_lower_bound, &mut bytes);
        serialize_scalars(
            &self.responses_decomposition_blinders_lower_bound,
            &mut bytes,
        );
        serialize_scalars(&self.responses_decomposition_lower_bound, &mut bytes);
        serialize_scalars(&self.responses_private_attributes_lower_bound, &mut bytes);
        serialize_scalar(&self.response_credential_blinder_lower_bound, &mut bytes);

        serialize_g2_projectives(
            &self.commitments_decomposition_kappas_upper_bound,
            &mut bytes,
        );
        serialize_g2_projective(&self.commitment_credential_blinder_upper_bound, &mut bytes);
        serialize_scalars(
            &self.responses_decomposition_blinders_upper_bound,
            &mut bytes,
        );
        serialize_scalars(&self.responses_decomposition_upper_bound, &mut bytes);
        serialize_scalars(&self.responses_private_attributes_upper_bound, &mut bytes);
        serialize_scalar(&self.response_credential_blinder_upper_bound, &mut bytes);

        bytes
    }

    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut pointer = 0;

        // also deserialiaze the number of private attributes
        let number_of_serialized_private_attributes = deserialize_usize(&bytes, &mut pointer);

        let base_u = deserialize_usize(&bytes, &mut pointer);
        let number_of_base_elements_l = deserialize_usize(&bytes, &mut pointer);

        let lower_bound = deserialize_scalar(&bytes, &mut pointer);
        let upper_bound = deserialize_scalar(&bytes, &mut pointer);

        let commitments_decomposition_kappas_lower_bound =
            deserialize_g2_projectives(&bytes, &mut pointer, number_of_base_elements_l);
        let commitment_credential_kappa_lower_bound =
            deserialize_g2_projective(&bytes, &mut pointer);
        let responses_decomposition_blinders_lower_bound =
            deserialize_scalars(&bytes, &mut pointer, number_of_base_elements_l);
        let responses_decomposition_lower_bound =
            deserialize_scalars(&bytes, &mut pointer, number_of_base_elements_l);
        let responses_private_attributes_lower_bound = deserialize_scalars(
            &bytes,
            &mut pointer,
            number_of_serialized_private_attributes,
        );
        let response_credential_blinder_lower_bound = deserialize_scalar(&bytes, &mut pointer);

        let commitments_decomposition_kappas_upper_bound =
            deserialize_g2_projectives(&bytes, &mut pointer, number_of_base_elements_l);
        let commitment_credential_blinder_upper_bound =
            deserialize_g2_projective(&bytes, &mut pointer);
        let responses_decomposition_blinders_upper_bound =
            deserialize_scalars(&bytes, &mut pointer, number_of_base_elements_l);
        let responses_decomposition_upper_bound =
            deserialize_scalars(&bytes, &mut pointer, number_of_base_elements_l);
        let responses_private_attributes_upper_bound = deserialize_scalars(
            &bytes,
            &mut pointer,
            number_of_serialized_private_attributes,
        );
        let response_credential_blinder_upper_bound = deserialize_scalar(&bytes, &mut pointer);

        Ok(RangeProof {
            // parameters
            base_u,
            number_of_base_elements_l,
            lower_bound,
            upper_bound,
            // lower bound
            commitments_decomposition_kappas_lower_bound,
            commitment_credential_kappa_lower_bound,
            responses_decomposition_blinders_lower_bound,
            responses_decomposition_lower_bound,
            response_credential_blinder_lower_bound,
            responses_private_attributes_lower_bound,
            // upper bound
            commitments_decomposition_kappas_upper_bound,
            commitment_credential_blinder_upper_bound,
            responses_decomposition_blinders_upper_bound,
            responses_decomposition_upper_bound,
            response_credential_blinder_upper_bound,
            responses_private_attributes_upper_bound,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::Signature;
    use group::Group;
    use rand::thread_rng;

    use crate::scheme::issuance::{compute_attribute_encryption, compute_commitment_hash};
    use crate::scheme::keygen::{keygen, single_attribute_keygen};
    use crate::scheme::setup::setup;
    use crate::scheme::verification::compute_kappa;
    use crate::utils::{
        compute_u_ary_decomposition, default_base_u, default_max,
        default_number_of_base_elements_l, issue_range_signatures, issue_set_signatures,
        pick_signature, pick_signatures_for_decomposition,
    };

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

    // test that SetMembershipProof is verified with on single private attribute
    #[test]
    fn set_membership_proof_correctness_1() {
        let params = setup(1).unwrap();
        let sp_h = params.gen1() * params.random_scalar();
        let sp_key_pair = single_attribute_keygen(&params);
        let sp_private_key = sp_key_pair.secret_key();
        let sp_verification_key = sp_key_pair.verification_key();

        // define one single private attribute
        let private_attribute = 0;
        let private_attributes = vec![Scalar::from(private_attribute)];

        // issue signatures for the values of the set
        let phi = [
            RawAttribute::Number(0),
            RawAttribute::Number(1),
            RawAttribute::Number(2),
        ];
        let membership_signatures = issue_set_signatures(&sp_h, &sp_private_key, &phi);

        // pick the right signature for attribute
        let membership_signature = pick_signature(
            &RawAttribute::Number(private_attribute),
            &membership_signatures,
        );

        // simulate a valid signature on attribute
        let h = params.gen1() * params.random_scalar();
        let key_pair = keygen(&params);
        let private_key = key_pair.secret_key();
        let verification_key = key_pair.verification_key();

        let signature = Signature(
            h,
            h * private_key.x + h * (private_key.ys[0] * (Attribute::from(private_attribute))),
        );

        // randomize signatures
        let (_, element_blinder) = membership_signature.randomise(&params);
        let (_, credential_blinder) = signature.randomise(&params);

        // construct set membership proof
        let pi = SetMembershipProof::construct(
            &params,
            &verification_key,
            &sp_verification_key,
            &element_blinder,
            &credential_blinder,
            &private_attributes,
        );

        let element_kappa = compute_kappa(
            &params,
            &sp_verification_key,
            &private_attributes,
            element_blinder,
        );
        let credential_kappa = compute_kappa(
            &params,
            &verification_key,
            &private_attributes,
            credential_blinder,
        );

        // this only checks that signatures are "randomized" as they should and proven as they
        // should
        assert!(pi.verify(
            &params,
            &verification_key,
            &sp_verification_key,
            &element_kappa,
            &credential_kappa
        ));
    }

    // test that SetMembershipProof is verified with two private attributes
    #[test]
    fn set_membership_proof_correctness_2() {
        let params = setup(2).unwrap();
        let sp_h = params.gen1() * params.random_scalar();
        let sp_key_pair = single_attribute_keygen(&params);
        let sp_private_key = sp_key_pair.secret_key();
        let sp_verification_key = sp_key_pair.verification_key();

        // define one single private attribute
        let private_attribute = 0;
        let private_attributes = vec![Scalar::from(private_attribute), params.random_scalar()];

        // issue signatures for the values of the set
        let phi = [
            RawAttribute::Number(0),
            RawAttribute::Number(1),
            RawAttribute::Number(2),
        ];
        let membership_signatures = issue_set_signatures(&sp_h, &sp_private_key, &phi);

        // pick the right signature for attribute
        let membership_signature = pick_signature(
            &RawAttribute::Number(private_attribute),
            &membership_signatures,
        );

        // simulate a valid signature on attribute
        let h = params.gen1() * params.random_scalar();
        let key_pair = keygen(&params);
        let private_key = key_pair.secret_key();
        let verification_key = key_pair.verification_key();

        let signature = Signature(
            h,
            h * key_pair.secret_key().x
                + h * (private_key.ys[0] * (Attribute::from(private_attributes[0]))
                    + private_key.ys[1] * (Attribute::from(private_attributes[1]))),
        );

        // randomize signatures
        let (_, element_blinder) = membership_signature.randomise(&params);
        let (_, credential_blinder) = signature.randomise(&params);

        // construct set membership proof
        let pi = SetMembershipProof::construct(
            &params,
            &verification_key,
            &sp_verification_key,
            &element_blinder,
            &credential_blinder,
            &private_attributes,
        );

        let element_kappa = compute_kappa(
            &params,
            &sp_verification_key,
            &private_attributes,
            element_blinder,
        );
        let credential_kappa = compute_kappa(
            &params,
            &verification_key,
            &private_attributes,
            credential_blinder,
        );

        // this only checks that signatures are "randomized" as they should and proven as they
        // should
        assert!(pi.verify(
            &params,
            &verification_key,
            &sp_verification_key,
            &element_kappa,
            &credential_kappa
        ));
    }

    // test that SetMembershipProof is verified with on single private attribute and one public one
    #[test]
    fn set_membership_proof_correctness_1_1() {
        let params = setup(2).unwrap();
        let sp_h = params.gen1() * params.random_scalar();
        let sp_key_pair = single_attribute_keygen(&params);
        let sp_private_key = sp_key_pair.secret_key();
        let sp_verification_key = sp_key_pair.verification_key();

        // define one single private attribute
        let private_attribute = 0;
        let private_attributes = vec![Scalar::from(private_attribute)];

        // issue signatures for the values of the set
        let phi = [
            RawAttribute::Number(0),
            RawAttribute::Number(1),
            RawAttribute::Number(2),
        ];
        let membership_signatures = issue_set_signatures(&sp_h, &sp_private_key, &phi);

        // pick the right signature for attribute
        let membership_signature = pick_signature(
            &RawAttribute::Number(private_attribute),
            &membership_signatures,
        );

        // simulate a valid signature on attribute
        let h = params.gen1() * params.random_scalar();
        let key_pair = keygen(&params);
        let private_key = key_pair.secret_key();
        let verification_key = key_pair.verification_key();

        let signature = Signature(
            h,
            h * private_key.x + h * (private_key.ys[0] * (Attribute::from(private_attribute))),
        );

        // randomize signatures
        let (_, element_blinder) = membership_signature.randomise(&params);
        let (_, credential_blinder) = signature.randomise(&params);

        // construct set membership proof
        let pi = SetMembershipProof::construct(
            &params,
            &verification_key,
            &sp_verification_key,
            &element_blinder,
            &credential_blinder,
            &private_attributes,
        );

        let element_kappa = compute_kappa(
            &params,
            &sp_verification_key,
            &private_attributes,
            element_blinder,
        );
        let credential_kappa = compute_kappa(
            &params,
            &verification_key,
            &private_attributes,
            credential_blinder,
        );

        // this only checks that signatures are "randomized" as they should and proven as they
        // should
        assert!(pi.verify(
            &params,
            &verification_key,
            &sp_verification_key,
            &element_kappa,
            &credential_kappa
        ));
    }

    // test that SetMembershipProof is properly deserialized/serialized with one single private
    // attribute
    #[test]
    fn set_membership_proof_bytes_roundtrip_1() {
        let params = setup(1).unwrap();

        let verification_key = keygen(&params).verification_key();
        let sp_verification_key = single_attribute_keygen(&params).verification_key();
        let private_attributes = params.n_random_scalars(1);

        let element_blinder = params.random_scalar();
        let credential_blinder = params.random_scalar();

        let pi = SetMembershipProof::construct(
            &params,
            &verification_key,
            &sp_verification_key,
            &element_blinder,
            &credential_blinder,
            &private_attributes,
        );

        assert_eq!(SetMembershipProof::from_bytes(&pi.to_bytes()).unwrap(), pi);
    }

    // test that SetMembershipProof is properly deserialized/serialized with ten private
    // attributes
    #[test]
    fn set_membership_proof_bytes_roundtrip_10() {
        let params = setup(10).unwrap();

        let verification_key = keygen(&params).verification_key();
        let sp_verification_key = single_attribute_keygen(&params).verification_key();
        let private_attributes = params.n_random_scalars(1);

        let element_blinder = params.random_scalar();
        let credential_blinder = params.random_scalar();

        let pi = SetMembershipProof::construct(
            &params,
            &verification_key,
            &sp_verification_key,
            &element_blinder,
            &credential_blinder,
            &private_attributes,
        );

        assert_eq!(SetMembershipProof::from_bytes(&pi.to_bytes()).unwrap(), pi);
    }

    // test that SetMembershipProof is properly deserialized/serialized with five private
    // attribute and five public ones
    #[test]
    fn set_membership_proof_bytes_roundtrip_5_5() {
        let params = setup(10).unwrap();

        let verification_key = keygen(&params).verification_key();
        let sp_verification_key = single_attribute_keygen(&params).verification_key();
        let private_attributes = params.n_random_scalars(5);

        let element_blinder = params.random_scalar();
        let credential_blinder = params.random_scalar();

        let pi = SetMembershipProof::construct(
            &params,
            &verification_key,
            &sp_verification_key,
            &element_blinder,
            &credential_blinder,
            &private_attributes,
        );

        assert_eq!(SetMembershipProof::from_bytes(&pi.to_bytes()).unwrap(), pi);
    }

    // test that RangeProof is verified with on single private attribute
    #[test]
    fn range_proof_correctness_1() {
        // init parameters for 1 message credential
        let params = setup(1).unwrap();
        let sp_h = params.gen1() * params.random_scalar();
        let sp_key_pair = single_attribute_keygen(&params);
        let sp_private_key = sp_key_pair.secret_key();
        let sp_verification_key = sp_key_pair.verification_key();

        let base_u = default_base_u();
        let number_of_base_elements_l = default_number_of_base_elements_l();
        let lower_bound = Scalar::from(5);
        let upper_bound = Scalar::from(15);

        // define one single private attribute
        let private_attribute = 10;
        let private_attribute_for_proof = Scalar::from(private_attribute);
        let private_attributes = vec![private_attribute_for_proof];

        // issue signatures for all base u elements
        let range_signatures = issue_range_signatures(&sp_h, &sp_private_key, 0, base_u);

        // simulate a valid signature on attribute
        let h = params.gen1() * params.random_scalar();
        let key_pair = keygen(&params);
        let private_key = key_pair.secret_key();
        let verification_key = key_pair.verification_key();

        let credential = Signature(
            h,
            h * key_pair.secret_key().x
                + h * (private_key.ys[0] * (Attribute::from(private_attribute))),
        );

        // lower bound
        let decomposition_lower_bound = compute_u_ary_decomposition(
            &(private_attribute_for_proof - lower_bound),
            base_u,
            number_of_base_elements_l,
        );

        let decomposition_signatures_lower_bound =
            pick_signatures_for_decomposition(&decomposition_lower_bound, &range_signatures);

        let (_, decomposition_blinders_lower_bound): (Vec<_>, Vec<_>) =
            decomposition_signatures_lower_bound
                .iter()
                .map(|s| s.randomise(&params))
                .unzip();

        let (_randomized_credential_lower_bound, credential_blinder_lower_bound) =
            credential.randomise(&params);

        let decomposition_kappas_lower_bound = decomposition_blinders_lower_bound
            .iter()
            .enumerate()
            .map(|(i, b)| {
                compute_kappa(
                    &params,
                    &sp_verification_key,
                    &decomposition_lower_bound[i..],
                    *b,
                )
            })
            .collect();

        let credential_kappa_lower_bound = compute_kappa(
            &params,
            &verification_key,
            &private_attributes,
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
            pick_signatures_for_decomposition(&decomposition_upper_bound, &range_signatures);

        let (_, decomposition_blinders_upper_bound): (Vec<_>, Vec<_>) =
            decomposition_signatures_upper_bound
                .iter()
                .map(|s| s.randomise(&params))
                .unzip();

        let (_, credential_blinder_upper_bound) = credential.randomise(&params);

        let decomposition_kappas_upper_bound = decomposition_blinders_upper_bound
            .iter()
            .enumerate()
            .map(|(i, b)| {
                compute_kappa(
                    &params,
                    &sp_verification_key,
                    &decomposition_upper_bound[i..],
                    *b,
                )
            })
            .collect();

        let credential_kappa_upper_bound = compute_kappa(
            &params,
            &verification_key,
            &private_attributes,
            credential_blinder_upper_bound,
        );

        let nizkp = RangeProof::construct(
            &params,
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

        // verify that constructed proof is a valid one
        assert!(nizkp.verify(
            &params,
            &verification_key,
            &sp_verification_key,
            &decomposition_kappas_lower_bound,
            &credential_kappa_lower_bound,
            &decomposition_kappas_upper_bound,
            &credential_kappa_upper_bound,
        ));
    }

    // test that RangeProof is verified with on two private attributes
    #[test]
    fn range_proof_correctness_2() {
        // init parameters for 2 message credential
        let params = setup(2).unwrap();
        let sp_h = params.gen1() * params.random_scalar();
        let sp_key_pair = single_attribute_keygen(&params);
        let sp_private_key = sp_key_pair.secret_key();
        let sp_verification_key = sp_key_pair.verification_key();

        let base_u = default_base_u();
        let number_of_base_elements_l = default_number_of_base_elements_l();
        let lower_bound = Scalar::from(5);
        let upper_bound = Scalar::from(15);

        // define two private attributes
        let private_attribute = 10;
        let private_attribute_for_proof = Scalar::from(private_attribute);
        let private_attributes = vec![private_attribute_for_proof, params.random_scalar()];

        // issue signatures for all base u elements
        let range_signatures = issue_range_signatures(&sp_h, &sp_private_key, 0, base_u);

        // simulate a valid signature on attribute
        let h = params.gen1() * params.random_scalar();
        let key_pair = keygen(&params);
        let private_key = key_pair.secret_key();
        let verification_key = key_pair.verification_key();

        let credential = Signature(
            h,
            h * key_pair.secret_key().x
                + h * (private_key.ys[0] * (Attribute::from(private_attributes[0]))
                    + private_key.ys[1] * (Attribute::from(private_attributes[1]))),
        );

        // lower bound
        let decomposition_lower_bound = compute_u_ary_decomposition(
            &(private_attribute_for_proof - lower_bound),
            base_u,
            number_of_base_elements_l,
        );

        let decomposition_signatures_lower_bound =
            pick_signatures_for_decomposition(&decomposition_lower_bound, &range_signatures);

        let (_, decomposition_blinders_lower_bound): (Vec<_>, Vec<_>) =
            decomposition_signatures_lower_bound
                .iter()
                .map(|s| s.randomise(&params))
                .unzip();

        let (_, credential_blinder_lower_bound) = credential.randomise(&params);

        let decomposition_kappas_lower_bound = decomposition_blinders_lower_bound
            .iter()
            .enumerate()
            .map(|(i, b)| {
                compute_kappa(
                    &params,
                    &sp_verification_key,
                    &decomposition_lower_bound[i..],
                    *b,
                )
            })
            .collect();

        let credential_kappa_lower_bound = compute_kappa(
            &params,
            &verification_key,
            &private_attributes,
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
            pick_signatures_for_decomposition(&decomposition_upper_bound, &range_signatures);

        let (_, decomposition_blinders_upper_bound): (Vec<_>, Vec<_>) =
            decomposition_signatures_upper_bound
                .iter()
                .map(|s| s.randomise(&params))
                .unzip();

        let (_, credential_blinder_upper_bound) = credential.randomise(&params);

        let decomposition_kappas_upper_bound = decomposition_blinders_upper_bound
            .iter()
            .enumerate()
            .map(|(i, b)| {
                compute_kappa(
                    &params,
                    &sp_verification_key,
                    &decomposition_upper_bound[i..],
                    *b,
                )
            })
            .collect();

        let credential_kappa_upper_bound = compute_kappa(
            &params,
            &verification_key,
            &private_attributes,
            credential_blinder_upper_bound,
        );

        let nizkp = RangeProof::construct(
            &params,
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

        // verify that constructed proof is a valid one
        assert!(nizkp.verify(
            &params,
            &verification_key,
            &sp_verification_key,
            &decomposition_kappas_lower_bound,
            &credential_kappa_lower_bound,
            &decomposition_kappas_upper_bound,
            &credential_kappa_upper_bound,
        ));
    }

    // test that RangeProof is verified with on single private attribute and one public one
    #[test]
    fn range_proof_correctness_1_1() {
        // init parameters for 1 message credential
        let params = setup(2).unwrap();
        let sp_h = params.gen1() * params.random_scalar();
        let sp_key_pair = single_attribute_keygen(&params);
        let sp_private_key = sp_key_pair.secret_key();
        let sp_verification_key = sp_key_pair.verification_key();

        let base_u = default_base_u();
        let number_of_base_elements_l = default_number_of_base_elements_l();
        let lower_bound = Scalar::from(5);
        let upper_bound = Scalar::from(15);

        // define one single private attribute
        let private_attribute = 10;
        let private_attribute_for_proof = Scalar::from(private_attribute);
        let private_attributes = vec![private_attribute_for_proof];

        // issue signatures for all base u elements
        let range_signatures = issue_range_signatures(&sp_h, &sp_private_key, 0, base_u);

        // simulate a valid signature on attribute
        let h = params.gen1() * params.random_scalar();
        let key_pair = keygen(&params);
        let private_key = key_pair.secret_key();
        let verification_key = key_pair.verification_key();

        let credential = Signature(
            h,
            h * key_pair.secret_key().x
                + h * (private_key.ys[0] * (Attribute::from(private_attribute))),
        );

        // lower bound
        let decomposition_lower_bound = compute_u_ary_decomposition(
            &(private_attribute_for_proof - lower_bound),
            base_u,
            number_of_base_elements_l,
        );

        let decomposition_signatures_lower_bound =
            pick_signatures_for_decomposition(&decomposition_lower_bound, &range_signatures);

        let (_, decomposition_blinders_lower_bound): (Vec<_>, Vec<_>) =
            decomposition_signatures_lower_bound
                .iter()
                .map(|s| s.randomise(&params))
                .unzip();

        let (_randomized_credential_lower_bound, credential_blinder_lower_bound) =
            credential.randomise(&params);

        let decomposition_kappas_lower_bound = decomposition_blinders_lower_bound
            .iter()
            .enumerate()
            .map(|(i, b)| {
                compute_kappa(
                    &params,
                    &sp_verification_key,
                    &decomposition_lower_bound[i..],
                    *b,
                )
            })
            .collect();

        let credential_kappa_lower_bound = compute_kappa(
            &params,
            &verification_key,
            &private_attributes,
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
            pick_signatures_for_decomposition(&decomposition_upper_bound, &range_signatures);

        let (_, decomposition_blinders_upper_bound): (Vec<_>, Vec<_>) =
            decomposition_signatures_upper_bound
                .iter()
                .map(|s| s.randomise(&params))
                .unzip();

        let (_, credential_blinder_upper_bound) = credential.randomise(&params);

        let decomposition_kappas_upper_bound = decomposition_blinders_upper_bound
            .iter()
            .enumerate()
            .map(|(i, b)| {
                compute_kappa(
                    &params,
                    &sp_verification_key,
                    &decomposition_upper_bound[i..],
                    *b,
                )
            })
            .collect();

        let credential_kappa_upper_bound = compute_kappa(
            &params,
            &verification_key,
            &private_attributes,
            credential_blinder_upper_bound,
        );

        let nizkp = RangeProof::construct(
            &params,
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

        // verify that constructed proof is a valid one
        assert!(nizkp.verify(
            &params,
            &verification_key,
            &sp_verification_key,
            &decomposition_kappas_lower_bound,
            &credential_kappa_lower_bound,
            &decomposition_kappas_upper_bound,
            &credential_kappa_upper_bound,
        ));
    }

    #[test]
    #[should_panic]
    fn range_proof_correctness_out_of_bound_panic_1() {
        let private_attribute = 10;
        let private_attribute_for_proof = Scalar::from(private_attribute);

        // define lower and upper bound for range proof where lower bound > private_attribute
        let lower_bound = Scalar::from(11);
        let upper_bound = Scalar::from(15);

        // compute u-ary decomposition for private_attribute_for_proof-lower_bound and
        // private_attribute_for_proof-upper_bound+u^l
        // should panic because the private attribute is not in the given range
        compute_u_ary_decomposition(
            &(private_attribute_for_proof - lower_bound),
            default_base_u(),
            default_number_of_base_elements_l(),
        );
        compute_u_ary_decomposition(
            &(private_attribute_for_proof - upper_bound + Scalar::from(default_max())),
            default_base_u(),
            default_number_of_base_elements_l(),
        );
    }

    #[test]
    #[should_panic]
    fn range_proof_correctness_out_of_bound_panic_2() {
        let private_attribute = 15;
        let private_attribute_for_proof = Scalar::from(private_attribute);

        // define lower and upper bound for range proof where upper bound = private attribute
        let lower_bound = Scalar::from(11);
        let upper_bound = Scalar::from(15);

        // compute u-ary decomposition for private_attribute_for_proof-lower_bound and
        // private_attribute_for_proof-upper_bound+u^l
        // should panic because the private attribute is not in the given range
        compute_u_ary_decomposition(
            &(private_attribute_for_proof - lower_bound),
            default_base_u(),
            default_number_of_base_elements_l(),
        );
        compute_u_ary_decomposition(
            &(private_attribute_for_proof - upper_bound + Scalar::from(default_max())),
            default_base_u(),
            default_number_of_base_elements_l(),
        );
    }

    #[test]
    #[should_panic]
    fn range_proof_correctness_out_of_bound_panic_3() {
        let private_attribute = 16;
        let private_attribute_for_proof = Scalar::from(private_attribute);

        // define lower and upper bound for range proof where upper bound > private attribute
        let lower_bound = Scalar::from(11);
        let upper_bound = Scalar::from(15);

        // compute u-ary decomposition for private_attribute_for_proof-lower_bound and
        // private_attribute_for_proof-upper_bound+u^l
        // should panic because the private attribute is not in the given range
        compute_u_ary_decomposition(
            &(private_attribute_for_proof - lower_bound),
            default_base_u(),
            default_number_of_base_elements_l(),
        );
        compute_u_ary_decomposition(
            &(private_attribute_for_proof - upper_bound + Scalar::from(default_max())),
            default_base_u(),
            default_number_of_base_elements_l(),
        );
    }

    #[test]
    fn range_proof_bytes_roundtrip_1() {
        let params = setup(1).unwrap();
        let base_u = default_base_u();
        let number_of_base_elements_l = default_number_of_base_elements_l();
        let lower_bound = params.random_scalar();
        let upper_bound = params.random_scalar();

        let verification_key = keygen(&params).verification_key();
        let sp_verification_key = single_attribute_keygen(&params).verification_key();

        let decomposition_lower_bound = params.n_random_scalars(number_of_base_elements_l);
        let decomposition_blinders_lower_bound = params.n_random_scalars(number_of_base_elements_l);
        let credential_blinder_lower_bound = params.random_scalar();

        let decomposition_upper_bound = params.n_random_scalars(number_of_base_elements_l);
        let decomposition_blinders_upper_bound = params.n_random_scalars(number_of_base_elements_l);
        let credential_blinder_upper_bound = params.random_scalar();

        let private_attributes = params.n_random_scalars(1);

        let nizkp = RangeProof::construct(
            &params,
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

        assert_eq!(RangeProof::from_bytes(&nizkp.to_bytes()).unwrap(), nizkp);
    }

    #[test]
    fn range_proof_bytes_roundtrip_10() {
        let params = setup(10).unwrap();
        let base_u = 4;
        let number_of_base_elements_l = 8;
        let lower_bound = params.random_scalar();
        let upper_bound = params.random_scalar();

        let verification_key = keygen(&params).verification_key();
        let sp_verification_key = single_attribute_keygen(&params).verification_key();

        let decomposition_lower_bound = params.n_random_scalars(number_of_base_elements_l);
        let decomposition_blinders_lower_bound = params.n_random_scalars(number_of_base_elements_l);
        let credential_blinder_lower_bound = params.random_scalar();

        let decomposition_upper_bound = params.n_random_scalars(number_of_base_elements_l);
        let decomposition_blinders_upper_bound = params.n_random_scalars(number_of_base_elements_l);
        let credential_blinder_upper_bound = params.random_scalar();

        let private_attributes = params.n_random_scalars(10);

        let nizkp = RangeProof::construct(
            &params,
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

        assert_eq!(RangeProof::from_bytes(&nizkp.to_bytes()).unwrap(), nizkp);
    }

    #[test]
    fn range_proof_bytes_roundtrip_5_5() {
        let params = setup(10).unwrap();
        let base_u = 4;
        let number_of_base_elements_l = 8;
        let lower_bound = params.random_scalar();
        let upper_bound = params.random_scalar();

        let verification_key = keygen(&params).verification_key();
        let sp_verification_key = single_attribute_keygen(&params).verification_key();

        let decomposition_lower_bound = params.n_random_scalars(number_of_base_elements_l);
        let decomposition_blinders_lower_bound = params.n_random_scalars(number_of_base_elements_l);
        let credential_blinder_lower_bound = params.random_scalar();

        let decomposition_upper_bound = params.n_random_scalars(number_of_base_elements_l);
        let decomposition_blinders_upper_bound = params.n_random_scalars(number_of_base_elements_l);
        let credential_blinder_upper_bound = params.random_scalar();

        let private_attributes = params.n_random_scalars(5);

        let nizkp = RangeProof::construct(
            &params,
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

        assert_eq!(RangeProof::from_bytes(&nizkp.to_bytes()).unwrap(), nizkp);
    }
}
