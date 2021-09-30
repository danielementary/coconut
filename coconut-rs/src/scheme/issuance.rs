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
use std::convert::TryInto;

use bls12_381::{G1Affine, G1Projective, Scalar};
use group::{Curve, GroupEncoding};

use crate::{Attribute, elgamal, VerificationKey};
use crate::elgamal::{Ciphertext, EphemeralKey};
use crate::error::{CoconutError, Result};
use crate::proofs::ProofCmCs;
use crate::scheme::BlindedSignature;
use crate::scheme::SecretKey;
use crate::scheme::setup::Parameters;
// TODO: possibly completely remove those two functions.
// They only exist to have a simpler and smaller code snippets to test
// basic functionalities.
/// Creates a Coconut Signature under a given secret key on a set of public attributes only.
#[cfg(test)]
use crate::Signature;
use crate::traits::{Base58, Bytable};
use crate::utils::{hash_g1, try_deserialize_g1_projective};

// TODO NAMING: double check this one
// Lambda
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct BlindSignRequest {
    // cm
    commitment: G1Projective,
    // h
    commitment_hash: G1Projective,
    // c
    attributes_ciphertexts: Vec<elgamal::Ciphertext>,
    // pi_s
    pi_s: ProofCmCs,
}

impl TryFrom<&[u8]> for BlindSignRequest {
    type Error = CoconutError;

    fn try_from(bytes: &[u8]) -> Result<BlindSignRequest> {
        if bytes.len() < 48 + 48 + 8 + 96 {
            return Err(CoconutError::DeserializationMinLength {
                min: 48 + 48 + 8 + 9,
                actual: bytes.len(),
            });
        }

        let mut j = 0;
        let COMMITMENT_BYTES_LEN = 48;
        let COMMITMENT_HASH_BYTES_LEN = 48;

        let cm_bytes = bytes[..j + COMMITMENT_BYTES_LEN].try_into().unwrap();
        let commitment = try_deserialize_g1_projective(
            &cm_bytes,
            CoconutError::Deserialization(
                "Failed to deserialize compressed commitment".to_string(),
            ),
        )?;
        j += COMMITMENT_BYTES_LEN;

        let cm_hash_bytes = bytes[j..j + COMMITMENT_HASH_BYTES_LEN].try_into().unwrap();
        let commitment_hash = try_deserialize_g1_projective(
            &cm_hash_bytes,
            CoconutError::Deserialization(
                "Failed to deserialize compressed commitment hash".to_string(),
            ),
        )?;
        j += COMMITMENT_HASH_BYTES_LEN;

        let c_len = u64::from_le_bytes(bytes[j..j + 8].try_into().unwrap());
        j += 8;
        if bytes[j..].len() < c_len as usize * 96 {
            return Err(CoconutError::DeserializationMinLength {
                min: c_len as usize * 96,
                actual: bytes[56..].len(),
            });
        }

        let mut attributes_ciphertexts = Vec::with_capacity(c_len as usize);
        for i in 0..c_len as usize {
            let start = j + i * 96;
            let end = start + 96;
            attributes_ciphertexts.push(Ciphertext::try_from(&bytes[start..end])?)
        }

        let pi_s = ProofCmCs::from_bytes(&bytes[j + c_len as usize * 96..])?;

        Ok(BlindSignRequest {
            commitment,
            commitment_hash,
            attributes_ciphertexts,
            pi_s,
        })
    }
}

impl Bytable for BlindSignRequest {
    fn to_byte_vec(&self) -> Vec<u8> {
        let cm_bytes = self.commitment.to_affine().to_compressed();
        let cm_hash_bytes = self.commitment_hash.to_affine().to_compressed();
        let c_len = self.attributes_ciphertexts.len() as u64;
        let proof_bytes = self.pi_s.to_bytes();

        let mut bytes = Vec::with_capacity(48 + 48 + 8 + c_len as usize * 96 + proof_bytes.len());

        bytes.extend_from_slice(&cm_bytes);
        bytes.extend_from_slice(&cm_hash_bytes);
        bytes.extend_from_slice(&c_len.to_le_bytes());
        for c in &self.attributes_ciphertexts {
            bytes.extend_from_slice(&c.to_bytes());
        }

        bytes.extend_from_slice(&proof_bytes);

        bytes
    }

    fn try_from_byte_slice(slice: &[u8]) -> Result<Self> {
        BlindSignRequest::from_bytes(slice)
    }
}

impl Base58 for BlindSignRequest {}

impl BlindSignRequest {
    fn verify_proof(&self, params: &Parameters, pub_key: &elgamal::PublicKey) -> bool {
        self.pi_s.verify(
            params,
            pub_key,
            &self.commitment,
            &self.attributes_ciphertexts,
        )
    }

    // TODO: perhaps also include pi_s.len()?
    // to be determined once we implement serde to make sure its 1:1 compatible
    // with bincode
    // cm || c.len() || c || pi_s
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_byte_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<BlindSignRequest> {
        BlindSignRequest::try_from(bytes)
    }
}


pub fn compute_private_attributes_commitment(
    params: &Parameters,
    private_attributes: &[Attribute],
    hs: &[G1Affine],
) -> (Scalar, G1Projective) {
    let commitment_opening = params.random_scalar();

    // Produces h0 ^ m0 * h1^m1 * .... * hn^mn
    // where m0, m1, ...., mn are private attributes
    let attr_cm = private_attributes
        .iter().zip(hs).map(|(&m, h)| h * m).sum::<G1Projective>();

    // Produces g1^r * h0 ^ m0 * h1^m1 * .... * hn^mn
    let commitment = params.gen1() * commitment_opening + attr_cm;
    (commitment_opening, commitment)
}

pub fn compute_commitment_hash(commitment: G1Projective) -> G1Projective {
    hash_g1(commitment.to_bytes())
}

pub fn compute_attribute_encryption(
    params: &Parameters,
    private_attributes: &[Attribute],
    pub_key: &elgamal::PublicKey,
    commitment_hash: G1Projective,
) -> (Vec<Ciphertext>, Vec<EphemeralKey>) {
    private_attributes
        .iter()
        .map(|m| pub_key.encrypt(params, &commitment_hash, m))
        .unzip()
}

/// Builds cryptographic material required for blind sign.
pub fn prepare_blind_sign(
    params: &Parameters,
    pub_key: &elgamal::PublicKey,
    private_attributes: &[Attribute],
    public_attributes: &[Attribute],
) -> Result<BlindSignRequest> {
    if private_attributes.is_empty() {
        return Err(CoconutError::Issuance(
            "Tried to prepare blind sign request for an empty set of private attributes"
                .to_string(),
        ));
    }

    let hs = params.gen_hs();
    if private_attributes.len() + public_attributes.len() > hs.len() {
        return Err(CoconutError::IssuanceMaxAttributes {
            max: hs.len(),
            requested: private_attributes.len() + public_attributes.len(),
        });
    }

    let (commitment_opening, commitment) =
        compute_private_attributes_commitment(params, private_attributes, hs);

    // Compute the challenge as the commitment hash
    let commitment_hash = compute_commitment_hash(commitment);
    // build ElGamal encryption
    let (attributes_ciphertexts, ephemeral_keys): (Vec<_>, Vec<_>) = compute_attribute_encryption(params, private_attributes, pub_key, commitment_hash);

    let pi_s = ProofCmCs::construct(
        params,
        pub_key,
        &ephemeral_keys,
        &commitment,
        &commitment_opening,
        private_attributes,
        public_attributes,
    );

    Ok(BlindSignRequest {
        commitment,
        commitment_hash,
        attributes_ciphertexts,
        pi_s,
    })
}

pub fn blind_sign(
    params: &Parameters,
    secret_key: &SecretKey,
    pub_key: &elgamal::PublicKey,
    blind_sign_request: &BlindSignRequest,
    public_attributes: &[Attribute],
) -> Result<BlindedSignature> {
    let num_private = blind_sign_request.attributes_ciphertexts.len();
    let hs = params.gen_hs();

    if num_private + public_attributes.len() > hs.len() {
        return Err(CoconutError::IssuanceMaxAttributes {
            max: hs.len(),
            requested: num_private + public_attributes.len(),
        });
    }

    // Verify the commitment hash
    let h = hash_g1(blind_sign_request.commitment.to_bytes());
    if !(h == blind_sign_request.commitment_hash) {
        return Err(CoconutError::Issuance(
            "Failed to verify the commitment hash".to_string(),
        ));
    }

    // Verify the ZK proof
    if !blind_sign_request.verify_proof(params, pub_key) {
        return Err(CoconutError::Issuance(
            "Failed to verify the proof of knowledge".to_string(),
        ));
    }

    // in python implementation there are n^2 G1 multiplications, let's do it with a single one instead.
    // i.e. compute h ^ (pub_m[0] * y[m + 1] + ... + pub_m[n] * y[m + n]) directly (where m is number of PRIVATE attributes)
    // rather than ((h ^ pub_m[0]) ^ y[m + 1] , (h ^ pub_m[1]) ^ y[m + 2] , ...).sum() separately
    let signed_public = h * public_attributes
        .iter()
        .zip(secret_key.ys.iter().skip(num_private))
        .map(|(attr, yi)| attr * yi)
        .sum::<Scalar>();

    // c1[0] ^ y[0] * ... * c1[m] ^ y[m]
    let sig_1 = blind_sign_request
        .attributes_ciphertexts
        .iter()
        .map(|ciphertext| ciphertext.c1())
        .zip(secret_key.ys.iter())
        .map(|(c1, yi)| c1 * yi)
        .sum();

    // h ^ x + c2[0] ^ y[0] + ... c2[m] ^ y[m] + h ^ (pub_m[0] * y[m + 1] + ... + pub_m[n] * y[m + n])
    let sig_2 = blind_sign_request
        .attributes_ciphertexts
        .iter()
        .map(|ciphertext| ciphertext.c2())
        .zip(secret_key.ys.iter())
        .map(|(c2, yi)| c2 * yi)
        .chain(std::iter::once(h * secret_key.x))
        .chain(std::iter::once(signed_public))
        .sum();

    Ok(BlindedSignature(h, elgamal::Ciphertext(sig_1, sig_2)))
}

#[cfg(test)]
pub fn sign(
    params: &mut Parameters,
    secret_key: &SecretKey,
    public_attributes: &[Attribute],
) -> Result<Signature> {
    if public_attributes.len() > secret_key.ys.len() {
        return Err(CoconutError::IssuanceMaxAttributes {
            max: secret_key.ys.len(),
            requested: public_attributes.len(),
        });
    }

    // TODO: why in the python implementation this hash onto the curve is present
    // while it's not used in the paper? the paper uses random exponent instead.
    // (the python implementation hashes string representation of all attributes onto the curve,
    // but I think the same can be achieved by just summing the attributes thus avoiding the unnecessary
    // transformation. If I'm wrong, please correct me.)
    let attributes_sum = public_attributes.iter().sum::<Scalar>();
    let h = hash_g1((params.gen1() * attributes_sum).to_bytes());

    // x + m0 * y0 + m1 * y1 + ... mn * yn
    let exponent = secret_key.x
        + public_attributes
        .iter()
        .zip(secret_key.ys.iter())
        .map(|(m_i, y_i)| m_i * y_i)
        .sum::<Scalar>();

    let sig2 = h * exponent;
    Ok(Signature(h, sig2))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blind_sign_request_bytes_roundtrip() {
        let mut params = Parameters::new(1).unwrap();
        let public_attributes = params.n_random_scalars(0);
        let private_attributes = params.n_random_scalars(1);
        let elgamal_keypair = elgamal::elgamal_keygen(&params);

        let lambda = prepare_blind_sign(
            &mut params,
            elgamal_keypair.public_key(),
            &private_attributes,
            &public_attributes,
        )
            .unwrap();

        let bytes = lambda.to_bytes();
        println!("{:?}", bytes.len());
        assert_eq!(
            BlindSignRequest::try_from(bytes.as_slice()).unwrap(),
            lambda
        );

        let mut params = Parameters::new(4).unwrap();
        let public_attributes = params.n_random_scalars(2);
        let private_attributes = params.n_random_scalars(2);
        let lambda = prepare_blind_sign(
            &mut params,
            elgamal_keypair.public_key(),
            &private_attributes,
            &public_attributes,
        )
            .unwrap();

        let bytes = lambda.to_bytes();
        assert_eq!(
            BlindSignRequest::try_from(bytes.as_slice()).unwrap(),
            lambda
        );
    }
}
