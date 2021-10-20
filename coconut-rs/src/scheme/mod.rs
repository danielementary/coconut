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

// TODO: implement https://crates.io/crates/signature traits?

use std::convert::TryFrom;
use std::convert::TryInto;

use bls12_381::{G1Projective, G2Prepared, G2Projective, Scalar};
use group::Curve;

pub use keygen::{SecretKey, VerificationKey};

use crate::elgamal::Ciphertext;
use crate::error::{CoconutError, Result};
use crate::scheme::aggregation::{aggregate_signature_shares, aggregate_signatures};
use crate::scheme::setup::Parameters;
use crate::scheme::verification::check_bilinear_pairing;
use crate::scheme::verification_set_membership::issue_membership_signatures;
use crate::traits::{Base58, Bytable};
use crate::utils::try_deserialize_g1_projective;
use crate::{elgamal, Attribute};

pub mod aggregation;
pub mod issuance;
pub mod keygen;
pub mod setup;
pub mod verification;
pub mod verification_set_membership;

pub type SignerIndex = u64;

// (h, s)
#[derive(Debug, Clone, Copy)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Signature(pub(crate) G1Projective, pub(crate) G1Projective);

pub type PartialSignature = Signature;

impl TryFrom<&[u8]> for Signature {
    type Error = CoconutError;

    fn try_from(bytes: &[u8]) -> Result<Signature> {
        if bytes.len() != 96 {
            return Err(CoconutError::Deserialization(format!(
                "Signature must be exactly 96 bytes, got {}",
                bytes.len()
            )));
        }

        let sig1_bytes: &[u8; 48] = &bytes[..48].try_into().expect("Slice size != 48");
        let sig2_bytes: &[u8; 48] = &bytes[48..].try_into().expect("Slice size != 48");

        let sig1 = try_deserialize_g1_projective(
            &sig1_bytes,
            CoconutError::Deserialization("Failed to deserialize compressed sig1".to_string()),
        )?;

        let sig2 = try_deserialize_g1_projective(
            &sig2_bytes,
            CoconutError::Deserialization("Failed to deserialize compressed sig2".to_string()),
        )?;

        Ok(Signature(sig1, sig2))
    }
}

impl Signature {
    pub(crate) fn sig1(&self) -> &G1Projective {
        &self.0
    }

    pub(crate) fn sig2(&self) -> &G1Projective {
        &self.1
    }

    pub fn randomise(&self, params: &Parameters) -> (Signature, Scalar) {
        let r = params.random_scalar();
        let r_prime = params.random_scalar();
        let h_prime = self.0 * r_prime;
        let s_prime = (self.1 * r_prime) + (h_prime * r);
        (Signature(h_prime, s_prime), r)
    }

    pub fn to_bytes(self) -> [u8; 96] {
        let mut bytes = [0u8; 96];
        bytes[..48].copy_from_slice(&self.0.to_affine().to_compressed());
        bytes[48..].copy_from_slice(&self.1.to_affine().to_compressed());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Signature> {
        Signature::try_from(bytes)
    }
}

impl Bytable for Signature {
    fn to_byte_vec(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }

    fn try_from_byte_slice(slice: &[u8]) -> Result<Self> {
        Signature::from_bytes(slice)
    }
}

impl Base58 for Signature {}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct BlindedSignature(G1Projective, elgamal::Ciphertext);

impl Bytable for BlindedSignature {
    fn to_byte_vec(&self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }

    fn try_from_byte_slice(slice: &[u8]) -> Result<Self> {
        Self::from_bytes(slice)
    }
}

impl Base58 for BlindedSignature {}

impl TryFrom<&[u8]> for BlindedSignature {
    type Error = CoconutError;

    fn try_from(bytes: &[u8]) -> Result<BlindedSignature> {
        if bytes.len() != 144 {
            return Err(CoconutError::Deserialization(format!(
                "BlindedSignature must be exactly 144 bytes, got {}",
                bytes.len()
            )));
        }

        let h_bytes: &[u8; 48] = &bytes[..48].try_into().expect("Slice size != 48");

        let h = try_deserialize_g1_projective(
            &h_bytes,
            CoconutError::Deserialization("Failed to deserialize compressed h".to_string()),
        )?;
        let c_tilde = Ciphertext::try_from(&bytes[48..])?;

        Ok(BlindedSignature(h, c_tilde))
    }
}

impl BlindedSignature {
    pub fn unblind(
        &self,
        params: &Parameters,
        private_key: &elgamal::PrivateKey,
        partial_verification_key: &VerificationKey,
        private_attributes: &[Attribute],
        public_attributes: &[Attribute],
        commitment_hash: G1Projective,
    ) -> Result<Signature> {
        // parse the signature
        let h = &self.0;
        let c = &self.1;
        let sig2 = private_key.decrypt(c);

        // Verify the commitment hash
        if !(commitment_hash == *h) {
            return Err(CoconutError::Unblind(
                "Verification of commitment hash from signature failed".to_string(),
            ));
        }

        let alpha = partial_verification_key.alpha;

        let tmp = private_attributes
            .iter()
            .chain(public_attributes.iter())
            .zip(partial_verification_key.beta.iter())
            .map(|(attr, beta_i)| beta_i * attr)
            .sum::<G2Projective>();

        // Verify the signature share
        if !check_bilinear_pairing(
            &h.to_affine(),
            &G2Prepared::from((alpha + tmp).to_affine()),
            &sig2.to_affine(),
            params.prepared_miller_g2(),
        ) {
            return Err(CoconutError::Unblind(
                "Verification of signature share failed".to_string(),
            ));
        }

        Ok(Signature(self.0, sig2))
    }

    pub fn to_bytes(&self) -> [u8; 144] {
        let mut bytes = [0u8; 144];
        bytes[..48].copy_from_slice(&self.0.to_affine().to_compressed());
        bytes[48..].copy_from_slice(&self.1.to_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<BlindedSignature> {
        BlindedSignature::try_from(bytes)
    }
}

// perhaps this should take signature by reference? we'll see how it goes
pub struct SignatureShare {
    signature: Signature,
    index: SignerIndex,
}

impl SignatureShare {
    pub fn new(signature: Signature, index: SignerIndex) -> Self {
        SignatureShare { signature, index }
    }

    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    pub fn index(&self) -> SignerIndex {
        self.index
    }

    // pub fn aggregate(shares: &[Self]) -> Result<Signature> {
    //     aggregate_signature_shares(shares)
    // }
}

#[cfg(test)]
mod tests {
    use crate::scheme::aggregation::aggregate_verification_keys;
    use crate::scheme::issuance::{blind_sign, prepare_blind_sign, sign};
    use crate::scheme::keygen::{keygen, ttp_keygen};
    use crate::scheme::verification::{prove_credential, verify, verify_credential};

    use super::*;

    #[test]
    fn verification_on_two_private_attributes() {
        let mut params = Parameters::new(2).unwrap();
        let private_attributes = params.n_random_scalars(2);
        let elgamal_keypair = elgamal::elgamal_keygen(&mut params);

        let keypair1 = keygen(&mut params);
        let keypair2 = keygen(&mut params);

        let lambda =
            prepare_blind_sign(&mut params, &elgamal_keypair, &private_attributes, &[]).unwrap();

        let sig1 = blind_sign(
            &mut params,
            &keypair1.secret_key(),
            elgamal_keypair.public_key(),
            &lambda,
            &[],
        )
        .unwrap()
        .unblind(
            &params,
            elgamal_keypair.private_key(),
            &keypair1.verification_key(),
            &private_attributes,
            &[],
            lambda.commitment_hash,
        )
        .unwrap();

        let sig2 = blind_sign(
            &mut params,
            &keypair2.secret_key(),
            elgamal_keypair.public_key(),
            &lambda,
            &[],
        )
        .unwrap()
        .unblind(
            &params,
            elgamal_keypair.private_key(),
            &keypair2.verification_key(),
            &private_attributes,
            &[],
            lambda.commitment_hash,
        )
        .unwrap();

        let theta1 = prove_credential(
            &mut params,
            &keypair1.verification_key(),
            &sig1,
            &private_attributes,
        )
        .unwrap();

        let theta2 = prove_credential(
            &mut params,
            &keypair2.verification_key(),
            &sig2,
            &private_attributes,
        )
        .unwrap();

        assert!(verify_credential(
            &params,
            &keypair1.verification_key(),
            &theta1,
            &[],
        ));

        assert!(verify_credential(
            &params,
            &keypair2.verification_key(),
            &theta2,
            &[],
        ));

        assert!(!verify_credential(
            &params,
            &keypair1.verification_key(),
            &theta2,
            &[],
        ));
    }

    #[test]
    fn verification_on_two_public_attributes() {
        let mut params = Parameters::new(2).unwrap();
        let attributes = params.n_random_scalars(2);

        let keypair1 = keygen(&mut params);
        let keypair2 = keygen(&mut params);
        let sig1 = sign(&mut params, &keypair1.secret_key(), &attributes).unwrap();
        let sig2 = sign(&mut params, &keypair2.secret_key(), &attributes).unwrap();

        assert!(verify(
            &params,
            &keypair1.verification_key(),
            &attributes,
            &sig1,
        ));

        assert!(!verify(
            &params,
            &keypair2.verification_key(),
            &attributes,
            &sig1,
        ));

        assert!(!verify(
            &params,
            &keypair1.verification_key(),
            &attributes,
            &sig2,
        ));
    }

    #[test]
    fn verification_on_two_public_and_two_private_attributes() {
        let mut params = Parameters::new(4).unwrap();
        let public_attributes = params.n_random_scalars(2);
        let private_attributes = params.n_random_scalars(2);
        let elgamal_keypair = elgamal::elgamal_keygen(&mut params);

        let keypair1 = keygen(&mut params);
        let keypair2 = keygen(&mut params);

        let lambda = prepare_blind_sign(
            &mut params,
            &elgamal_keypair,
            &private_attributes,
            &public_attributes,
        )
        .unwrap();

        let sig1 = blind_sign(
            &mut params,
            &keypair1.secret_key(),
            elgamal_keypair.public_key(),
            &lambda,
            &public_attributes,
        )
        .unwrap()
        .unblind(
            &params,
            elgamal_keypair.private_key(),
            &keypair1.verification_key(),
            &private_attributes,
            &public_attributes,
            lambda.commitment_hash,
        )
        .unwrap();

        let sig2 = blind_sign(
            &mut params,
            &keypair2.secret_key(),
            elgamal_keypair.public_key(),
            &lambda,
            &public_attributes,
        )
        .unwrap()
        .unblind(
            &params,
            elgamal_keypair.private_key(),
            &keypair2.verification_key(),
            &private_attributes,
            &public_attributes,
            lambda.commitment_hash,
        )
        .unwrap();

        let theta1 = prove_credential(
            &mut params,
            &keypair1.verification_key(),
            &sig1,
            &private_attributes,
        )
        .unwrap();

        let theta2 = prove_credential(
            &mut params,
            &keypair2.verification_key(),
            &sig2,
            &private_attributes,
        )
        .unwrap();

        assert!(verify_credential(
            &params,
            &keypair1.verification_key(),
            &theta1,
            &public_attributes,
        ));

        assert!(verify_credential(
            &params,
            &keypair2.verification_key(),
            &theta2,
            &public_attributes,
        ));

        assert!(!verify_credential(
            &params,
            &keypair1.verification_key(),
            &theta2,
            &public_attributes,
        ));
    }

    #[test]
    fn verification_on_two_public_and_two_private_attributes_from_two_signers() {
        let mut params = Parameters::new(4).unwrap();
        let public_attributes = params.n_random_scalars(2);
        let private_attributes = params.n_random_scalars(2);
        let elgamal_keypair = elgamal::elgamal_keygen(&params);

        let keypairs = ttp_keygen(&mut params, 2, 3).unwrap();

        let lambda = prepare_blind_sign(
            &mut params,
            &elgamal_keypair,
            &private_attributes,
            &public_attributes,
        )
        .unwrap();

        let sigs = keypairs
            .iter()
            .map(|keypair| {
                blind_sign(
                    &mut params,
                    &keypair.secret_key(),
                    elgamal_keypair.public_key(),
                    &lambda,
                    &public_attributes,
                )
                .unwrap()
                .unblind(
                    &params,
                    elgamal_keypair.private_key(),
                    &keypair.verification_key(),
                    &private_attributes,
                    &public_attributes,
                    lambda.commitment_hash,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        let vks = keypairs
            .into_iter()
            .map(|keypair| keypair.verification_key())
            .collect::<Vec<_>>();

        let mut attributes = Vec::with_capacity(private_attributes.len() + public_attributes.len());
        attributes.extend_from_slice(&private_attributes);
        attributes.extend_from_slice(&public_attributes);

        let aggr_vk = aggregate_verification_keys(&vks[..2], Some(&[1, 2])).unwrap();
        let aggr_sig =
            aggregate_signatures(&params, &aggr_vk, &attributes, &sigs[..2], Some(&[1, 2]))
                .unwrap();

        let theta =
            prove_credential(&mut params, &aggr_vk, &aggr_sig, &private_attributes).unwrap();

        assert!(verify_credential(
            &params,
            &aggr_vk,
            &theta,
            &public_attributes,
        ));

        // taking different subset of keys and credentials
        let aggr_vk = aggregate_verification_keys(&vks[1..], Some(&[2, 3])).unwrap();
        let aggr_sig =
            aggregate_signatures(&params, &aggr_vk, &attributes, &sigs[1..], Some(&[2, 3]))
                .unwrap();

        let theta =
            prove_credential(&mut params, &aggr_vk, &aggr_sig, &private_attributes).unwrap();

        assert!(verify_credential(
            &params,
            &aggr_vk,
            &theta,
            &public_attributes,
        ));
    }

    #[test]
    fn signature_bytes_roundtrip() {
        let params = Parameters::default();
        let r = params.random_scalar();
        let s = params.random_scalar();
        let signature = Signature(params.gen1() * r, params.gen1() * s);
        let bytes = signature.to_bytes();

        // also make sure it is equivalent to the internal g1 compressed bytes concatenated
        let expected_bytes = [
            signature.0.to_affine().to_compressed(),
            signature.1.to_affine().to_compressed(),
        ]
        .concat();
        assert_eq!(expected_bytes, bytes);
        assert_eq!(signature, Signature::try_from(&bytes[..]).unwrap())
    }

    #[test]
    fn blinded_signature_bytes_roundtrip() {
        let params = Parameters::default();
        let r = params.random_scalar();
        let s = params.random_scalar();
        let t = params.random_scalar();
        let blinded_sig = BlindedSignature(
            params.gen1() * t,
            Ciphertext(params.gen1() * r, params.gen1() * s),
        );
        let bytes = blinded_sig.to_bytes();

        // also make sure it is equivalent to the internal g1 compressed bytes concatenated
        let expected_bytes = [
            blinded_sig.0.to_affine().to_compressed(),
            blinded_sig.1 .0.to_affine().to_compressed(),
            blinded_sig.1 .1.to_affine().to_compressed(),
        ]
        .concat();
        assert_eq!(expected_bytes, bytes);
        assert_eq!(blinded_sig, BlindedSignature::try_from(&bytes[..]).unwrap())
    }
}
