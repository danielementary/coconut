use crate::{
    aggregate_signature_shares, aggregate_verification_keys, blind_sign, default_base_u,
    default_number_of_base_elements_l, elgamal_keygen, issue_range_signatures,
    issue_set_signatures, prepare_blind_sign, prove_credential_and_range,
    prove_credential_and_set_membership, setup, single_attribute_keygen, ttp_keygen,
    verify_range_credential, verify_set_membership_credential, CoconutError, RawAttribute,
    Signature, SignatureShare, VerificationKey,
};
use bls12_381::Scalar;

#[test]
fn main_set_membership() -> Result<(), CoconutError> {
    let params = setup(1).unwrap();

    // build dummy private attribute 1
    let private_attribute = 1;
    let private_attributes = vec![RawAttribute::Number(private_attribute).into()];
    let public_attributes = params.n_random_scalars(0);

    let elgamal_keypair = elgamal_keygen(&params);

    // generate commitment and encryption
    let blind_sign_request = prepare_blind_sign(
        &params,
        &elgamal_keypair,
        &private_attributes,
        &public_attributes,
    )?;

    // generate_keys
    let coconut_keypairs = ttp_keygen(&params, 2, 3).unwrap();
    let verification_keys: Vec<VerificationKey> = coconut_keypairs
        .iter()
        .map(|keypair| keypair.verification_key())
        .collect();

    // aggregate verification keys
    let verification_key = aggregate_verification_keys(&verification_keys, Some(&[1, 2, 3]))?;

    // generate blinded signatures
    let mut blinded_signatures = Vec::new();
    for keypair in coconut_keypairs {
        let blinded_signature = blind_sign(
            &params,
            &keypair.secret_key(),
            &elgamal_keypair.public_key(),
            &blind_sign_request,
            &public_attributes,
        )?;
        blinded_signatures.push(blinded_signature)
    }

    // Unblind signatures
    let unblinded_signatures: Vec<Signature> = blinded_signatures
        .into_iter()
        .zip(verification_keys.iter())
        .map(|(signature, verification_key)| {
            signature
                .unblind(
                    &params,
                    &elgamal_keypair.private_key(),
                    &verification_key,
                    &private_attributes,
                    &public_attributes,
                    blind_sign_request.commitment_hash,
                )
                .unwrap()
        })
        .collect();

    // Aggregate signatures
    let signature_shares: Vec<SignatureShare> = unblinded_signatures
        .iter()
        .enumerate()
        .map(|(idx, signature)| SignatureShare::new(*signature, (idx + 1) as u64))
        .collect();

    let mut attributes = Vec::with_capacity(private_attributes.len() + public_attributes.len());
    attributes.extend_from_slice(&private_attributes);
    attributes.extend_from_slice(&public_attributes);

    let signature =
        aggregate_signature_shares(&params, &verification_key, &attributes, &signature_shares)?;

    let sp_h = params.gen1() * params.random_scalar();
    let sp_key_pair = single_attribute_keygen(&params);
    let sp_private_key = sp_key_pair.secret_key();
    let set = (0..10).map(|i| RawAttribute::Number(i as u64)).collect();
    let sp_signatures = issue_set_signatures(&sp_h, &sp_private_key, &set);

    let sp_verification_key = sp_key_pair.verification_key();

    // Randomize credentials and generate any cryptographic material to verify them
    let theta = prove_credential_and_set_membership(
        &params,
        &verification_key,
        &sp_verification_key,
        &signature,
        &sp_signatures,
        &private_attributes,
    )?;

    // Verify credentials
    assert!(verify_set_membership_credential(
        &params,
        &verification_key,
        &sp_verification_key,
        &theta,
        &public_attributes,
    ));

    Ok(())
}

#[test]
fn main_set_membership_10() -> Result<(), CoconutError> {
    let params = setup(10).unwrap();

    // build dummy private attribute
    let private_attribute = 1;
    let private_attributes = vec![
        [RawAttribute::Number(private_attribute).into()].to_vec(),
        params.n_random_scalars(9),
    ]
    .concat();
    let public_attributes = params.n_random_scalars(0);

    let elgamal_keypair = elgamal_keygen(&params);

    // generate commitment and encryption
    let blind_sign_request = prepare_blind_sign(
        &params,
        &elgamal_keypair,
        &private_attributes,
        &public_attributes,
    )?;

    // generate_keys
    let coconut_keypairs = ttp_keygen(&params, 2, 3).unwrap();
    let verification_keys: Vec<VerificationKey> = coconut_keypairs
        .iter()
        .map(|keypair| keypair.verification_key())
        .collect();

    // aggregate verification keys
    let verification_key = aggregate_verification_keys(&verification_keys, Some(&[1, 2, 3]))?;

    // generate blinded signatures
    let mut blinded_signatures = Vec::new();
    for keypair in coconut_keypairs {
        let blinded_signature = blind_sign(
            &params,
            &keypair.secret_key(),
            &elgamal_keypair.public_key(),
            &blind_sign_request,
            &public_attributes,
        )?;
        blinded_signatures.push(blinded_signature)
    }

    // Unblind signatures
    let unblinded_signatures: Vec<Signature> = blinded_signatures
        .into_iter()
        .zip(verification_keys.iter())
        .map(|(signature, verification_key)| {
            signature
                .unblind(
                    &params,
                    &elgamal_keypair.private_key(),
                    &verification_key,
                    &private_attributes,
                    &public_attributes,
                    blind_sign_request.commitment_hash,
                )
                .unwrap()
        })
        .collect();

    // Aggregate signatures
    let signature_shares: Vec<SignatureShare> = unblinded_signatures
        .iter()
        .enumerate()
        .map(|(idx, signature)| SignatureShare::new(*signature, (idx + 1) as u64))
        .collect();

    let mut attributes = Vec::with_capacity(private_attributes.len() + public_attributes.len());
    attributes.extend_from_slice(&private_attributes);
    attributes.extend_from_slice(&public_attributes);

    let signature =
        aggregate_signature_shares(&params, &verification_key, &attributes, &signature_shares)?;

    let sp_h = params.gen1() * params.random_scalar();
    let sp_key_pair = single_attribute_keygen(&params);
    let sp_private_key = sp_key_pair.secret_key();
    let set = (0..10).map(|i| RawAttribute::Number(i as u64)).collect();
    let sp_signatures = issue_set_signatures(&sp_h, &sp_private_key, &set);

    let sp_verification_key = sp_key_pair.verification_key();

    // Randomize credentials and generate any cryptographic material to verify them
    let theta = prove_credential_and_set_membership(
        &params,
        &verification_key,
        &sp_verification_key,
        &signature,
        &sp_signatures,
        &private_attributes,
    )?;

    // Verify credentials
    assert!(verify_set_membership_credential(
        &params,
        &verification_key,
        &sp_verification_key,
        &theta,
        &public_attributes,
    ));

    Ok(())
}

#[test]
fn main_set_membership_5_5() -> Result<(), CoconutError> {
    let params = setup(10).unwrap();

    // build dummy private attribute
    let private_attribute = 1;
    let private_attributes = vec![
        [RawAttribute::Number(private_attribute).into()].to_vec(),
        params.n_random_scalars(4),
    ]
    .concat();
    let public_attributes = params.n_random_scalars(5);

    let elgamal_keypair = elgamal_keygen(&params);

    // generate commitment and encryption
    let blind_sign_request = prepare_blind_sign(
        &params,
        &elgamal_keypair,
        &private_attributes,
        &public_attributes,
    )?;

    // generate_keys
    let coconut_keypairs = ttp_keygen(&params, 2, 3).unwrap();
    let verification_keys: Vec<VerificationKey> = coconut_keypairs
        .iter()
        .map(|keypair| keypair.verification_key())
        .collect();

    // aggregate verification keys
    let verification_key = aggregate_verification_keys(&verification_keys, Some(&[1, 2, 3]))?;

    // generate blinded signatures
    let mut blinded_signatures = Vec::new();
    for keypair in coconut_keypairs {
        let blinded_signature = blind_sign(
            &params,
            &keypair.secret_key(),
            &elgamal_keypair.public_key(),
            &blind_sign_request,
            &public_attributes,
        )?;
        blinded_signatures.push(blinded_signature)
    }

    // Unblind signatures
    let unblinded_signatures: Vec<Signature> = blinded_signatures
        .into_iter()
        .zip(verification_keys.iter())
        .map(|(signature, verification_key)| {
            signature
                .unblind(
                    &params,
                    &elgamal_keypair.private_key(),
                    &verification_key,
                    &private_attributes,
                    &public_attributes,
                    blind_sign_request.commitment_hash,
                )
                .unwrap()
        })
        .collect();

    // Aggregate signatures
    let signature_shares: Vec<SignatureShare> = unblinded_signatures
        .iter()
        .enumerate()
        .map(|(idx, signature)| SignatureShare::new(*signature, (idx + 1) as u64))
        .collect();

    let mut attributes = Vec::with_capacity(private_attributes.len() + public_attributes.len());
    attributes.extend_from_slice(&private_attributes);
    attributes.extend_from_slice(&public_attributes);

    let signature =
        aggregate_signature_shares(&params, &verification_key, &attributes, &signature_shares)?;

    let sp_h = params.gen1() * params.random_scalar();
    let sp_key_pair = single_attribute_keygen(&params);
    let sp_private_key = sp_key_pair.secret_key();
    let set = (0..10).map(|i| RawAttribute::Number(i as u64)).collect();
    let sp_signatures = issue_set_signatures(&sp_h, &sp_private_key, &set);

    let sp_verification_key = sp_key_pair.verification_key();

    // Randomize credentials and generate any cryptographic material to verify them
    let theta = prove_credential_and_set_membership(
        &params,
        &verification_key,
        &sp_verification_key,
        &signature,
        &sp_signatures,
        &private_attributes,
    )?;

    // Verify credentials
    assert!(verify_set_membership_credential(
        &params,
        &verification_key,
        &sp_verification_key,
        &theta,
        &public_attributes,
    ));

    Ok(())
}

#[test]
#[should_panic]
fn main_set_membership_out_of_set() {
    let params = setup(1).unwrap();

    // build dummy private attribute 1
    let private_attribute = 1;
    let private_attributes = vec![RawAttribute::Number(private_attribute).into()];
    let public_attributes = params.n_random_scalars(0);

    let elgamal_keypair = elgamal_keygen(&params);

    // generate commitment and encryption
    let blind_sign_request = prepare_blind_sign(
        &params,
        &elgamal_keypair,
        &private_attributes,
        &public_attributes,
    )
    .unwrap();

    // generate_keys
    let coconut_keypairs = ttp_keygen(&params, 2, 3).unwrap();
    let verification_keys: Vec<VerificationKey> = coconut_keypairs
        .iter()
        .map(|keypair| keypair.verification_key())
        .collect();

    // aggregate verification keys
    let verification_key =
        aggregate_verification_keys(&verification_keys, Some(&[1, 2, 3])).unwrap();

    // generate blinded signatures
    let mut blinded_signatures = Vec::new();
    for keypair in coconut_keypairs {
        let blinded_signature = blind_sign(
            &params,
            &keypair.secret_key(),
            &elgamal_keypair.public_key(),
            &blind_sign_request,
            &public_attributes,
        )
        .unwrap();
        blinded_signatures.push(blinded_signature)
    }

    // Unblind signatures
    let unblinded_signatures: Vec<Signature> = blinded_signatures
        .into_iter()
        .zip(verification_keys.iter())
        .map(|(signature, verification_key)| {
            signature
                .unblind(
                    &params,
                    &elgamal_keypair.private_key(),
                    &verification_key,
                    &private_attributes,
                    &public_attributes,
                    blind_sign_request.commitment_hash,
                )
                .unwrap()
        })
        .collect();

    // Aggregate signatures
    let signature_shares: Vec<SignatureShare> = unblinded_signatures
        .iter()
        .enumerate()
        .map(|(idx, signature)| SignatureShare::new(*signature, (idx + 1) as u64))
        .collect();

    let mut attributes = Vec::with_capacity(private_attributes.len() + public_attributes.len());
    attributes.extend_from_slice(&private_attributes);
    attributes.extend_from_slice(&public_attributes);

    let signature =
        aggregate_signature_shares(&params, &verification_key, &attributes, &signature_shares)
            .unwrap();

    let sp_h = params.gen1() * params.random_scalar();
    let sp_key_pair = single_attribute_keygen(&params);
    let sp_private_key = sp_key_pair.secret_key();
    let set = (3..10).map(|i| RawAttribute::Number(i as u64)).collect(); // make sure private attribute is not in the set
    let sp_signatures = issue_set_signatures(&sp_h, &sp_private_key, &set);

    let sp_verification_key = sp_key_pair.verification_key();

    // Randomize credentials and generate any cryptographic material to verify them
    // should panic because the private attribute is not in the set
    prove_credential_and_set_membership(
        &params,
        &verification_key,
        &sp_verification_key,
        &signature,
        &sp_signatures,
        &private_attributes,
    )
    .unwrap();
}

#[test]
fn main_range() -> Result<(), CoconutError> {
    let params = setup(1).unwrap();

    // build dummy private attribute 10
    let private_attribute = 10;
    let private_attributes = vec![RawAttribute::Number(private_attribute).into()];
    let public_attributes = params.n_random_scalars(0);

    let elgamal_keypair = elgamal_keygen(&params);

    // generate commitment and encryption
    let blind_sign_request = prepare_blind_sign(
        &params,
        &elgamal_keypair,
        &private_attributes,
        &public_attributes,
    )?;

    // generate_keys
    let coconut_keypairs = ttp_keygen(&params, 2, 3).unwrap();
    let verification_keys: Vec<VerificationKey> = coconut_keypairs
        .iter()
        .map(|keypair| keypair.verification_key())
        .collect();

    // aggregate verification keys
    let verification_key = aggregate_verification_keys(&verification_keys, Some(&[1, 2, 3]))?;

    // generate blinded signatures
    let mut blinded_signatures = Vec::new();
    for keypair in coconut_keypairs {
        let blinded_signature = blind_sign(
            &params,
            &keypair.secret_key(),
            &elgamal_keypair.public_key(),
            &blind_sign_request,
            &public_attributes,
        )?;
        blinded_signatures.push(blinded_signature)
    }

    // Unblind signatures
    let unblinded_signatures: Vec<Signature> = blinded_signatures
        .into_iter()
        .zip(verification_keys.iter())
        .map(|(signature, verification_key)| {
            signature
                .unblind(
                    &params,
                    &elgamal_keypair.private_key(),
                    &verification_key,
                    &private_attributes,
                    &public_attributes,
                    blind_sign_request.commitment_hash,
                )
                .unwrap()
        })
        .collect();

    // Aggregate signatures
    let signature_shares: Vec<SignatureShare> = unblinded_signatures
        .iter()
        .enumerate()
        .map(|(idx, signature)| SignatureShare::new(*signature, (idx + 1) as u64))
        .collect();

    let mut attributes = Vec::with_capacity(private_attributes.len() + public_attributes.len());
    attributes.extend_from_slice(&private_attributes);
    attributes.extend_from_slice(&public_attributes);

    let signature =
        aggregate_signature_shares(&params, &verification_key, &attributes, &signature_shares)?;

    // parameters
    let base_u = default_base_u();
    let number_of_base_elements_l = default_number_of_base_elements_l();

    let lower_bound = Scalar::from(5);
    let upper_bound = Scalar::from(15);

    let sp_h = params.gen1() * params.random_scalar();
    let sp_key_pair = single_attribute_keygen(&params);
    let sp_private_key = sp_key_pair.secret_key();
    let sp_signatures = issue_range_signatures(&sp_h, &sp_private_key, 0, base_u);

    let sp_verification_key = sp_key_pair.verification_key();

    // Randomize credentials and generate any cryptographic material to verify them
    let theta = prove_credential_and_range(
        &params,
        base_u,
        number_of_base_elements_l,
        lower_bound,
        upper_bound,
        &verification_key,
        &sp_verification_key,
        &signature,
        &sp_signatures,
        &private_attributes,
    )?;

    // Verify credentials
    assert!(verify_range_credential(
        &params,
        &verification_key,
        &sp_verification_key,
        &theta,
        &public_attributes,
    ));

    Ok(())
}

#[test]
fn main_range_10() -> Result<(), CoconutError> {
    let params = setup(10).unwrap();

    // build dummy private attribute 10
    let private_attribute = 10;
    let private_attributes = vec![
        [RawAttribute::Number(private_attribute).into()].to_vec(),
        params.n_random_scalars(9),
    ]
    .concat();
    let public_attributes = params.n_random_scalars(0);

    let elgamal_keypair = elgamal_keygen(&params);

    // generate commitment and encryption
    let blind_sign_request = prepare_blind_sign(
        &params,
        &elgamal_keypair,
        &private_attributes,
        &public_attributes,
    )?;

    // generate_keys
    let coconut_keypairs = ttp_keygen(&params, 2, 3).unwrap();
    let verification_keys: Vec<VerificationKey> = coconut_keypairs
        .iter()
        .map(|keypair| keypair.verification_key())
        .collect();

    // aggregate verification keys
    let verification_key = aggregate_verification_keys(&verification_keys, Some(&[1, 2, 3]))?;

    // generate blinded signatures
    let mut blinded_signatures = Vec::new();
    for keypair in coconut_keypairs {
        let blinded_signature = blind_sign(
            &params,
            &keypair.secret_key(),
            &elgamal_keypair.public_key(),
            &blind_sign_request,
            &public_attributes,
        )?;
        blinded_signatures.push(blinded_signature)
    }

    // Unblind signatures
    let unblinded_signatures: Vec<Signature> = blinded_signatures
        .into_iter()
        .zip(verification_keys.iter())
        .map(|(signature, verification_key)| {
            signature
                .unblind(
                    &params,
                    &elgamal_keypair.private_key(),
                    &verification_key,
                    &private_attributes,
                    &public_attributes,
                    blind_sign_request.commitment_hash,
                )
                .unwrap()
        })
        .collect();

    // Aggregate signatures
    let signature_shares: Vec<SignatureShare> = unblinded_signatures
        .iter()
        .enumerate()
        .map(|(idx, signature)| SignatureShare::new(*signature, (idx + 1) as u64))
        .collect();

    let mut attributes = Vec::with_capacity(private_attributes.len() + public_attributes.len());
    attributes.extend_from_slice(&private_attributes);
    attributes.extend_from_slice(&public_attributes);

    let signature =
        aggregate_signature_shares(&params, &verification_key, &attributes, &signature_shares)?;

    // parameters
    let base_u = default_base_u();
    let number_of_base_elements_l = default_number_of_base_elements_l();

    let lower_bound = Scalar::from(5);
    let upper_bound = Scalar::from(15);

    let sp_h = params.gen1() * params.random_scalar();
    let sp_key_pair = single_attribute_keygen(&params);
    let sp_private_key = sp_key_pair.secret_key();
    let sp_signatures = issue_range_signatures(&sp_h, &sp_private_key, 0, base_u);

    let sp_verification_key = sp_key_pair.verification_key();

    // Randomize credentials and generate any cryptographic material to verify them
    let theta = prove_credential_and_range(
        &params,
        base_u,
        number_of_base_elements_l,
        lower_bound,
        upper_bound,
        &verification_key,
        &sp_verification_key,
        &signature,
        &sp_signatures,
        &private_attributes,
    )?;

    // Verify credentials
    assert!(verify_range_credential(
        &params,
        &verification_key,
        &sp_verification_key,
        &theta,
        &public_attributes,
    ));

    Ok(())
}

#[test]
fn main_range_5_5() -> Result<(), CoconutError> {
    let params = setup(10).unwrap();

    // build dummy private attribute 10
    let private_attribute = 10;
    let private_attributes = vec![
        [RawAttribute::Number(private_attribute).into()].to_vec(),
        params.n_random_scalars(4),
    ]
    .concat();
    let public_attributes = params.n_random_scalars(5);

    let elgamal_keypair = elgamal_keygen(&params);

    // generate commitment and encryption
    let blind_sign_request = prepare_blind_sign(
        &params,
        &elgamal_keypair,
        &private_attributes,
        &public_attributes,
    )?;

    // generate_keys
    let coconut_keypairs = ttp_keygen(&params, 2, 3).unwrap();
    let verification_keys: Vec<VerificationKey> = coconut_keypairs
        .iter()
        .map(|keypair| keypair.verification_key())
        .collect();

    // aggregate verification keys
    let verification_key = aggregate_verification_keys(&verification_keys, Some(&[1, 2, 3]))?;

    // generate blinded signatures
    let mut blinded_signatures = Vec::new();
    for keypair in coconut_keypairs {
        let blinded_signature = blind_sign(
            &params,
            &keypair.secret_key(),
            &elgamal_keypair.public_key(),
            &blind_sign_request,
            &public_attributes,
        )?;
        blinded_signatures.push(blinded_signature)
    }

    // Unblind signatures
    let unblinded_signatures: Vec<Signature> = blinded_signatures
        .into_iter()
        .zip(verification_keys.iter())
        .map(|(signature, verification_key)| {
            signature
                .unblind(
                    &params,
                    &elgamal_keypair.private_key(),
                    &verification_key,
                    &private_attributes,
                    &public_attributes,
                    blind_sign_request.commitment_hash,
                )
                .unwrap()
        })
        .collect();

    // Aggregate signatures
    let signature_shares: Vec<SignatureShare> = unblinded_signatures
        .iter()
        .enumerate()
        .map(|(idx, signature)| SignatureShare::new(*signature, (idx + 1) as u64))
        .collect();

    let mut attributes = Vec::with_capacity(private_attributes.len() + public_attributes.len());
    attributes.extend_from_slice(&private_attributes);
    attributes.extend_from_slice(&public_attributes);

    let signature =
        aggregate_signature_shares(&params, &verification_key, &attributes, &signature_shares)?;

    // parameters
    let base_u = default_base_u();
    let number_of_base_elements_l = default_number_of_base_elements_l();

    let lower_bound = Scalar::from(5);
    let upper_bound = Scalar::from(15);

    let sp_h = params.gen1() * params.random_scalar();
    let sp_key_pair = single_attribute_keygen(&params);
    let sp_private_key = sp_key_pair.secret_key();
    let sp_signatures = issue_range_signatures(&sp_h, &sp_private_key, 0, base_u);

    let sp_verification_key = sp_key_pair.verification_key();

    // Randomize credentials and generate any cryptographic material to verify them
    let theta = prove_credential_and_range(
        &params,
        base_u,
        number_of_base_elements_l,
        lower_bound,
        upper_bound,
        &verification_key,
        &sp_verification_key,
        &signature,
        &sp_signatures,
        &private_attributes,
    )?;

    // Verify credentials
    assert!(verify_range_credential(
        &params,
        &verification_key,
        &sp_verification_key,
        &theta,
        &public_attributes,
    ));

    Ok(())
}

#[test]
#[should_panic]
fn main_range_out_of_lower_bound() {
    let params = setup(1).unwrap();

    // build dummy private attribute 10
    let private_attribute = 4;
    let private_attributes = vec![RawAttribute::Number(private_attribute).into()];
    let public_attributes = params.n_random_scalars(0);

    let elgamal_keypair = elgamal_keygen(&params);

    // generate commitment and encryption
    let blind_sign_request = prepare_blind_sign(
        &params,
        &elgamal_keypair,
        &private_attributes,
        &public_attributes,
    )
    .unwrap();

    // generate_keys
    let coconut_keypairs = ttp_keygen(&params, 2, 3).unwrap();
    let verification_keys: Vec<VerificationKey> = coconut_keypairs
        .iter()
        .map(|keypair| keypair.verification_key())
        .collect();

    // aggregate verification keys
    let verification_key =
        aggregate_verification_keys(&verification_keys, Some(&[1, 2, 3])).unwrap();

    // generate blinded signatures
    let mut blinded_signatures = Vec::new();
    for keypair in coconut_keypairs {
        let blinded_signature = blind_sign(
            &params,
            &keypair.secret_key(),
            &elgamal_keypair.public_key(),
            &blind_sign_request,
            &public_attributes,
        )
        .unwrap();
        blinded_signatures.push(blinded_signature)
    }

    // Unblind signatures
    let unblinded_signatures: Vec<Signature> = blinded_signatures
        .into_iter()
        .zip(verification_keys.iter())
        .map(|(signature, verification_key)| {
            signature
                .unblind(
                    &params,
                    &elgamal_keypair.private_key(),
                    &verification_key,
                    &private_attributes,
                    &public_attributes,
                    blind_sign_request.commitment_hash,
                )
                .unwrap()
        })
        .collect();

    // Aggregate signatures
    let signature_shares: Vec<SignatureShare> = unblinded_signatures
        .iter()
        .enumerate()
        .map(|(idx, signature)| SignatureShare::new(*signature, (idx + 1) as u64))
        .collect();

    let mut attributes = Vec::with_capacity(private_attributes.len() + public_attributes.len());
    attributes.extend_from_slice(&private_attributes);
    attributes.extend_from_slice(&public_attributes);

    let signature =
        aggregate_signature_shares(&params, &verification_key, &attributes, &signature_shares)
            .unwrap();

    // parameters
    let base_u = default_base_u();
    let number_of_base_elements_l = default_number_of_base_elements_l();

    let lower_bound = Scalar::from(5);
    let upper_bound = Scalar::from(15);

    let sp_h = params.gen1() * params.random_scalar();
    let sp_key_pair = single_attribute_keygen(&params);
    let sp_private_key = sp_key_pair.secret_key();
    let sp_signatures = issue_range_signatures(&sp_h, &sp_private_key, 0, base_u);

    let sp_verification_key = sp_key_pair.verification_key();

    // Randomize credentials and generate any cryptographic material to verify them
    prove_credential_and_range(
        &params,
        base_u,
        number_of_base_elements_l,
        lower_bound,
        upper_bound,
        &verification_key,
        &sp_verification_key,
        &signature,
        &sp_signatures,
        &private_attributes,
    )
    .unwrap();
}

#[test]
fn main_range_lower_bound() -> Result<(), CoconutError> {
    let params = setup(1).unwrap();

    // build dummy private attribute 10
    let private_attribute = 5;
    let private_attributes = vec![RawAttribute::Number(private_attribute).into()];
    let public_attributes = params.n_random_scalars(0);

    let elgamal_keypair = elgamal_keygen(&params);

    // generate commitment and encryption
    let blind_sign_request = prepare_blind_sign(
        &params,
        &elgamal_keypair,
        &private_attributes,
        &public_attributes,
    )?;

    // generate_keys
    let coconut_keypairs = ttp_keygen(&params, 2, 3).unwrap();
    let verification_keys: Vec<VerificationKey> = coconut_keypairs
        .iter()
        .map(|keypair| keypair.verification_key())
        .collect();

    // aggregate verification keys
    let verification_key = aggregate_verification_keys(&verification_keys, Some(&[1, 2, 3]))?;

    // generate blinded signatures
    let mut blinded_signatures = Vec::new();
    for keypair in coconut_keypairs {
        let blinded_signature = blind_sign(
            &params,
            &keypair.secret_key(),
            &elgamal_keypair.public_key(),
            &blind_sign_request,
            &public_attributes,
        )?;
        blinded_signatures.push(blinded_signature)
    }

    // Unblind signatures
    let unblinded_signatures: Vec<Signature> = blinded_signatures
        .into_iter()
        .zip(verification_keys.iter())
        .map(|(signature, verification_key)| {
            signature
                .unblind(
                    &params,
                    &elgamal_keypair.private_key(),
                    &verification_key,
                    &private_attributes,
                    &public_attributes,
                    blind_sign_request.commitment_hash,
                )
                .unwrap()
        })
        .collect();

    // Aggregate signatures
    let signature_shares: Vec<SignatureShare> = unblinded_signatures
        .iter()
        .enumerate()
        .map(|(idx, signature)| SignatureShare::new(*signature, (idx + 1) as u64))
        .collect();

    let mut attributes = Vec::with_capacity(private_attributes.len() + public_attributes.len());
    attributes.extend_from_slice(&private_attributes);
    attributes.extend_from_slice(&public_attributes);

    let signature =
        aggregate_signature_shares(&params, &verification_key, &attributes, &signature_shares)?;

    // parameters
    let base_u = default_base_u();
    let number_of_base_elements_l = default_number_of_base_elements_l();

    let lower_bound = Scalar::from(5);
    let upper_bound = Scalar::from(15);

    let sp_h = params.gen1() * params.random_scalar();
    let sp_key_pair = single_attribute_keygen(&params);
    let sp_private_key = sp_key_pair.secret_key();
    let sp_signatures = issue_range_signatures(&sp_h, &sp_private_key, 0, base_u);

    let sp_verification_key = sp_key_pair.verification_key();

    // Randomize credentials and generate any cryptographic material to verify them
    let theta = prove_credential_and_range(
        &params,
        base_u,
        number_of_base_elements_l,
        lower_bound,
        upper_bound,
        &verification_key,
        &sp_verification_key,
        &signature,
        &sp_signatures,
        &private_attributes,
    )?;

    // Verify credentials
    assert!(verify_range_credential(
        &params,
        &verification_key,
        &sp_verification_key,
        &theta,
        &public_attributes,
    ));

    Ok(())
}

#[test]
fn main_range_upper_bound() -> Result<(), CoconutError> {
    let params = setup(1).unwrap();

    // build dummy private attribute 10
    let private_attribute = 14;
    let private_attributes = vec![RawAttribute::Number(private_attribute).into()];
    let public_attributes = params.n_random_scalars(0);

    let elgamal_keypair = elgamal_keygen(&params);

    // generate commitment and encryption
    let blind_sign_request = prepare_blind_sign(
        &params,
        &elgamal_keypair,
        &private_attributes,
        &public_attributes,
    )?;

    // generate_keys
    let coconut_keypairs = ttp_keygen(&params, 2, 3).unwrap();
    let verification_keys: Vec<VerificationKey> = coconut_keypairs
        .iter()
        .map(|keypair| keypair.verification_key())
        .collect();

    // aggregate verification keys
    let verification_key = aggregate_verification_keys(&verification_keys, Some(&[1, 2, 3]))?;

    // generate blinded signatures
    let mut blinded_signatures = Vec::new();
    for keypair in coconut_keypairs {
        let blinded_signature = blind_sign(
            &params,
            &keypair.secret_key(),
            &elgamal_keypair.public_key(),
            &blind_sign_request,
            &public_attributes,
        )?;
        blinded_signatures.push(blinded_signature)
    }

    // Unblind signatures
    let unblinded_signatures: Vec<Signature> = blinded_signatures
        .into_iter()
        .zip(verification_keys.iter())
        .map(|(signature, verification_key)| {
            signature
                .unblind(
                    &params,
                    &elgamal_keypair.private_key(),
                    &verification_key,
                    &private_attributes,
                    &public_attributes,
                    blind_sign_request.commitment_hash,
                )
                .unwrap()
        })
        .collect();

    // Aggregate signatures
    let signature_shares: Vec<SignatureShare> = unblinded_signatures
        .iter()
        .enumerate()
        .map(|(idx, signature)| SignatureShare::new(*signature, (idx + 1) as u64))
        .collect();

    let mut attributes = Vec::with_capacity(private_attributes.len() + public_attributes.len());
    attributes.extend_from_slice(&private_attributes);
    attributes.extend_from_slice(&public_attributes);

    let signature =
        aggregate_signature_shares(&params, &verification_key, &attributes, &signature_shares)?;

    // parameters
    let base_u = default_base_u();
    let number_of_base_elements_l = default_number_of_base_elements_l();

    let lower_bound = Scalar::from(5);
    let upper_bound = Scalar::from(15);

    let sp_h = params.gen1() * params.random_scalar();
    let sp_key_pair = single_attribute_keygen(&params);
    let sp_private_key = sp_key_pair.secret_key();
    let sp_signatures = issue_range_signatures(&sp_h, &sp_private_key, 0, base_u);

    let sp_verification_key = sp_key_pair.verification_key();

    // Randomize credentials and generate any cryptographic material to verify them
    let theta = prove_credential_and_range(
        &params,
        base_u,
        number_of_base_elements_l,
        lower_bound,
        upper_bound,
        &verification_key,
        &sp_verification_key,
        &signature,
        &sp_signatures,
        &private_attributes,
    )?;

    // Verify credentials
    assert!(verify_range_credential(
        &params,
        &verification_key,
        &sp_verification_key,
        &theta,
        &public_attributes,
    ));

    Ok(())
}

#[test]
#[should_panic]
fn main_range_out_of_upper_bound() {
    let params = setup(1).unwrap();

    // build dummy private attribute 10
    let private_attribute = 15;
    let private_attributes = vec![RawAttribute::Number(private_attribute).into()];
    let public_attributes = params.n_random_scalars(0);

    let elgamal_keypair = elgamal_keygen(&params);

    // generate commitment and encryption
    let blind_sign_request = prepare_blind_sign(
        &params,
        &elgamal_keypair,
        &private_attributes,
        &public_attributes,
    )
    .unwrap();

    // generate_keys
    let coconut_keypairs = ttp_keygen(&params, 2, 3).unwrap();
    let verification_keys: Vec<VerificationKey> = coconut_keypairs
        .iter()
        .map(|keypair| keypair.verification_key())
        .collect();

    // aggregate verification keys
    let verification_key =
        aggregate_verification_keys(&verification_keys, Some(&[1, 2, 3])).unwrap();

    // generate blinded signatures
    let mut blinded_signatures = Vec::new();
    for keypair in coconut_keypairs {
        let blinded_signature = blind_sign(
            &params,
            &keypair.secret_key(),
            &elgamal_keypair.public_key(),
            &blind_sign_request,
            &public_attributes,
        )
        .unwrap();
        blinded_signatures.push(blinded_signature)
    }

    // Unblind signatures
    let unblinded_signatures: Vec<Signature> = blinded_signatures
        .into_iter()
        .zip(verification_keys.iter())
        .map(|(signature, verification_key)| {
            signature
                .unblind(
                    &params,
                    &elgamal_keypair.private_key(),
                    &verification_key,
                    &private_attributes,
                    &public_attributes,
                    blind_sign_request.commitment_hash,
                )
                .unwrap()
        })
        .collect();

    // Aggregate signatures
    let signature_shares: Vec<SignatureShare> = unblinded_signatures
        .iter()
        .enumerate()
        .map(|(idx, signature)| SignatureShare::new(*signature, (idx + 1) as u64))
        .collect();

    let mut attributes = Vec::with_capacity(private_attributes.len() + public_attributes.len());
    attributes.extend_from_slice(&private_attributes);
    attributes.extend_from_slice(&public_attributes);

    let signature =
        aggregate_signature_shares(&params, &verification_key, &attributes, &signature_shares)
            .unwrap();

    // parameters
    let base_u = default_base_u();
    let number_of_base_elements_l = default_number_of_base_elements_l();

    let lower_bound = Scalar::from(5);
    let upper_bound = Scalar::from(15);

    let sp_h = params.gen1() * params.random_scalar();
    let sp_key_pair = single_attribute_keygen(&params);
    let sp_private_key = sp_key_pair.secret_key();
    let sp_signatures = issue_range_signatures(&sp_h, &sp_private_key, 0, base_u);

    let sp_verification_key = sp_key_pair.verification_key();

    // Randomize credentials and generate any cryptographic material to verify them
    prove_credential_and_range(
        &params,
        base_u,
        number_of_base_elements_l,
        lower_bound,
        upper_bound,
        &verification_key,
        &sp_verification_key,
        &signature,
        &sp_signatures,
        &private_attributes,
    )
    .unwrap();
}
