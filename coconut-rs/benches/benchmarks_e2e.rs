use criterion::{criterion_group, criterion_main, Criterion};

use core::time::Duration;

use bls12_381::Scalar;

use coconut_rs::{
    aggregate_signature_shares, aggregate_verification_keys, blind_sign, elgamal_keygen,
    issue_membership_signatures, issue_range_signatures, prepare_blind_sign, prove_credential,
    prove_credential_and_range, prove_credential_and_set_membership, setup, ttp_keygen,
    verify_credential, verify_range_credential, verify_set_membership_credential, RawAttribute,
    Signature, SignatureShare, VerificationKey,
};

pub fn bench_e2e_runs(c: &mut Criterion) {
    // setup with no proof
    let params = setup(1).unwrap();

    let private_attributes = params.n_random_scalars(1);
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

    // Unblind

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

    // Randomize credentials and generate any cryptographic material to verify them
    let signature =
        aggregate_signature_shares(&params, &verification_key, &attributes, &signature_shares)
            .unwrap();

    // benchmark prove credential
    c.bench_function("prove credential", |b| {
        b.iter(|| prove_credential(&params, &verification_key, &signature, &private_attributes));
    });

    // Generate cryptographic material to verify them
    let theta =
        prove_credential(&params, &verification_key, &signature, &private_attributes).unwrap();

    // benchmark verify credential
    c.bench_function("verify credential", |b| {
        b.iter(|| verify_credential(&params, &verification_key, &theta, &public_attributes));
    });

    // setup for set membership proof
    let params = setup(1).unwrap();

    // build dummy private attribute 1
    let private_attribute = 1;
    let private_attributes = [RawAttribute::Number(private_attribute).into()];
    let public_attributes = params.n_random_scalars(0);

    let elgamal_keypair = elgamal_keygen(&params);

    // issue signatures for 0, 1 and 2
    let set = [
        RawAttribute::Number(0),
        RawAttribute::Number(1),
        RawAttribute::Number(2),
    ];
    let membership_signatures = issue_membership_signatures(&params, &set);

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

    // pick the membership signature corresponding to the private attribute
    let membership_signature = membership_signatures
        .signatures
        .get(&RawAttribute::Number(private_attribute))
        .unwrap();
    let sp_verification_key = membership_signatures.sp_verification_key;

    // benchmark prove credential and set membership
    c.bench_function("prove credential and set membership", |b| {
        b.iter(|| {
            prove_credential_and_set_membership(
                &params,
                &verification_key,
                &sp_verification_key,
                &signature,
                &membership_signature,
                &private_attributes,
            )
        });
    });

    // Randomize credentials and generate any cryptographic material to verify them
    let theta = prove_credential_and_set_membership(
        &params,
        &verification_key,
        &sp_verification_key,
        &signature,
        &membership_signature,
        &private_attributes,
    )
    .unwrap();

    // benchmark verify credential
    c.bench_function("verify credential and set membership", |b| {
        b.iter(|| {
            verify_set_membership_credential(
                &params,
                &verification_key,
                &sp_verification_key,
                &theta,
                &public_attributes,
            )
        });
    });

    // setup for range proof
    let params = setup(1).unwrap();

    // build dummy private attribute 1
    let private_attribute = 10;
    let private_attributes = [RawAttribute::Number(private_attribute).into()];
    let public_attributes = params.n_random_scalars(0);

    let elgamal_keypair = elgamal_keygen(&params);

    // issue range signatures for element 0..U-1
    let a = Scalar::from(5);
    let b = Scalar::from(15);
    let range_signatures = issue_range_signatures(&params);

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

    let sp_verification_key = &range_signatures.sp_verification_key;

    // benchmark prove credential and range proof
    c.bench_function("prove credential and range proof", |b2| {
        b2.iter(|| {
            prove_credential_and_range(
                &params,
                &verification_key,
                &sp_verification_key,
                &signature,
                &range_signatures,
                a,
                b,
                &private_attributes,
            )
        });
    });

    // Randomize credentials and generate any cryptographic material to verify them
    let theta = prove_credential_and_range(
        &params,
        &verification_key,
        &sp_verification_key,
        &signature,
        &range_signatures,
        a,
        b,
        &private_attributes,
    )
    .unwrap();

    // benchmark verify credential
    c.bench_function("verify credential and set membership", |b| {
        b.iter(|| {
            verify_range_credential(
                &params,
                &verification_key,
                &sp_verification_key,
                &theta,
                &public_attributes,
            )
        });
    });
}

criterion_group!(benches_e2e, bench_e2e_runs);
criterion_main!(benches_e2e);
