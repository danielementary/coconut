use criterion::{criterion_group, criterion_main, Criterion};

use coconut_rs::{
    aggregate_signature_shares, aggregate_verification_keys, blind_sign, elgamal_keygen,
    issue_set_signatures, prepare_blind_sign, prove_credential_and_set_membership, setup,
    single_attribute_keygen, ttp_keygen, verify_set_membership_credential, RawAttribute, Signature,
    SignatureShare, VerificationKey,
};

pub fn e2e_proof_set(c: &mut Criterion) {
    let mut c = c.benchmark_group("sample_size");
    c.sample_size(10);

    let params = setup(1).unwrap();

    let private_attribute = 1;
    let private_attributes = vec![RawAttribute::Number(private_attribute).into()];
    let public_attributes = params.n_random_scalars(0);

    let elgamal_keypair = elgamal_keygen(&params);

    let blind_sign_request = prepare_blind_sign(
        &params,
        &elgamal_keypair,
        &private_attributes,
        &public_attributes,
    )
    .unwrap();

    let coconut_keypairs = ttp_keygen(&params, 7, 10).unwrap();
    let verification_keys: Vec<VerificationKey> = coconut_keypairs
        .iter()
        .map(|keypair| keypair.verification_key())
        .collect();

    let verification_key =
        aggregate_verification_keys(&verification_keys, Some(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]))
            .unwrap();

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

    let set = (0..10).map(|i| RawAttribute::Number(i as u64)).collect();
    c.bench_function("Issuance 10", |b| {
        b.iter(|| issue_set_signatures(&sp_h, &sp_private_key, &set));
    });

    let sp_signatures = issue_set_signatures(&sp_h, &sp_private_key, &set);
    let sp_verification_key = sp_key_pair.verification_key();

    c.bench_function("Proof 10", |b| {
        b.iter(|| {
            prove_credential_and_set_membership(
                &params,
                &verification_key,
                &sp_verification_key,
                &signature,
                &sp_signatures,
                &private_attributes,
            )
        });
    });

    let theta = prove_credential_and_set_membership(
        &params,
        &verification_key,
        &sp_verification_key,
        &signature,
        &sp_signatures,
        &private_attributes,
    )
    .unwrap();

    println!("theta 10 length {} bytes", theta.to_bytes().len());

    c.bench_function("Verification 10", |b| {
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

    let set = (0..50).map(|i| RawAttribute::Number(i as u64)).collect();
    c.bench_function("Issuance 50", |b| {
        b.iter(|| issue_set_signatures(&sp_h, &sp_private_key, &set));
    });

    let sp_signatures = issue_set_signatures(&sp_h, &sp_private_key, &set);
    let sp_verification_key = sp_key_pair.verification_key();

    c.bench_function("Proof 50", |b| {
        b.iter(|| {
            prove_credential_and_set_membership(
                &params,
                &verification_key,
                &sp_verification_key,
                &signature,
                &sp_signatures,
                &private_attributes,
            )
        });
    });

    let theta = prove_credential_and_set_membership(
        &params,
        &verification_key,
        &sp_verification_key,
        &signature,
        &sp_signatures,
        &private_attributes,
    )
    .unwrap();

    println!("theta 50 length {} bytes", theta.to_bytes().len());

    c.bench_function("Verification 50", |b| {
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

    let set = (0..100).map(|i| RawAttribute::Number(i as u64)).collect();
    c.bench_function("Issuance 100", |b| {
        b.iter(|| issue_set_signatures(&sp_h, &sp_private_key, &set));
    });

    let sp_signatures = issue_set_signatures(&sp_h, &sp_private_key, &set);
    let sp_verification_key = sp_key_pair.verification_key();

    c.bench_function("Proof 100", |b| {
        b.iter(|| {
            prove_credential_and_set_membership(
                &params,
                &verification_key,
                &sp_verification_key,
                &signature,
                &sp_signatures,
                &private_attributes,
            )
        });
    });

    let theta = prove_credential_and_set_membership(
        &params,
        &verification_key,
        &sp_verification_key,
        &signature,
        &sp_signatures,
        &private_attributes,
    )
    .unwrap();

    println!("theta 100 length {} bytes", theta.to_bytes().len());

    c.bench_function("Verification 100", |b| {
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

    let set = (0..500).map(|i| RawAttribute::Number(i as u64)).collect();
    c.bench_function("Issuance 500", |b| {
        b.iter(|| issue_set_signatures(&sp_h, &sp_private_key, &set));
    });

    let sp_signatures = issue_set_signatures(&sp_h, &sp_private_key, &set);
    let sp_verification_key = sp_key_pair.verification_key();

    c.bench_function("Proof 500", |b| {
        b.iter(|| {
            prove_credential_and_set_membership(
                &params,
                &verification_key,
                &sp_verification_key,
                &signature,
                &sp_signatures,
                &private_attributes,
            )
        });
    });

    let theta = prove_credential_and_set_membership(
        &params,
        &verification_key,
        &sp_verification_key,
        &signature,
        &sp_signatures,
        &private_attributes,
    )
    .unwrap();

    println!("theta 500 length {} bytes", theta.to_bytes().len());

    c.bench_function("Verification 500", |b| {
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

    let set = (0..1000).map(|i| RawAttribute::Number(i as u64)).collect();
    c.bench_function("Issuance 1000", |b| {
        b.iter(|| issue_set_signatures(&sp_h, &sp_private_key, &set));
    });

    let sp_signatures = issue_set_signatures(&sp_h, &sp_private_key, &set);
    let sp_verification_key = sp_key_pair.verification_key();

    c.bench_function("Proof 1000", |b| {
        b.iter(|| {
            prove_credential_and_set_membership(
                &params,
                &verification_key,
                &sp_verification_key,
                &signature,
                &sp_signatures,
                &private_attributes,
            )
        });
    });

    let theta = prove_credential_and_set_membership(
        &params,
        &verification_key,
        &sp_verification_key,
        &signature,
        &sp_signatures,
        &private_attributes,
    )
    .unwrap();

    println!("theta 1000 length {} bytes", theta.to_bytes().len());

    c.bench_function("Verification 1000", |b| {
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

    c.finish();
}

criterion_group!(benches, e2e_proof_set);
criterion_main!(benches);
