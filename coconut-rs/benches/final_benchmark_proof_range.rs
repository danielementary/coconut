use criterion::{criterion_group, criterion_main, Criterion};
use std::time::Duration;

use bls12_381::Scalar;

use coconut_rs::{
    aggregate_signature_shares, aggregate_verification_keys, blind_sign, elgamal_keygen,
    issue_range_signatures, prepare_blind_sign, prove_credential_and_range, setup,
    single_attribute_keygen, ttp_keygen, verify_range_credential, RawAttribute, Signature,
    SignatureShare, VerificationKey,
};

pub fn bench_e2e_runs(c: &mut Criterion) {
    let mut c = c.benchmark_group("sample_size");
    c.sample_size(10);
    c.measurement_time(Duration::from_secs(25));

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

    let base_u = 2;
    let number_of_base_elements_l = 4;

    let lower_bound = Scalar::from(0);
    let upper_bound = Scalar::from(10);

    let sp_h = params.gen1() * params.random_scalar();
    let sp_key_pair = single_attribute_keygen(&params);
    let sp_private_key = sp_key_pair.secret_key();

    c.bench_function("BASE 2 Issuance 10", |b| {
        b.iter(|| issue_range_signatures(&sp_h, &sp_private_key, 0, base_u));
    });

    let sp_signatures = issue_range_signatures(&sp_h, &sp_private_key, 0, base_u);
    let sp_verification_key = sp_key_pair.verification_key();

    // benchmark prove credential
    c.bench_function("BASE 2 Proof 10", |b| {
        b.iter(|| {
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
        });
    });

    // Generate cryptographic material to verify them
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
    )
    .unwrap();

    println!("theta 10 length {} bytes", theta.to_bytes().len());

    // benchmark verify credential
    c.bench_function("BASE 2 Verification 10", |b| {
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

    let base_u = 2;
    let number_of_base_elements_l = 6;

    let lower_bound = Scalar::from(0);
    let upper_bound = Scalar::from(50);

    let sp_h = params.gen1() * params.random_scalar();
    let sp_key_pair = single_attribute_keygen(&params);
    let sp_private_key = sp_key_pair.secret_key();

    c.bench_function("BASE 2 Issuance 50", |b| {
        b.iter(|| issue_range_signatures(&sp_h, &sp_private_key, 0, base_u));
    });

    let sp_signatures = issue_range_signatures(&sp_h, &sp_private_key, 0, base_u);
    let sp_verification_key = sp_key_pair.verification_key();

    // benchmark prove credential
    c.bench_function("BASE 2 Proof 50", |b| {
        b.iter(|| {
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
        });
    });

    // Generate cryptographic material to verify them
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
    )
    .unwrap();

    println!("theta 50 length {} bytes", theta.to_bytes().len());

    // benchmark verify credential
    c.bench_function("BASE 2 Verification 50", |b| {
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

    let base_u = 2;
    let number_of_base_elements_l = 7;

    let lower_bound = Scalar::from(0);
    let upper_bound = Scalar::from(100);

    let sp_h = params.gen1() * params.random_scalar();
    let sp_key_pair = single_attribute_keygen(&params);
    let sp_private_key = sp_key_pair.secret_key();

    c.bench_function("BASE 2 Issuance 100", |b| {
        b.iter(|| issue_range_signatures(&sp_h, &sp_private_key, 0, base_u));
    });

    let sp_signatures = issue_range_signatures(&sp_h, &sp_private_key, 0, base_u);
    let sp_verification_key = sp_key_pair.verification_key();

    // benchmark prove credential
    c.bench_function("BASE 2 Proof 100", |b| {
        b.iter(|| {
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
        });
    });

    // Generate cryptographic material to verify them
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
    )
    .unwrap();

    println!("theta 100 length {} bytes", theta.to_bytes().len());

    // benchmark verify credential
    c.bench_function("BASE 2 Verification 100", |b| {
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

    let base_u = 2;
    let number_of_base_elements_l = 9;

    let lower_bound = Scalar::from(0);
    let upper_bound = Scalar::from(500);

    let sp_h = params.gen1() * params.random_scalar();
    let sp_key_pair = single_attribute_keygen(&params);
    let sp_private_key = sp_key_pair.secret_key();

    c.bench_function("BASE 2 Issuance 500", |b| {
        b.iter(|| issue_range_signatures(&sp_h, &sp_private_key, 0, base_u));
    });

    let sp_signatures = issue_range_signatures(&sp_h, &sp_private_key, 0, base_u);
    let sp_verification_key = sp_key_pair.verification_key();

    // benchmark prove credential
    c.bench_function("BASE 2 Proof 500", |b| {
        b.iter(|| {
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
        });
    });

    // Generate cryptographic material to verify them
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
    )
    .unwrap();

    println!("theta 500 length {} bytes", theta.to_bytes().len());

    // benchmark verify credential
    c.bench_function("BASE 2 Verification 500", |b| {
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

    let base_u = 2;
    let number_of_base_elements_l = 10;

    let lower_bound = Scalar::from(0);
    let upper_bound = Scalar::from(1000);

    let sp_h = params.gen1() * params.random_scalar();
    let sp_key_pair = single_attribute_keygen(&params);
    let sp_private_key = sp_key_pair.secret_key();

    c.bench_function("BASE 2 Issuance 1000", |b| {
        b.iter(|| issue_range_signatures(&sp_h, &sp_private_key, 0, base_u));
    });

    let sp_signatures = issue_range_signatures(&sp_h, &sp_private_key, 0, base_u);
    let sp_verification_key = sp_key_pair.verification_key();

    // benchmark prove credential
    c.bench_function("BASE 2 Proof 1000", |b| {
        b.iter(|| {
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
        });
    });

    // Generate cryptographic material to verify them
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
    )
    .unwrap();

    println!("theta 1000 length {} bytes", theta.to_bytes().len());

    // benchmark verify credential
    c.bench_function("BASE 2 Verification 1000", |b| {
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

    let base_u = 3;
    let number_of_base_elements_l = 3;

    let lower_bound = Scalar::from(0);
    let upper_bound = Scalar::from(10);

    let sp_h = params.gen1() * params.random_scalar();
    let sp_key_pair = single_attribute_keygen(&params);
    let sp_private_key = sp_key_pair.secret_key();

    c.bench_function("BASE 3 Issuance 10", |b| {
        b.iter(|| issue_range_signatures(&sp_h, &sp_private_key, 0, base_u));
    });

    let sp_signatures = issue_range_signatures(&sp_h, &sp_private_key, 0, base_u);
    let sp_verification_key = sp_key_pair.verification_key();

    // benchmark prove credential
    c.bench_function("BASE 3 Proof 10", |b| {
        b.iter(|| {
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
        });
    });

    // Generate cryptographic material to verify them
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
    )
    .unwrap();

    println!("theta 10 length {} bytes", theta.to_bytes().len());

    // benchmark verify credential
    c.bench_function("BASE 3 Verification 10", |b| {
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

    let base_u = 3;
    let number_of_base_elements_l = 4;

    let lower_bound = Scalar::from(0);
    let upper_bound = Scalar::from(50);

    let sp_h = params.gen1() * params.random_scalar();
    let sp_key_pair = single_attribute_keygen(&params);
    let sp_private_key = sp_key_pair.secret_key();

    c.bench_function("BASE 3 Issuance 50", |b| {
        b.iter(|| issue_range_signatures(&sp_h, &sp_private_key, 0, base_u));
    });

    let sp_signatures = issue_range_signatures(&sp_h, &sp_private_key, 0, base_u);
    let sp_verification_key = sp_key_pair.verification_key();

    // benchmark prove credential
    c.bench_function("BASE 3 Proof 50", |b| {
        b.iter(|| {
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
        });
    });

    // Generate cryptographic material to verify them
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
    )
    .unwrap();

    println!("theta 50 length {} bytes", theta.to_bytes().len());

    // benchmark verify credential
    c.bench_function("BASE 3 Verification 50", |b| {
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

    let base_u = 3;
    let number_of_base_elements_l = 5;

    let lower_bound = Scalar::from(0);
    let upper_bound = Scalar::from(100);

    let sp_h = params.gen1() * params.random_scalar();
    let sp_key_pair = single_attribute_keygen(&params);
    let sp_private_key = sp_key_pair.secret_key();

    c.bench_function("BASE 3 Issuance 100", |b| {
        b.iter(|| issue_range_signatures(&sp_h, &sp_private_key, 0, base_u));
    });

    let sp_signatures = issue_range_signatures(&sp_h, &sp_private_key, 0, base_u);
    let sp_verification_key = sp_key_pair.verification_key();

    // benchmark prove credential
    c.bench_function("BASE 3 Proof 100", |b| {
        b.iter(|| {
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
        });
    });

    // Generate cryptographic material to verify them
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
    )
    .unwrap();

    println!("theta 100 length {} bytes", theta.to_bytes().len());

    // benchmark verify credential
    c.bench_function("BASE 3 Verification 100", |b| {
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

    let base_u = 3;
    let number_of_base_elements_l = 6;

    let lower_bound = Scalar::from(0);
    let upper_bound = Scalar::from(500);

    let sp_h = params.gen1() * params.random_scalar();
    let sp_key_pair = single_attribute_keygen(&params);
    let sp_private_key = sp_key_pair.secret_key();

    c.bench_function("BASE 3 Issuance 500", |b| {
        b.iter(|| issue_range_signatures(&sp_h, &sp_private_key, 0, base_u));
    });

    let sp_signatures = issue_range_signatures(&sp_h, &sp_private_key, 0, base_u);
    let sp_verification_key = sp_key_pair.verification_key();

    // benchmark prove credential
    c.bench_function("BASE 3 Proof 500", |b| {
        b.iter(|| {
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
        });
    });

    // Generate cryptographic material to verify them
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
    )
    .unwrap();

    println!("theta 500 length {} bytes", theta.to_bytes().len());

    // benchmark verify credential
    c.bench_function("BASE 3 Verification 500", |b| {
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

    let base_u = 3;
    let number_of_base_elements_l = 7;

    let lower_bound = Scalar::from(0);
    let upper_bound = Scalar::from(1000);

    let sp_h = params.gen1() * params.random_scalar();
    let sp_key_pair = single_attribute_keygen(&params);
    let sp_private_key = sp_key_pair.secret_key();

    c.bench_function("BASE 3 Issuance 1000", |b| {
        b.iter(|| issue_range_signatures(&sp_h, &sp_private_key, 0, base_u));
    });

    let sp_signatures = issue_range_signatures(&sp_h, &sp_private_key, 0, base_u);
    let sp_verification_key = sp_key_pair.verification_key();

    // benchmark prove credential
    c.bench_function("BASE 3 Proof 1000", |b| {
        b.iter(|| {
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
        });
    });

    // Generate cryptographic material to verify them
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
    )
    .unwrap();

    println!("theta 1000 length {} bytes", theta.to_bytes().len());

    // benchmark verify credential
    c.bench_function("BASE 3 Verification 1000", |b| {
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

    let base_u = 4;
    let number_of_base_elements_l = 2;

    let lower_bound = Scalar::from(0);
    let upper_bound = Scalar::from(10);

    let sp_h = params.gen1() * params.random_scalar();
    let sp_key_pair = single_attribute_keygen(&params);
    let sp_private_key = sp_key_pair.secret_key();

    c.bench_function("BASE 4 Issuance 10", |b| {
        b.iter(|| issue_range_signatures(&sp_h, &sp_private_key, 0, base_u));
    });

    let sp_signatures = issue_range_signatures(&sp_h, &sp_private_key, 0, base_u);
    let sp_verification_key = sp_key_pair.verification_key();

    // benchmark prove credential
    c.bench_function("BASE 4 Proof 10", |b| {
        b.iter(|| {
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
        });
    });

    // Generate cryptographic material to verify them
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
    )
    .unwrap();

    println!("theta 10 length {} bytes", theta.to_bytes().len());

    // benchmark verify credential
    c.bench_function("BASE 4 Verification 10", |b| {
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

    let base_u = 4;
    let number_of_base_elements_l = 3;

    let lower_bound = Scalar::from(0);
    let upper_bound = Scalar::from(50);

    let sp_h = params.gen1() * params.random_scalar();
    let sp_key_pair = single_attribute_keygen(&params);
    let sp_private_key = sp_key_pair.secret_key();

    c.bench_function("BASE 4 Issuance 50", |b| {
        b.iter(|| issue_range_signatures(&sp_h, &sp_private_key, 0, base_u));
    });

    let sp_signatures = issue_range_signatures(&sp_h, &sp_private_key, 0, base_u);
    let sp_verification_key = sp_key_pair.verification_key();

    // benchmark prove credential
    c.bench_function("BASE 4 Proof 50", |b| {
        b.iter(|| {
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
        });
    });

    // Generate cryptographic material to verify them
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
    )
    .unwrap();

    println!("theta 50 length {} bytes", theta.to_bytes().len());

    // benchmark verify credential
    c.bench_function("BASE 4 Verification 50", |b| {
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

    let base_u = 4;
    let number_of_base_elements_l = 4;

    let lower_bound = Scalar::from(0);
    let upper_bound = Scalar::from(100);

    let sp_h = params.gen1() * params.random_scalar();
    let sp_key_pair = single_attribute_keygen(&params);
    let sp_private_key = sp_key_pair.secret_key();

    c.bench_function("BASE 4 Issuance 100", |b| {
        b.iter(|| issue_range_signatures(&sp_h, &sp_private_key, 0, base_u));
    });

    let sp_signatures = issue_range_signatures(&sp_h, &sp_private_key, 0, base_u);
    let sp_verification_key = sp_key_pair.verification_key();

    // benchmark prove credential
    c.bench_function("BASE 4 Proof 100", |b| {
        b.iter(|| {
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
        });
    });

    // Generate cryptographic material to verify them
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
    )
    .unwrap();

    println!("theta 100 length {} bytes", theta.to_bytes().len());

    // benchmark verify credential
    c.bench_function("BASE 4 Verification 100", |b| {
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

    let base_u = 4;
    let number_of_base_elements_l = 5;

    let lower_bound = Scalar::from(0);
    let upper_bound = Scalar::from(500);

    let sp_h = params.gen1() * params.random_scalar();
    let sp_key_pair = single_attribute_keygen(&params);
    let sp_private_key = sp_key_pair.secret_key();

    c.bench_function("BASE 4 Issuance 500", |b| {
        b.iter(|| issue_range_signatures(&sp_h, &sp_private_key, 0, base_u));
    });

    let sp_signatures = issue_range_signatures(&sp_h, &sp_private_key, 0, base_u);
    let sp_verification_key = sp_key_pair.verification_key();

    // benchmark prove credential
    c.bench_function("BASE 4 Proof 500", |b| {
        b.iter(|| {
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
        });
    });

    // Generate cryptographic material to verify them
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
    )
    .unwrap();

    println!("theta 500 length {} bytes", theta.to_bytes().len());

    // benchmark verify credential
    c.bench_function("BASE 4 Verification 500", |b| {
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

    let base_u = 4;
    let number_of_base_elements_l = 5;

    let lower_bound = Scalar::from(0);
    let upper_bound = Scalar::from(1000);

    let sp_h = params.gen1() * params.random_scalar();
    let sp_key_pair = single_attribute_keygen(&params);
    let sp_private_key = sp_key_pair.secret_key();

    c.bench_function("BASE 4 Issuance 1000", |b| {
        b.iter(|| issue_range_signatures(&sp_h, &sp_private_key, 0, base_u));
    });

    let sp_signatures = issue_range_signatures(&sp_h, &sp_private_key, 0, base_u);
    let sp_verification_key = sp_key_pair.verification_key();

    // benchmark prove credential
    c.bench_function("BASE 4 Proof 1000", |b| {
        b.iter(|| {
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
        });
    });

    // Generate cryptographic material to verify them
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
    )
    .unwrap();

    println!("theta 1000 length {} bytes", theta.to_bytes().len());

    // benchmark verify credential
    c.bench_function("BASE 4 Verification 1000", |b| {
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

    c.finish();
}

criterion_group!(benches_e2e, bench_e2e_runs);
criterion_main!(benches_e2e);
