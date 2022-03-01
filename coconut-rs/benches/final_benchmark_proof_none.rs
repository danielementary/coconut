use criterion::{criterion_group, criterion_main, Criterion};
use std::time::Duration;

use coconut_rs::{
    aggregate_signature_shares, aggregate_verification_keys, blind_sign, elgamal_keygen,
    prepare_blind_sign, prove_credential, setup, ttp_keygen, verify_credential, Signature,
    SignatureShare, VerificationKey,
};

fn e2e_proof_none(c: &mut Criterion) {
    let mut c = c.benchmark_group("sample_size");
    c.sample_size(10);
    c.measurement_time(Duration::from_secs(25));

    let params = setup(1).unwrap();

    let private_attributes = params.n_random_scalars(1);
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

    c.bench_function("Proof", |b| {
        b.iter(|| prove_credential(&params, &verification_key, &signature, &private_attributes));
    });

    let theta =
        prove_credential(&params, &verification_key, &signature, &private_attributes).unwrap();

    println!("theta length {} bytes", theta.to_bytes().len());

    c.bench_function("Verification", |b| {
        b.iter(|| verify_credential(&params, &verification_key, &theta, &public_attributes));
    });
}

criterion_group!(benches, e2e_proof_none);
criterion_main!(benches);
