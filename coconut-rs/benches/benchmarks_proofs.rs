use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

use core::time::Duration;
use std::convert::{TryFrom, TryInto};

use rand::Rng;

use bls12_381::Scalar;
use coconut_rs::{
    compute_u_ary_decomposition, default_base_u, default_number_of_base_elements_l,
    issue_range_signatures, issue_set_signatures, keygen, pick_signatures_for_decomposition,
    prove_credential_and_range, prove_credential_and_set_membership, setup,
    single_attribute_keygen, RangeTheta, RawAttribute, SetMembershipTheta, Signature,
};

pub fn bench_proofs_functions(c: &mut Criterion) {
    let mut rng = rand::thread_rng();

    let params = setup(1).unwrap();

    let sp_h = params.gen1() * params.random_scalar();
    let sp_key_pair = single_attribute_keygen(&params);
    let sp_private_key = sp_key_pair.secret_key();

    let set = (0..100)
        .map(|_| RawAttribute::Number(rng.gen::<u64>()))
        .collect::<Vec<_>>();

    // benchmark the issuance of set membership signatures
    let mut group = c.benchmark_group("issue set membership signatures (1, 5, 10, 50, 100)");
    group.measurement_time(Duration::new(10, 0));
    for l in [1, 5, 10, 50, 100].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(l), l, |b, &l| {
            b.iter(|| issue_set_signatures(&sp_h, &sp_private_key, &set[..l].to_vec()));
        });
    }
    group.finish();

    let base_u = default_base_u();

    // benchmark the issuance of range signatures
    c.bench_function("issue default u range signatures", |b| {
        b.iter(|| issue_range_signatures(&sp_h, &sp_private_key, 0, base_u))
    });

    let number_of_base_elements_l = default_number_of_base_elements_l();

    let decomposition = (0..number_of_base_elements_l)
        .map(|_| Scalar::from(rng.gen_range(0..base_u) as u64))
        .collect::<Vec<Scalar>>()
        .try_into()
        .unwrap();
    let range_signatures = issue_range_signatures(&sp_h, &sp_private_key, 0, base_u);

    // benchmark how long it takes to pick the corresponding signatures
    c.bench_function("pick L range signatures", |b| {
        b.iter(|| pick_signatures_for_decomposition(&decomposition, &range_signatures));
    });

    // benchmark the U-ary decomposition
    let mut group =
        c.benchmark_group("compute the U-ary decomposition (0, 1, 255, 100, 43690, 65535)");
    for n in [0, 1, 255, 100, 43690, 65535].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(n), n, |b, &n| {
            b.iter(|| {
                compute_u_ary_decomposition(&Scalar::from(n), base_u, number_of_base_elements_l)
            });
        });
    }
    group.finish();

    // prepare roundtrips benchmarks with dummy values
    let params = setup(10).unwrap();

    let verification_key = keygen(&params).verification_key();
    let sp_key_pair = single_attribute_keygen(&params);
    let sp_verification_key = sp_key_pair.verification_key();

    let credential = Signature(
        params.gen1() * params.random_scalar(),
        params.gen1() * params.random_scalar(),
    );

    let sp_h = params.gen1() * params.random_scalar();
    let sp_private_key = sp_key_pair.secret_key();
    let set = (0..11).map(|i| RawAttribute::Number(i as u64)).collect();
    let sp_signatures = issue_set_signatures(&sp_h, &sp_private_key, &set);

    let private_attributes = vec![[Scalar::from(10)].to_vec(), params.n_random_scalars(4)].concat();

    let set_membership_theta = prove_credential_and_set_membership(
        &params,
        &verification_key,
        &sp_verification_key,
        &credential,
        &sp_signatures,
        &private_attributes,
    )
    .unwrap();

    // benchmark how long it takes to convert SetMembershipTheta to bytes and back
    c.bench_function("convert SetMembershipTheta to bytes and back", |b| {
        b.iter(|| {
            SetMembershipTheta::try_from(set_membership_theta.to_bytes().as_slice()).unwrap()
        });
    });

    let lower_bound = Scalar::from(0);
    let upper_bound = Scalar::from(15);

    let sp_signatures = issue_range_signatures(&sp_h, &sp_private_key, 0, base_u);

    let range_theta = prove_credential_and_range(
        &params,
        base_u,
        number_of_base_elements_l,
        lower_bound,
        upper_bound,
        &verification_key,
        &sp_verification_key,
        &credential,
        &sp_signatures,
        &private_attributes,
    )
    .unwrap();

    // benchmark how long it takes to convert RangeTheta to bytes and back
    c.bench_function("convert RangeTheta to bytes and back", |b| {
        b.iter(|| RangeTheta::try_from(range_theta.to_bytes().as_slice()).unwrap());
    });
}

criterion_group!(benches_proof, bench_proofs_functions);
criterion_main!(benches_proof);
