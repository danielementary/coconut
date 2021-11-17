use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use core::time::Duration;
use std::convert::{TryFrom, TryInto};
use std::mem;

use rand::Rng;

use bls12_381::Scalar;
use coconut_rs::{
    compute_u_ary_decomposition, issue_membership_signatures, issue_range_signatures, keygen,
    pick_range_signatures, prove_credential_and_range, prove_credential_and_set_membership, setup,
    single_attribute_keygen, RangeTheta, RawAttribute, SetMembershipTheta, L, U,
};

pub fn bench_proofs_functions(c: &mut Criterion) {
    let params = setup(1).unwrap();
    let set: [RawAttribute; 100] = (0..100)
        .map(|i| RawAttribute::Number(i))
        .collect::<Vec<RawAttribute>>()
        .try_into()
        .unwrap();

    // benchmark the issuance of set membership signatures
    let mut group = c.benchmark_group("issue set membership signatures (2, 5, 10, 50, 100)");
    group.measurement_time(Duration::new(10, 0));
    for l in [2, 5, 10, 50, 100].iter() {
        group.throughput(Throughput::Bytes(mem::size_of_val(&set[..*l]) as u64));
        group.bench_with_input(BenchmarkId::from_parameter(l), l, |b, &l| {
            b.iter(|| issue_membership_signatures(&params, &set[..l]));
        });
    }
    group.finish();

    // benchmark the issuance of range signatures
    c.bench_function("issue U range signatures", |b| {
        b.iter(|| issue_range_signatures(&params))
    });

    let mut rng = rand::thread_rng();
    let ms = (0..L)
        .map(|_| Scalar::from(rng.gen_range(0..U) as u64))
        .collect::<Vec<Scalar>>()
        .try_into()
        .unwrap();
    let range_signatures = issue_range_signatures(&params);

    // benchmark how long it takes to pick the corresponding signatures
    c.bench_function("pick L range signatures", |b| {
        b.iter(|| pick_range_signatures(&ms, &range_signatures));
    });

    // benchmark the U-ary decomposition
    let mut group =
        c.benchmark_group("compute the U-ary decomposition (0, 1, 255, 100, 43690, 65535)");
    for n in [0, 1, 255, 100, 43690, 65535].iter() {
        group.throughput(Throughput::Bytes(mem::size_of_val(&Scalar::from(*n)) as u64));
        group.bench_with_input(BenchmarkId::from_parameter(n), n, |b, &n| {
            b.iter(|| compute_u_ary_decomposition(Scalar::from(n)));
        });
    }
    group.finish();

    // TODO: add roundtrips for SMP, RP, SMT and RT
    //
    // prepare roundtrips benchmarks with dummy values
    let params = setup(10).unwrap();

    let verification_key = keygen(&params).verification_key();
    let sp_verification_key = single_attribute_keygen(&params).verification_key();
    let private_attributes = params.n_random_scalars(5);

    let signature = range_signatures
        .signatures
        .get(&RawAttribute::Number(0))
        .unwrap();
    let membership_signature = range_signatures
        .signatures
        .get(&RawAttribute::Number(0))
        .unwrap();

    let set_membership_theta = prove_credential_and_set_membership(
        &params,
        &verification_key,
        &sp_verification_key,
        &signature,
        &membership_signature,
        &private_attributes,
    )
    .unwrap();

    // benchmark how long it takes to convert SetMembershipTheta to bytes and back
    c.bench_function("convert SetMembershipTheta to bytes and back", |b| {
        b.iter(|| {
            SetMembershipTheta::try_from(set_membership_theta.to_bytes().as_slice()).unwrap()
        });
    });

    let a = Scalar::from(0);
    let b = Scalar::from(15);

    let range_theta = prove_credential_and_range(
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

    // benchmark how long it takes to convert RangeTheta to bytes and back
    c.bench_function("convert RangeTheta to bytes and back", |b| {
        b.iter(|| RangeTheta::try_from(range_theta.to_bytes().as_slice()).unwrap());
    });
}

criterion_group!(benches_proof, bench_proofs_functions);
criterion_main!(benches_proof);
