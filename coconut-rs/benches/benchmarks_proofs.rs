use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use core::time::Duration;
use std::convert::TryInto;
use std::mem;

use rand::Rng;

use bls12_381::Scalar;
use coconut_rs::{
    compute_u_ary_decomposition, issue_membership_signatures, issue_range_signatures,
    pick_range_signatures, setup, RawAttribute, L, U,
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
}

criterion_group!(benches_proof, bench_proofs_functions);
criterion_main!(benches_proof);
