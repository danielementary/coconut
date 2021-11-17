use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use core::time::Duration;
use std::convert::TryInto;
use std::mem;

use coconut_rs::{issue_membership_signatures, setup, RawAttribute};

pub fn bench_issue_signatures(c: &mut Criterion) {
    let params = setup(1).unwrap();
    let set: [RawAttribute; 100] = (0..100)
        .map(|i| RawAttribute::Number(i))
        .collect::<Vec<RawAttribute>>()
        .try_into()
        .unwrap();

    let mut group = c.benchmark_group("issue set membership signatures (2, 5, 10, 50, 100)");
    group.measurement_time(Duration::new(10, 0));
    for l in [2, 5, 10, 50, 100].iter() {
        group.throughput(Throughput::Bytes(mem::size_of_val(&set[..*l]) as u64));
        group.bench_with_input(BenchmarkId::from_parameter(l), l, |b, &l| {
            b.iter(|| issue_membership_signatures(&params, &set[..l]));
        });
    }
    group.finish();
}

criterion_group!(benches_proof, bench_issue_signatures);
criterion_main!(benches_proof);
