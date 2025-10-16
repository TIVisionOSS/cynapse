//! Performance benchmarks for cynapse
//!
//! Run with: cargo bench

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use cynapse::core::{
    hasher::{HashAlgorithm, HashEngine},
    mapper::MemoryMapper,
};

fn bench_hash_algorithms(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_algorithms");
    let data = vec![0xAA; 4096]; // One page

    for algo in &[HashAlgorithm::Blake3, HashAlgorithm::Sha256] {
        group.bench_with_input(
            BenchmarkId::new("single_page", algo.name()),
            algo,
            |b, &algo| {
                let engine = HashEngine::new(algo);
                b.iter(|| engine.hash_page(black_box(&data), 0x1000).unwrap());
            },
        );
    }

    group.finish();
}

fn bench_page_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("page_hashing");

    for size in &[4096, 8192, 16384, 65536] {
        let data = vec![0xAA; *size];

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            let engine = HashEngine::new(HashAlgorithm::Blake3);
            b.iter(|| engine.hash_pages(black_box(&data), 0x1000).unwrap());
        });
    }

    group.finish();
}

fn bench_merkle_tree_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_tree");
    let engine = HashEngine::new(HashAlgorithm::Blake3);

    for page_count in &[4, 16, 64, 256] {
        let data = vec![0xAA; page_count * 4096];
        let pages = engine.hash_pages(&data, 0x1000).unwrap();

        group.bench_with_input(
            BenchmarkId::from_parameter(page_count),
            &pages,
            |b, pages| {
                b.iter(|| engine.build_merkle_tree(black_box(pages)));
            },
        );
    }

    group.finish();
}

fn bench_memory_enumeration(c: &mut Criterion) {
    c.bench_function("enumerate_segments", |b| {
        b.iter(|| {
            let mut mapper = MemoryMapper::new().unwrap();
            mapper.enumerate_executable_segments().unwrap()
        });
    });
}

fn bench_difference_detection(c: &mut Criterion) {
    let mut group = c.benchmark_group("difference_detection");
    let engine = HashEngine::new(HashAlgorithm::Blake3);

    for page_count in &[10, 50, 100] {
        let data1 = vec![0xAA; page_count * 4096];
        let mut data2 = data1.clone();
        data2[2048] = 0xBB; // Modify one byte

        let pages1 = engine.hash_pages(&data1, 0x1000).unwrap();
        let pages2 = engine.hash_pages(&data2, 0x1000).unwrap();

        group.bench_with_input(
            BenchmarkId::from_parameter(page_count),
            &(pages1, pages2),
            |b, (p1, p2)| {
                b.iter(|| engine.find_differences(black_box(p1), black_box(p2)));
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_hash_algorithms,
    bench_page_hashing,
    bench_merkle_tree_construction,
    bench_memory_enumeration,
    bench_difference_detection,
);

criterion_main!(benches);
