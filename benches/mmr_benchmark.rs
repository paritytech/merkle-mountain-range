#[macro_use]
extern crate criterion;

use criterion::{black_box, BatchSize, BenchmarkId, Criterion};

use bytes::Bytes;
use polkadot_ckb_merkle_mountain_range::{
    util::MemStore, Error, MMRStoreReadOps, Merge, Result, MMR,
};
use rand::{seq::SliceRandom, thread_rng};
use std::convert::TryFrom;

use blake2b_rs::{Blake2b, Blake2bBuilder};
use itertools::iproduct;

fn new_blake2b() -> Blake2b {
    Blake2bBuilder::new(32).build()
}

#[derive(Eq, PartialEq, Clone, Debug, Default)]
struct NumberHash(pub Bytes);
impl TryFrom<u32> for NumberHash {
    type Error = Error;
    fn try_from(num: u32) -> Result<Self> {
        let mut hasher = new_blake2b();
        let mut hash = [0u8; 32];
        hasher.update(&num.to_le_bytes());
        hasher.finalize(&mut hash);
        Ok(NumberHash(hash.to_vec().into()))
    }
}

struct MergeNumberHash;

impl Merge for MergeNumberHash {
    type Item = NumberHash;
    fn merge(lhs: &Self::Item, rhs: &Self::Item) -> Result<Self::Item> {
        let mut hasher = new_blake2b();
        let mut hash = [0u8; 32];
        hasher.update(&lhs.0);
        hasher.update(&rhs.0);
        hasher.finalize(&mut hash);
        Ok(NumberHash(hash.to_vec().into()))
    }
}

fn _prepare_mmr(
    count: u32,
    roots: bool,
) -> (
    u64,
    MemStore<NumberHash>,
    Vec<u64>,
    Option<Vec<(u32, NumberHash)>>,
) {
    let store = MemStore::default();
    let mut prev_roots = Vec::new();
    let mut mmr = MMR::<_, MergeNumberHash, _>::new(0, &store);
    let positions: Vec<u64> = (0u32..count)
        .map(|i| {
            let position = mmr.push(NumberHash::try_from(i).unwrap()).unwrap();
            if roots {
                prev_roots.push((i + 1, mmr.get_root().expect("get root")));
            }
            position
        })
        .collect();
    let mmr_size = mmr.mmr_size();
    mmr.commit().expect("write to store");
    (
        mmr_size,
        store,
        positions,
        if roots { Some(prev_roots) } else { None },
    )
}

fn prepare_mmr_no_roots(count: u32) -> (u64, MemStore<NumberHash>, Vec<u64>) {
    let (mmr_size, store, positions, _) = _prepare_mmr(count, false);
    (mmr_size, store, positions)
}

fn prepare_mmr_with_roots(
    count: u32,
) -> (u64, MemStore<NumberHash>, Vec<u64>, Vec<(u32, NumberHash)>) {
    let (mmr_size, store, positions, roots) = _prepare_mmr(count, true);
    (mmr_size, store, positions, roots.unwrap())
}

const INDEX_OFFSET: u64 = 100_000;
const INDEX_DOMAIN: u64 = 2_000;

fn bench(c: &mut Criterion) {
    c.bench_function("MMR gen proof", |b| {
        let (mmr_size, store, positions) = prepare_mmr_no_roots(20_000_000);
        let mmr = MMR::<_, MergeNumberHash, _>::new(mmr_size, &store);
        let mut rng = thread_rng();
        b.iter(|| mmr.gen_proof(vec![*positions.choose(&mut rng).unwrap()]));
    });

    c.bench_function("MMR gen node-proof", |b| {
        let (mmr_size, store, positions) = prepare_mmr_no_roots(20_000_000);
        let mmr = MMR::<_, MergeNumberHash, _>::new(mmr_size, &store);
        let mut rng = thread_rng();
        b.iter(|| mmr.gen_node_proof(vec![*positions.choose(&mut rng).unwrap()]));
    });

    c.bench_function("MMR gen batch node-proof", |b| {
        let (mmr_size, store, positions) = prepare_mmr_no_roots(20_000_000);
        let mmr = MMR::<_, MergeNumberHash, _>::new(mmr_size, &store);
        let mut rng = thread_rng();
        b.iter(|| {
            mmr.gen_node_proof(
                positions
                    .choose_multiple(&mut rng, 2_000_000)
                    .cloned()
                    .collect::<Vec<_>>(),
            )
        });
    });

    c.bench_function("MMR gen ancestry-proof", |b| {
        let (mmr_size, store, _positions, roots) = prepare_mmr_with_roots(50_000);
        let mmr = MMR::<_, MergeNumberHash, _>::new(mmr_size, &store);
        let mut rng = thread_rng();
        b.iter(|| mmr.gen_ancestry_proof(roots.choose(&mut rng).unwrap().0 as u64));
    });

    c.bench_function("MMR verify", |b| {
        let (mmr_size, store, positions) = prepare_mmr_no_roots(20_000_000);
        let mmr = MMR::<_, MergeNumberHash, _>::new(mmr_size, &store);
        let mut rng = thread_rng();
        let root: NumberHash = mmr.get_root().unwrap();

        b.iter_batched(
            || {
                let pos = positions.choose(&mut rng).unwrap();
                let elem = (&store).get_elem(*pos).unwrap().unwrap();
                let proof = mmr.gen_proof(vec![*pos]).unwrap();
                (pos, elem, proof)
            },
            |(pos, elem, proof)| {
                proof
                    .verify(root.clone(), vec![(*pos, elem.clone())])
                    .unwrap();
            },
            BatchSize::SmallInput,
        );
    });

    c.bench_function("MMR verify node-proof", |b| {
        let (mmr_size, store, positions) = prepare_mmr_no_roots(20_000_000);
        let mmr = MMR::<_, MergeNumberHash, _>::new(mmr_size, &store);
        let mut rng = thread_rng();
        let root: NumberHash = mmr.get_root().unwrap();

        b.iter_batched(
            || {
                let pos = *positions.choose(&mut rng).unwrap();
                let elem = (&store).get_elem(pos).unwrap().unwrap();
                let proof = mmr.gen_node_proof(vec![pos]).unwrap();
                (pos, elem, proof)
            },
            |(pos, elem, proof)| {
                proof.verify(root.clone(), vec![(pos, elem)]).unwrap();
            },
            BatchSize::SmallInput,
        );
    });

    c.bench_function("MMR verify batch node-proof", |b| {
        let (mmr_size, store, positions) = prepare_mmr_no_roots(20_000_000);
        let mmr = MMR::<_, MergeNumberHash, _>::new(mmr_size, &store);
        let mut rng = thread_rng();
        let root: NumberHash = mmr.get_root().unwrap();

        b.iter_batched(
            || {
                // Setup: Generate a new proof for each iteration
                let pos_sample: Vec<u64> = positions
                    .choose_multiple(&mut rng, 2_000_000)
                    .cloned()
                    .collect();
                let elems = pos_sample
                    .iter()
                    .map(|pos| (&store).get_elem(*pos).unwrap().unwrap())
                    .collect::<Vec<_>>();
                let proof = mmr.gen_node_proof(pos_sample.clone()).unwrap();
                let elem_tuples = pos_sample
                    .into_iter()
                    .zip(elems.into_iter())
                    .collect::<Vec<_>>();
                (elem_tuples, proof)
            },
            |(elem_tuples, proof)| {
                // Benchmark: Verify the proof
                proof.verify(root.clone(), elem_tuples).unwrap();
            },
            BatchSize::SmallInput,
        );
    });

    c.bench_function("MMR verify ancestry-proof", |b| {
        let (mmr_size, store, _positions, roots) = prepare_mmr_with_roots(50_000);
        let mmr = MMR::<_, MergeNumberHash, _>::new(mmr_size, &store);
        let mut rng = thread_rng();
        let root: NumberHash = mmr.get_root().unwrap();

        b.iter_batched(
            || {
                let (prev_size, prev_root) = roots.choose(&mut rng).unwrap();
                let proof = mmr.gen_ancestry_proof(*prev_size as u64).unwrap();
                (prev_root.clone(), proof)
            },
            |(prev_root, proof)| {
                proof.verify_ancestor(root.clone(), prev_root).unwrap();
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(20);
    targets = bench
);
criterion_main!(benches);
