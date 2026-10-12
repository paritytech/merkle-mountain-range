use super::{MergeNumberHash, NumberHash};
use crate::ancestry_proof::{ancestry_proof_positions, expected_ancestry_proof_size};
use crate::leaf_index_to_mmr_size;
use crate::util::{MemMMR, MemStore};
use crate::Error;

#[test]
fn test_ancestry() {
    let store = MemStore::default();
    let mut mmr = MemMMR::<_, MergeNumberHash>::new(0, &store);

    let mmr_size = 5000;
    let mut prev_roots = Vec::new();
    for i in 0..mmr_size {
        mmr.push(NumberHash::from(i)).unwrap();
        prev_roots.push(mmr.get_root().expect("get root"));
    }

    let root = mmr.get_root().expect("get root");
    for i in 0..mmr_size {
        let prev_size = leaf_index_to_mmr_size(i.into());
        let ancestry_proof = mmr.gen_ancestry_proof(prev_size).expect("gen proof");
        assert!(ancestry_proof
            .verify_ancestor(root.clone(), prev_roots[i as usize].clone())
            .unwrap());
        // The store-free positions agree with the generator at this scale too.
        let generated: Vec<u64> = ancestry_proof
            .prev_peaks_proof
            .proof_items()
            .iter()
            .map(|(pos, _)| *pos)
            .collect();
        assert_eq!(
            ancestry_proof_positions(prev_size, mmr.mmr_size()).unwrap(),
            generated
        );
        assert_eq!(
            expected_ancestry_proof_size(ancestry_proof.prev_mmr_size, mmr.mmr_size()),
            ancestry_proof.prev_peaks_proof.proof_items().len()
        );
    }
}

/// `ancestry_proof_positions` must name exactly the positions `gen_ancestry_proof` emits, in the
/// same order, for every `(prev, current)` pair — including the item that stands for a bagged
/// run of right-hand peaks. Exhaustive up to 256 leaves, which covers the all-ones sizes 127 and
/// 255 (seven and eight peaks, the most bagging the range allows).
#[test]
fn test_ancestry_proof_positions_match_generated_proof() {
    for n in 2..=256u64 {
        let store = MemStore::default();
        let mut mmr = MemMMR::<_, MergeNumberHash>::new(0, &store);
        for i in 0..n {
            mmr.push(NumberHash::from(i as u32)).unwrap();
        }
        let mmr_size = mmr.mmr_size();
        // `k == n` is the identity extension: nothing to prove, empty proof.
        for k in 1..=n {
            let prev_size = leaf_index_to_mmr_size(k - 1);
            let proof = mmr.gen_ancestry_proof(prev_size).expect("gen proof");
            let generated: Vec<u64> = proof
                .prev_peaks_proof
                .proof_items()
                .iter()
                .map(|(pos, _)| *pos)
                .collect();
            let derived = ancestry_proof_positions(prev_size, mmr_size).expect("positions");
            assert_eq!(derived, generated, "k={} n={}", k, n);
            assert_eq!(
                derived.len(),
                expected_ancestry_proof_size(prev_size, mmr_size)
            );
        }
    }
}

#[test]
fn test_ancestry_proof_positions_rejects_what_gen_ancestry_proof_rejects() {
    // An empty previous MMR has no peaks to prove.
    assert!(ancestry_proof_positions(0, 7).is_err());
    // A previous MMR larger than the current one has peaks outside it.
    assert!(ancestry_proof_positions(7, 4).is_err());
    // The single-leaf identity case: nothing to prove.
    assert_eq!(ancestry_proof_positions(1, 1).unwrap(), Vec::<u64>::new());
    // Sizes that are not MMR sizes are rejected the way the verifiers reject them.
    assert!(matches!(
        ancestry_proof_positions(2, 7),
        Err(Error::CorruptedProof)
    ));
    assert!(matches!(
        ancestry_proof_positions(3, 5),
        Err(Error::CorruptedProof)
    ));
}

/// `gen_ancestry_proof`'s error and identity paths, pinned so the shared layout keeps them.
#[test]
fn test_gen_ancestry_proof_edge_cases() {
    let store = MemStore::default();
    let mut mmr = MemMMR::<_, MergeNumberHash>::new(0, &store);
    for i in 0..7u32 {
        mmr.push(NumberHash::from(i)).unwrap();
    }
    let size = mmr.mmr_size();
    let root = mmr.get_root().unwrap();

    // An empty previous MMR has no peaks to prove.
    assert!(matches!(
        mmr.gen_ancestry_proof(0),
        Err(Error::GenProofForInvalidNodes)
    ));
    // A previous MMR larger than this one has peaks outside it.
    assert!(matches!(
        mmr.gen_ancestry_proof(leaf_index_to_mmr_size(7)),
        Err(Error::GenProofForInvalidNodes)
    ));
    // Identity: nothing to prove, and the proof verifies the root as its own ancestor.
    let identity = mmr.gen_ancestry_proof(size).unwrap();
    assert!(identity.prev_peaks_proof.proof_items().is_empty());
    assert!(identity.verify_ancestor(root.clone(), root).unwrap());

    // The single-leaf identity keeps its special shape from before this change: no peaks
    // carried. `verify_ancestor` rejects that shape (it expects one peak for a 1-node MMR), so
    // unlike every other identity this proof does not verify. Pre-existing; tracked separately.
    let store = MemStore::default();
    let mut one = MemMMR::<_, MergeNumberHash>::new(0, &store);
    one.push(NumberHash::from(0u32)).unwrap();
    let identity = one.gen_ancestry_proof(1).unwrap();
    assert!(identity.prev_peaks.is_empty());
    assert!(identity.prev_peaks_proof.proof_items().is_empty());
}

/// Random `(prev, current)` pairs up to 2^20 leaves, without a store: the positions are as many
/// as `expected_ancestry_proof_size` says, strictly increasing, and inside the current MMR.
#[test]
fn test_ancestry_proof_positions_shape_at_scale() {
    use proptest::prelude::*;
    use proptest::test_runner::{Config, TestRunner};

    let mut runner = TestRunner::new(Config::with_cases(2000));
    runner
        .run(&(1u64..=(1 << 20), 1u64..=(1 << 20)), |(a, b)| {
            let (prev_leaves, leaves) = if a <= b { (a, b) } else { (b, a) };
            let prev_size = leaf_index_to_mmr_size(prev_leaves - 1);
            let size = leaf_index_to_mmr_size(leaves - 1);
            let positions = ancestry_proof_positions(prev_size, size).unwrap();
            prop_assert_eq!(
                positions.len(),
                expected_ancestry_proof_size(prev_size, size)
            );
            prop_assert!(positions.windows(2).all(|w| w[0] < w[1]));
            prop_assert!(positions.iter().all(|&p| p < size));
            if prev_leaves == leaves {
                prop_assert!(positions.is_empty());
            }
            Ok(())
        })
        .unwrap();
}
