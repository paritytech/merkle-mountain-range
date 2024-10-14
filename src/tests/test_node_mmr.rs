use super::{MergeNumberHash, NumberHash};
use crate::{
    leaf_index_to_mmr_size,
    util::{MemMMR, MemStore},
    Error,
};
use core::ops::Shl;
use faster_hex::hex_string;
use proptest::prelude::*;
use rand::{seq::SliceRandom, thread_rng};

fn test_mmr(count: u32, proof_elem: Vec<u32>) {
    let store = MemStore::default();
    let mut mmr = MemMMR::<_, MergeNumberHash>::new(0, &store);
    let positions: Vec<u64> = (0u32..count)
        .map(|i| mmr.push(NumberHash::from(i)).unwrap())
        .collect();
    let root = mmr.get_root().expect("get root");
    let proof = mmr
        .gen_node_proof(
            proof_elem
                .iter()
                .map(|elem| positions[*elem as usize])
                .collect(),
        )
        .expect("gen proof");
    assert!(proof
        .proof_items()
        .iter()
        .zip(proof.proof_items().iter().skip(1))
        .all(|((pos_a, _), (pos_b, _))| pos_a < pos_b));
    mmr.commit().expect("commit changes");
    let result = proof
        .verify(
            root,
            proof_elem
                .iter()
                .map(|elem| (positions[*elem as usize], NumberHash::from(*elem)))
                .collect(),
        )
        .unwrap();
    assert!(result);
}

fn test_gen_new_root_from_proof(count: u32) {
    let store = MemStore::default();
    let mut mmr = MemMMR::<_, MergeNumberHash>::new(0, &store);
    let positions: Vec<u64> = (0u32..count)
        .map(|i| mmr.push(NumberHash::from(i)).unwrap())
        .collect();
    let elem = count - 1;
    let pos = positions[elem as usize];
    let proof = mmr.gen_proof(vec![pos]).expect("gen proof");
    let new_elem = count;
    let new_pos = mmr.push(NumberHash::from(new_elem)).unwrap();
    let root = mmr.get_root().expect("get root");
    mmr.commit().expect("commit changes");
    let calculated_root = proof
        .calculate_root_with_new_leaf(
            vec![(pos, NumberHash::from(elem))],
            new_pos,
            NumberHash::from(new_elem),
            leaf_index_to_mmr_size(new_elem.into()),
        )
        .unwrap();
    assert_eq!(calculated_root, root);
}

#[test]
fn test_mmr_root() {
    let store = MemStore::default();
    let mut mmr = MemMMR::<_, MergeNumberHash>::new(0, &store);
    (0u32..11).for_each(|i| {
        mmr.push(NumberHash::from(i)).unwrap();
    });
    let root = mmr.get_root().expect("get root");
    let hex_root = hex_string(&root.0);
    assert_eq!(
        "f6794677f37a57df6a5ec36ce61036e43a36c1a009d05c81c9aa685dde1fd6e3",
        hex_root
    );
}

#[test]
fn test_empty_mmr_root() {
    let store = MemStore::<NumberHash>::default();
    let mmr = MemMMR::<_, MergeNumberHash>::new(0, &store);
    assert_eq!(Err(Error::GetRootOnEmpty), mmr.get_root());
}

#[test]
fn test_mmr_3_peaks() {
    test_mmr(11, vec![5]);
}

#[test]
fn test_mmr_2_peaks() {
    test_mmr(10, vec![5]);
}

#[test]
fn test_mmr_1_peak() {
    test_mmr(8, vec![5]);
}

#[test]
fn test_mmr_first_elem_proof() {
    test_mmr(11, vec![0]);
}

#[test]
fn test_mmr_last_elem_proof() {
    test_mmr(11, vec![10]);
}

#[test]
fn test_mmr_1_elem() {
    test_mmr(1, vec![0]);
}

#[test]
fn test_mmr_2_elems() {
    test_mmr(2, vec![0]);
    test_mmr(2, vec![1]);
}

#[test]
fn test_mmr_2_leaves_merkle_proof() {
    test_mmr(11, vec![3, 7]);
    test_mmr(11, vec![3, 4]);
}

#[test]
fn test_mmr_2_sibling_leaves_merkle_proof() {
    test_mmr(11, vec![4, 5]);
    test_mmr(11, vec![5, 6]);
    test_mmr(11, vec![6, 7]);
}

#[test]
fn test_mmr_3_leaves_merkle_proof() {
    test_mmr(11, vec![4, 5, 6]);
    test_mmr(11, vec![3, 5, 7]);
    test_mmr(11, vec![3, 4, 5]);
    test_mmr(100, vec![3, 5, 13]);
}

#[test]
fn test_gen_root_from_proof() {
    test_gen_new_root_from_proof(11);
}

#[test]
fn test_gen_proof_with_duplicate_leaves() {
    test_mmr(10, vec![5, 5]);
}

fn test_invalid_proof_verification(
    leaf_count: u32,
    positions_to_verify: Vec<u64>,
    // positions of entries that should be tampered
    tampered_positions: Vec<usize>,
    // optionally handroll proof from these positions
    handrolled_proof_positions: Option<Vec<u64>>,
    // optionally handroll tampered proof from these positions
    handrolled_tampered_proof_positions: Option<Vec<u64>>,
) {
    use crate::{ancestry_proof::NodeMerkleProof, Merge};
    use std::fmt::{Debug, Formatter};

    // Simple item struct to allow debugging the contents of MMR nodes/peaks
    #[derive(Clone, PartialEq)]
    enum MyItem {
        Number(u32),
        Merged(Box<MyItem>, Box<MyItem>),
    }

    impl Debug for MyItem {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            match self {
                MyItem::Number(x) => f.write_fmt(format_args!("{}", x)),
                MyItem::Merged(a, b) => f.write_fmt(format_args!("Merged({:#?}, {:#?})", a, b)),
            }
        }
    }

    #[derive(Debug)]
    struct MyMerge;

    impl Merge for MyMerge {
        type Item = MyItem;
        fn merge(lhs: &Self::Item, rhs: &Self::Item) -> Result<Self::Item, crate::Error> {
            return Ok(MyItem::Merged(Box::new(lhs.clone()), Box::new(rhs.clone())));
        }
    }

    // Let's build a simple MMR with the numbers 0 to 6
    let store = MemStore::default();
    let mut mmr = MemMMR::<_, MyMerge>::new(0, &store);
    let mut positions: Vec<u64> = Vec::new();
    for i in 0u32..leaf_count {
        let pos = mmr.push(MyItem::Number(i)).unwrap();
        positions.push(pos);
    }
    let root = mmr.get_root().unwrap();

    let entries_to_verify: Vec<(u64, MyItem)> = positions_to_verify
        .iter()
        .map(|pos| (*pos, mmr.batch().get_elem(*pos).unwrap().unwrap()))
        .collect();

    let mut tampered_entries_to_verify = entries_to_verify.clone();
    tampered_positions.iter().for_each(|proof_pos| {
        tampered_entries_to_verify[*proof_pos] = (
            tampered_entries_to_verify[*proof_pos].0,
            MyItem::Number(31337),
        )
    });

    let tampered_proof: Option<NodeMerkleProof<MyItem, MyMerge>> =
        if let Some(tampered_proof_positions) = handrolled_tampered_proof_positions {
            Some(NodeMerkleProof::new(
                mmr.mmr_size(),
                tampered_proof_positions
                    .iter()
                    .map(|pos| (*pos, mmr.batch().get_elem(*pos).unwrap().unwrap()))
                    .collect(),
            ))
        } else {
            None
        };

    // test with the proof generated by the library itself, or, if provided, a handrolled proof
    let proof = if let Some(proof_positions) = handrolled_proof_positions {
        NodeMerkleProof::new(
            mmr.mmr_size(),
            proof_positions
                .iter()
                .map(|pos| (*pos, mmr.batch().get_elem(*pos).unwrap().unwrap()))
                .collect(),
        )
    } else {
        mmr.gen_node_proof(positions_to_verify.clone()).unwrap()
    };

    // if proof items have been tampered with, the proof verification fails
    if let Some(tampered_proof) = tampered_proof {
        let tampered_proof_result =
            tampered_proof.verify(root.clone(), tampered_entries_to_verify.clone());
        assert!(tampered_proof_result.is_err() || !tampered_proof_result.unwrap());
    }

    // if any nodes to be verified aren't members of the mmr, the proof verification fails
    let tampered_entries_result = proof.verify(root.clone(), tampered_entries_to_verify.clone());
    assert!(tampered_entries_result.is_err() || !tampered_entries_result.unwrap());

    let proof_verification = proof.verify(root, entries_to_verify);
    // verification of the correct nodes passes
    assert!(proof_verification.unwrap());
}

#[test]
fn test_generic_proofs() {
    // working with proof generation
    test_invalid_proof_verification(7, vec![5], vec![0], None, None);
    test_invalid_proof_verification(7, vec![1, 2], vec![0], None, None);
    test_invalid_proof_verification(7, vec![1, 5], vec![0], None, None);
    // original example with proof items [Merged(Merged(0, 1), Merged(2, 3)), Merged(4, 5), 6]:
    test_invalid_proof_verification(7, vec![1, 6], vec![0], None, Some(vec![6, 9, 10]));
    // original example, but with correct proof items [0, Merged(2, 3), Merged(6, Merged(4, 5))]
    test_invalid_proof_verification(7, vec![1, 6], vec![0], None, None);
    test_invalid_proof_verification(7, vec![1, 6], vec![0], Some(vec![0, 5, 9, 10]), None);
    test_invalid_proof_verification(7, vec![5, 6], vec![0], None, None);
    test_invalid_proof_verification(7, vec![1, 5, 6], vec![0], None, None);
    test_invalid_proof_verification(7, vec![1, 5, 7], vec![0], None, None);
    test_invalid_proof_verification(7, vec![5, 6, 7], vec![0], None, None);
    test_invalid_proof_verification(7, vec![5, 6, 7, 8, 9, 10], vec![0], None, None);
    test_invalid_proof_verification(7, vec![1, 5, 7, 8, 9, 10], vec![0], None, None);
    test_invalid_proof_verification(7, vec![0, 1, 5, 7, 8, 9, 10], vec![0], None, None);
    test_invalid_proof_verification(7, vec![0, 1, 5, 6, 7, 8, 9, 10], vec![0], None, None);
    test_invalid_proof_verification(7, vec![0, 1, 2, 5, 6, 7, 8, 9, 10], vec![0], None, None);

    test_invalid_proof_verification(
        7,
        vec![0, 1, 2, 3, 7, 8, 9, 10],
        vec![0],
        Some(vec![4]),
        None,
    );
    test_invalid_proof_verification(7, vec![0, 2, 3, 7, 8, 9, 10], vec![0], None, None);
    test_invalid_proof_verification(7, vec![0, 3, 7, 8, 9, 10], vec![0], None, None);
    test_invalid_proof_verification(7, vec![0, 2, 3, 7, 8, 9, 10], vec![0], None, None);
}

prop_compose! {
    fn count_elem(count: u32)
                (elem in 0..count)
                -> (u32, u32) {
                    (count, elem)
    }
}

fn nodes_subset(subset_index: u128, position_count: u8) -> Vec<u64> {
    let mut positions = vec![];

    for index in 0..position_count {
        if (1 << index) & subset_index != 0 {
            positions.push(index as u64)
        }
    }

    positions
}

const MAX_LEAVES_COUNT: u32 = 64;
proptest! {
    #![proptest_config(ProptestConfig {
        cases: 2000, max_shrink_iters: 2000, .. ProptestConfig::default()
    })]
    #[test]
    fn test_mmr_generic_proof_proptest(
        (leaves_count, (positions, tampered_node_position)) in (1..=MAX_LEAVES_COUNT)
            .prop_flat_map(|leaves_count| {let mmr_size = leaf_index_to_mmr_size(leaves_count as u64 - 1);
                                           let subset_index = 1u128..1u128.shl(mmr_size as u8);
                                           (Just(leaves_count),
                                            (Just(mmr_size), subset_index).prop_flat_map(|(mmr_size, subset_index)| {
                                               let positions = nodes_subset(subset_index, mmr_size as u8);
                                                (Just(positions.clone()), 0..positions.len())
                                           }))})
    ) {
        test_invalid_proof_verification(leaves_count, positions, vec![tampered_node_position], None, None)
    }
}

const MAX_POS: u8 = 11;
proptest! {
    // for 7 leaves, have 11 nodes, so 2^11 possible subsets of nodes to generate a proof for
    #[test]
    fn test_7_leaf_mmr_generic_proof_proptest(
        positions in (1u128..1u128.shl(MAX_POS)).prop_map(|subset_index| nodes_subset(subset_index, MAX_POS))
    ) {
        let leaves_count = 7;
        test_invalid_proof_verification(leaves_count, positions, vec![0], None, None)
    }
}

proptest! {
    #[test]
    fn test_random_mmr(count in 10u32..500u32) {
        let mut leaves: Vec<u32> = (0..count).collect();
        let mut rng = thread_rng();
        leaves.shuffle(&mut rng);
        let leaves_count = rng.gen_range(1..count - 1);
        leaves.truncate(leaves_count as usize);
        test_mmr(count, leaves);
    }

    #[test]
    fn test_random_gen_root_with_new_leaf(count in 1u32..500u32) {
        test_gen_new_root_from_proof(count);
    }
}
