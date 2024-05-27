use super::{MergeNumberHash, NumberHash};
use crate::leaf_index_to_mmr_size;
use crate::util::{MemMMR, MemStore};

const MMR_SIZE: u32 = 1000;

#[test]
fn test_ancestry() {
    let store = MemStore::default();
    let mut mmr = MemMMR::<_, MergeNumberHash>::new(0, &store);

    let mut prev_roots = Vec::new();
    for i in 0..MMR_SIZE {
        mmr.push(NumberHash::from(i)).unwrap();
        prev_roots.push(mmr.get_root().expect("get root"));
    }

    let root = mmr.get_root().expect("get root");
    for i in 0..MMR_SIZE {
        let prev_size = leaf_index_to_mmr_size(i.into());
        let ancestry_proof = mmr.gen_ancestry_proof(prev_size).expect("gen proof");
        assert!(ancestry_proof
            .verify_ancestor(root.clone(), prev_roots[i as usize].clone())
            .unwrap());
    }
}

#[test]
fn test_ancestry_next_leaf() {
    let store = MemStore::default();
    let mut mmr = MemMMR::<_, MergeNumberHash>::new(0, &store);

    let mut prev_roots = Vec::new();
    for i in 0..MMR_SIZE {
        mmr.push(NumberHash::from(i)).unwrap();
        println!("{:?}", mmr.get_root().expect("get root"));
        prev_roots.push(mmr.get_root().expect("get root"));
    }

    let root = mmr.get_root().expect("get root");
    for i in 0..MMR_SIZE - 1 {
        let (next_leaf, ancestry_proof) = mmr
            .gen_ancestry_proof_next_leaf(i as u64)
            .expect("gen proof");
        assert!(ancestry_proof
            .verify_ancestor_next_leaf(root.clone(), next_leaf, prev_roots[i as usize].clone())
            .unwrap());
    }
}
