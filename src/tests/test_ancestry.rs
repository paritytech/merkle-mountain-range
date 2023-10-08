use super::{MergeNumberHash, NumberHash};
use crate::leaf_index_to_mmr_size;
use crate::mmr::AncestryProof;
use crate::util::{MemMMR, MemStore};

#[test]
fn test_ancestry() {
    let store = MemStore::default();
    let mut mmr = MemMMR::<_, MergeNumberHash>::new(0, store);

    let mmr_size = 300;
    let mut prev_roots = Vec::new();
    for i in 0..mmr_size {
        mmr.push(NumberHash::from(i)).unwrap();
        prev_roots.push(mmr.get_root().expect("get root"));
    }

    let root = mmr.get_root().expect("get root");
    for i in 0..mmr_size {
        let prev_size = leaf_index_to_mmr_size(i.into());
        let AncestryProof {
            prev_root,
            prev_peaks,
            merkle_proof,
        } = mmr.gen_ancestry_proof(prev_size).expect("gen proof");
        assert_eq!(prev_roots[i as usize], prev_root);
        assert!(merkle_proof
            .verify_ancestor(root.clone(), &prev_roots[i as usize], prev_size, prev_peaks)
            .unwrap());
    }
}
