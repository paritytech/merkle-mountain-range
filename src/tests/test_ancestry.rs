use super::{MergeNumberHash, NumberHash};
use crate::util::{MemMMR, MemStore};

#[test]
fn test_ancestry() {
    let store = MemStore::default();
    let mut mmr = MemMMR::<_, MergeNumberHash>::new(0, store);

    for i in 0..30 {
        mmr.push(NumberHash::from(i)).unwrap();
    }
    let prev_root = mmr.get_root().expect("get root");
    let prev_size = mmr.mmr_size();
    for i in 30..90 {
        mmr.push(NumberHash::from(i)).unwrap();
    }

    let root = mmr.get_root().expect("get root");
    let (prev_root_via_proof_gen, prev_peaks, proof) = mmr.gen_prefix_proof(prev_size).expect("gen proof");
    assert_eq!(prev_root, prev_root_via_proof_gen);
    assert!(proof.verify_ancestor(root, prev_root, prev_size, prev_peaks).unwrap());
}
