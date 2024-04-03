use crate::collections::VecDeque;
use crate::helper::{
    get_peak_map, get_peaks, is_descendant_pos, leaf_index_to_pos, parent_offset,
    pos_height_in_tree, sibling_offset,
};
use crate::mmr::{bagging_peaks_hashes, take_while_vec};
use crate::vec::Vec;
use crate::{Error, Merge, Result};
use core::fmt::Debug;
use core::marker::PhantomData;
use itertools::Itertools;

#[derive(Debug)]
pub struct NodeMerkleProof<T, M> {
    mmr_size: u64,
    proof: Vec<(u64, T)>,
    merge: PhantomData<M>,
}

#[derive(Debug)]
pub struct AncestryProof<T, M> {
    pub prev_peaks: Vec<T>,
    pub prev_size: u64,
    pub proof: NodeMerkleProof<T, M>,
}

impl<T: PartialEq + Debug + Clone, M: Merge<Item = T>> AncestryProof<T, M> {
    // TODO: restrict roots to be T::Node
    pub fn verify_ancestor(&self, root: T, prev_root: T) -> Result<bool> {
        let current_leaves_count = get_peak_map(self.proof.mmr_size);
        if current_leaves_count <= self.prev_peaks.len() as u64 {
            return Err(Error::CorruptedProof);
        }
        // Test if previous root is correct.
        let prev_peaks_positions = {
            let prev_peaks_positions = get_peaks(self.prev_size);
            if prev_peaks_positions.len() != self.prev_peaks.len() {
                return Err(Error::CorruptedProof);
            }
            prev_peaks_positions
        };

        let calculated_prev_root = bagging_peaks_hashes::<T, M>(self.prev_peaks.clone())?;
        if calculated_prev_root != prev_root {
            return Ok(false);
        }

        let nodes = self
            .prev_peaks
            .clone()
            .into_iter()
            .zip(prev_peaks_positions.iter())
            .map(|(peak, position)| (*position, peak))
            .collect();

        self.proof.verify(root, nodes)
    }
}

impl<T: Clone + PartialEq, M: Merge<Item = T>> NodeMerkleProof<T, M> {
    pub fn new(mmr_size: u64, proof: Vec<(u64, T)>) -> Self {
        NodeMerkleProof {
            mmr_size,
            proof,
            merge: PhantomData,
        }
    }

    pub fn mmr_size(&self) -> u64 {
        self.mmr_size
    }

    pub fn proof_items(&self) -> &[(u64, T)] {
        &self.proof
    }

    pub fn calculate_root(&self, leaves: Vec<(u64, T)>) -> Result<T> {
        calculate_root::<_, M, _>(leaves, self.mmr_size, self.proof.iter())
    }

    /// from merkle proof of leaf n to calculate merkle root of n + 1 leaves.
    /// by observe the MMR construction graph we know it is possible.
    /// https://github.com/jjyr/merkle-mountain-range#construct
    pub fn calculate_root_with_new_leaf(
        &self,
        mut nodes: Vec<(u64, T)>,
        new_pos: u64,
        new_elem: T,
        new_mmr_size: u64,
    ) -> Result<T> {
        nodes.push((new_pos, new_elem));
        calculate_root::<_, M, _>(nodes, new_mmr_size, self.proof.iter())
    }

    pub fn verify(&self, root: T, nodes: Vec<(u64, T)>) -> Result<bool> {
        let calculated_root = self.calculate_root(nodes)?;
        Ok(calculated_root == root)
    }

    /// Verifies a old root and all incremental leaves.
    ///
    /// If this method returns `true`, it means the following assertion are true:
    /// - The old root could be generated in the history of the current MMR.
    /// - All incremental leaves are on the current MMR.
    /// - The MMR, which could generate the old root, appends all incremental leaves, becomes the
    ///   current MMR.
    pub fn verify_incremental(&self, root: T, prev_root: T, incremental: Vec<T>) -> Result<bool> {
        let current_leaves_count = get_peak_map(self.mmr_size);
        if current_leaves_count <= incremental.len() as u64 {
            return Err(Error::CorruptedProof);
        }
        // Test if previous root is correct.
        let prev_leaves_count = current_leaves_count - incremental.len() as u64;

        let prev_peaks: Vec<_> = self
            .proof_items()
            .iter()
            .map(|(_, item)| item.clone())
            .collect();

        let calculated_prev_root = bagging_peaks_hashes::<T, M>(prev_peaks)?;
        if calculated_prev_root != prev_root {
            return Ok(false);
        }

        // Test if incremental leaves are correct.
        let leaves = incremental
            .into_iter()
            .enumerate()
            .map(|(index, leaf)| {
                let pos = leaf_index_to_pos(prev_leaves_count + index as u64);
                (pos, leaf)
            })
            .collect();
        self.verify(root, leaves)
    }
}

fn calculate_peak_root<
    'a,
    T: 'a + PartialEq,
    M: Merge<Item = T>,
    // I: Iterator<Item = &'a T>
>(
    nodes: Vec<(u64, T)>,
    peak_pos: u64,
    // proof_iter: &mut I,
) -> Result<T> {
    debug_assert!(!nodes.is_empty(), "can't be empty");
    // (position, hash, height)

    let mut queue: VecDeque<_> = nodes
        .into_iter()
        .map(|(pos, item)| (pos, item, pos_height_in_tree(pos)))
        .collect();

    let mut sibs_processed_from_back = Vec::new();

    // calculate tree root from each items
    while let Some((pos, item, height)) = queue.pop_front() {
        if pos == peak_pos {
            if queue.is_empty() {
                // return root once queue is consumed
                return Ok(item);
            }
            if queue
                .iter()
                .any(|entry| entry.0 == peak_pos && entry.1 != item)
            {
                return Err(Error::CorruptedProof);
            }
            if queue
                .iter()
                .all(|entry| entry.0 == peak_pos && &entry.1 == &item && entry.2 == height)
            {
                // return root if remaining queue consists only of duplicate root entries
                return Ok(item);
            }
            // if queue not empty, push peak back to the end
            queue.push_back((pos, item, height));
            continue;
        }
        // calculate sibling
        let next_height = pos_height_in_tree(pos + 1);
        let (parent_pos, parent_item) = {
            let sibling_offset = sibling_offset(height);
            if next_height > height {
                // implies pos is right sibling
                let (sib_pos, parent_pos) = (pos - sibling_offset, pos + 1);
                let parent_item = if Some(&sib_pos) == queue.front().map(|(pos, _, _)| pos) {
                    let sibling_item = queue.pop_front().map(|(_, item, _)| item).unwrap();
                    M::merge(&sibling_item, &item)?
                } else if Some(&sib_pos) == queue.back().map(|(pos, _, _)| pos) {
                    let sibling_item = queue.pop_back().map(|(_, item, _)| item).unwrap();
                    M::merge(&sibling_item, &item)?
                }
                // handle special if next queue item is descendant of sibling
                else if let Some(&(front_pos, ..)) = queue.front() {
                    if height > 0 && is_descendant_pos(sib_pos, front_pos) {
                        queue.push_back((pos, item, height));
                        continue;
                    } else {
                        return Err(Error::CorruptedProof);
                    }
                } else {
                    return Err(Error::CorruptedProof);
                };
                (parent_pos, parent_item)
            } else {
                // pos is left sibling
                let (sib_pos, parent_pos) = (pos + sibling_offset, pos + parent_offset(height));
                let parent_item = if Some(&sib_pos) == queue.front().map(|(pos, _, _)| pos) {
                    let sibling_item = queue.pop_front().map(|(_, item, _)| item).unwrap();
                    M::merge(&item, &sibling_item)?
                } else if Some(&sib_pos) == queue.back().map(|(pos, _, _)| pos) {
                    let sibling_item = queue.pop_back().map(|(_, item, _)| item).unwrap();
                    let parent = M::merge(&item, &sibling_item)?;
                    sibs_processed_from_back.push((sib_pos, sibling_item, height));
                    parent
                } else if let Some(&(front_pos, ..)) = queue.front() {
                    if height > 0 && is_descendant_pos(sib_pos, front_pos) {
                        queue.push_back((pos, item, height));
                        continue;
                    } else {
                        return Err(Error::CorruptedProof);
                    }
                } else {
                    return Err(Error::CorruptedProof);
                };
                (parent_pos, parent_item)
            }
        };

        if parent_pos <= peak_pos {
            let parent = (parent_pos, parent_item, height + 1);
            if peak_pos == parent_pos
                || queue.front() != Some(&parent)
                    && !sibs_processed_from_back.iter().any(|item| item == &parent)
            {
                queue.push_front(parent)
            };
        } else {
            return Err(Error::CorruptedProof);
        }
    }
    Err(Error::CorruptedProof)
}

fn calculate_peaks_hashes<
    'a,
    T: 'a + PartialEq + Clone,
    M: Merge<Item = T>,
    I: Iterator<Item = &'a (u64, T)>,
>(
    nodes: Vec<(u64, T)>,
    mmr_size: u64,
    proof_iter: I,
) -> Result<Vec<T>> {
    // special handle the only 1 leaf MMR
    if mmr_size == 1 && nodes.len() == 1 && nodes[0].0 == 0 {
        return Ok(nodes.into_iter().map(|(_pos, item)| item).collect());
    }

    // ensure nodes are sorted and unique
    let mut nodes: Vec<_> = nodes
        .into_iter()
        .chain(proof_iter.cloned())
        .sorted_by_key(|(pos, _)| *pos)
        .dedup_by(|a, b| a.0 == b.0)
        .collect();

    let peaks = get_peaks(mmr_size);

    let mut peaks_hashes: Vec<T> = Vec::with_capacity(peaks.len() + 1);
    for peak_pos in peaks {
        let mut nodes: Vec<(u64, T)> = take_while_vec(&mut nodes, |(pos, _)| *pos <= peak_pos);
        let peak_root = if nodes.len() == 1 && nodes[0].0 == peak_pos {
            // leaf is the peak
            nodes.remove(0).1
        } else if nodes.is_empty() {
            // if empty, means the next proof is a peak root or rhs bagged root
            // means that either all right peaks are bagged, or proof is corrupted
            // so we break loop and check no items left
            break;
        } else {
            calculate_peak_root::<_, M>(nodes, peak_pos)?
        };
        peaks_hashes.push(peak_root.clone());
    }

    // ensure nothing left in leaves
    if nodes.len() != 0 {
        return Err(Error::CorruptedProof);
    }

    // check rhs peaks
    // if let Some((_, rhs_peaks_hashes)) = proof_iter.next() {
    //     peaks_hashes.push(rhs_peaks_hashes.clone());
    // }
    // ensure nothing left in proof_iter
    // if proof_iter.next().is_some() {
    //     return Err(Error::CorruptedProof);
    // }
    Ok(peaks_hashes)
}

/// merkle proof
/// 1. sort items by position
/// 2. calculate root of each peak
/// 3. bagging peaks
fn calculate_root<
    'a,
    T: 'a + PartialEq + Clone,
    M: Merge<Item = T>,
    I: Iterator<Item = &'a (u64, T)>,
>(
    nodes: Vec<(u64, T)>,
    mmr_size: u64,
    proof_iter: I,
) -> Result<T> {
    let peaks_hashes = calculate_peaks_hashes::<_, M, _>(nodes, mmr_size, proof_iter)?;
    bagging_peaks_hashes::<_, M>(peaks_hashes)
}

