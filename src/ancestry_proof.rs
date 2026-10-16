use crate::collections::VecDeque;
use crate::helper::{
    get_peak_map, get_peaks, is_descendant_pos, is_valid_mmr_size, leaf_index_to_mmr_size,
    leaf_index_to_pos, parent_offset, pos_height_in_tree, sibling_offset,
};
pub use crate::mmr::bagging_peaks_hashes;
use crate::mmr::take_while_vec;
use crate::util::VeqDequeExt;
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
    pub prev_mmr_size: u64,
    pub prev_peaks: Vec<T>,
    pub prev_peaks_proof: NodeMerkleProof<T, M>,
}

impl<T: PartialEq + Debug + Clone, M: Merge<Item = T>> AncestryProof<T, M> {
    // TODO: restrict roots to be T::Node
    pub fn verify_ancestor(&self, root: T, prev_root: T) -> Result<bool> {
        if !is_valid_mmr_size(self.prev_peaks_proof.mmr_size)
            || !is_valid_mmr_size(self.prev_mmr_size)
        {
            return Err(Error::CorruptedProof);
        }
        let current_leaves_count = get_peak_map(self.prev_peaks_proof.mmr_size);
        if current_leaves_count <= self.prev_peaks.len() as u64 {
            return Err(Error::CorruptedProof);
        }
        // Test if previous root is correct.
        let prev_peaks_positions = {
            let prev_peaks_positions = get_peaks(self.prev_mmr_size);
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

        self.prev_peaks_proof.verify(root, nodes)
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
        if !is_valid_mmr_size(self.mmr_size) {
            return Err(Error::CorruptedProof);
        }
        let current_leaves_count = get_peak_map(self.mmr_size);
        if current_leaves_count <= incremental.len() as u64 {
            return Err(Error::CorruptedProof);
        }
        // Test if previous root is correct.
        let prev_leaves_count = current_leaves_count - incremental.len() as u64;

        // Bind proof items to the canonical peak positions of the previous MMR, otherwise
        // an attacker could permute the proof items and submit a forged `prev_root`
        // computed by bagging peaks in a non-canonical order.
        let prev_mmr_size = leaf_index_to_mmr_size(prev_leaves_count - 1);
        let expected_prev_peak_positions = get_peaks(prev_mmr_size);
        if self.proof.len() != expected_prev_peak_positions.len() {
            return Err(Error::CorruptedProof);
        }
        let mut prev_peaks: Vec<T> = Vec::with_capacity(self.proof.len());
        for (expected_pos, (actual_pos, item)) in
            expected_prev_peak_positions.iter().zip(self.proof.iter())
        {
            if *actual_pos != *expected_pos {
                return Err(Error::CorruptedProof);
            }
            prev_peaks.push(item.clone());
        }

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
    if !is_valid_mmr_size(mmr_size) {
        return Err(Error::CorruptedProof);
    }
    // special handle the only 1 leaf MMR
    if mmr_size == 1 && nodes.len() == 1 && nodes[0].0 == 0 {
        return Ok(nodes.into_iter().map(|(_pos, item)| item).collect());
    }

    let mut nodes: Vec<_> = nodes
        .into_iter()
        .chain(proof_iter.cloned())
        .sorted_by_key(|(pos, _)| *pos)
        .collect();

    // Reject conflicting entries at the same position before deduping; otherwise a single
    // proof could verify contradictory values for the same node.
    for pair in nodes.windows(2) {
        if pair[0].0 == pair[1].0 && pair[0].1 != pair[1].1 {
            return Err(Error::CorruptedProof);
        }
    }
    nodes.dedup_by(|a, b| a.0 == b.0);

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

    // Old `mmr.rs` code. It's not needed anymore since now we merge the `proof_iter`
    // items with the nodes.
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

/// The positions of the items `MMR::gen_ancestry_proof(prev_mmr_size)` emits for an MMR of
/// `mmr_size` nodes, in proof order — the exact positions its `prev_peaks_proof` carries, including
/// the single item that stands for a bagged run of right-hand peaks.
///
/// An MMR's shape is fixed by its size, so this is a pure function of the two sizes and needs no
/// store. A verifier that receives an ancestry proof as bare hashes can re-derive their positions
/// with it and hand `(position, hash)` pairs to [`NodeMerkleProof`].
///
/// Verifier-facing, so bad sizes are a `CorruptedProof`, as the verifiers report them: both must be
/// valid MMR sizes, and `prev_mmr_size` non-zero and at most `mmr_size`.
/// `gen_ancestry_proof` shares the layout below but not these checks. Any `u64` sizes are cheap:
/// the result has at most 63 positions.
pub fn ancestry_proof_positions(prev_mmr_size: u64, mmr_size: u64) -> Result<Vec<u64>> {
    if prev_mmr_size == 0
        || prev_mmr_size > mmr_size
        || !is_valid_mmr_size(prev_mmr_size)
        || !is_valid_mmr_size(mmr_size)
    {
        return Err(Error::CorruptedProof);
    }
    let (mut positions, bagged_run) = ancestry_proof_layout(prev_mmr_size, mmr_size)?;
    // The generator bags the trailing run into one item at the position of its first peak.
    if let Some(&first) = bagged_run.first() {
        positions.push(first);
    }
    positions.sort_unstable();
    Ok(positions)
}

/// The proof-item positions of an ancestry proof, in emission order, split into the individually
/// proven positions and the trailing run of right-hand peaks with nothing proven beneath them that
/// the proof bags into a single item (empty unless there are at least two). `gen_ancestry_proof`
/// fetches both from the store and bags the run's hashes; [`ancestry_proof_positions`] keeps only
/// the run's first position. Splitting here keeps that boundary in one place.
///
/// Errors as `gen_ancestry_proof` always has: `GenProofForInvalidNodes` for an empty previous MMR
/// or one whose peaks do not all lie within `mmr_size`.
pub(crate) fn ancestry_proof_layout(
    prev_mmr_size: u64,
    mmr_size: u64,
) -> Result<(Vec<u64>, Vec<u64>)> {
    let mut pos_list = get_peaks(prev_mmr_size);
    if pos_list.is_empty() {
        return Err(Error::GenProofForInvalidNodes);
    }
    if mmr_size == 1 && pos_list == [0] {
        return Ok((Vec::new(), Vec::new()));
    }
    let mut positions: Vec<u64> = Vec::new();
    let mut bagging_track = 0;
    for peak_pos in get_peaks(mmr_size) {
        let pos_list: Vec<_> = take_while_vec(&mut pos_list, |&pos| pos <= peak_pos);
        if pos_list.is_empty() {
            bagging_track += 1;
        } else {
            bagging_track = 0;
        }
        node_proof_positions_for_peak(&mut positions, pos_list, peak_pos);
    }
    if !pos_list.is_empty() {
        return Err(Error::GenProofForInvalidNodes);
    }
    // A run of two or more trailing peaks with nothing proven beneath them is bagged into one item.
    let bagged_run = if bagging_track > 1 {
        positions.split_off(positions.len() - bagging_track)
    } else {
        Vec::new()
    };
    Ok((positions, bagged_run))
}

/// The positions a node proof for `pos_list` under the peak at `peak_pos` consists of, appended to
/// `positions`: the store-free half of `MMR::gen_node_proof_for_peak`, which fetches exactly these.
pub(crate) fn node_proof_positions_for_peak(
    positions: &mut Vec<u64>,
    pos_list: Vec<u64>,
    peak_pos: u64,
) {
    // Nothing to prove if the position itself is the peak.
    if pos_list.len() == 1 && pos_list == [peak_pos] {
        return;
    }
    // The peak root stands in when no positions beneath it are proven.
    if pos_list.is_empty() {
        positions.push(peak_pos);
        return;
    }

    let mut queue: VecDeque<_> = VecDeque::new();
    for value in pos_list.iter().map(|pos| (pos_height_in_tree(*pos), *pos)) {
        queue.insert_sorted(value);
    }

    while let Some((height, pos)) = queue.pop_front() {
        debug_assert!(pos <= peak_pos);
        if pos == peak_pos {
            if queue.is_empty() {
                break;
            } else {
                continue;
            }
        }

        let (sib_pos, parent_pos) = {
            let next_height = pos_height_in_tree(pos + 1);
            let sibling_offset = sibling_offset(height);
            if next_height > height {
                // `pos` is a right sibling
                (pos - sibling_offset, pos + 1)
            } else {
                // `pos` is a left sibling
                (pos + sibling_offset, pos + parent_offset(height))
            }
        };

        if Some(&sib_pos) == queue.front().map(|(_, pos)| pos) {
            // The sibling is itself being proven; drop it.
            queue.pop_front();
        } else {
            positions.push(sib_pos);
        }
        if parent_pos < peak_pos {
            queue.insert_sorted((height + 1, parent_pos));
        }
    }
}

pub fn expected_ancestry_proof_size(prev_mmr_size: u64, mmr_size: u64) -> usize {
    let mut expected_proof_size: usize = 0;
    let mut prev_peaks = get_peaks(prev_mmr_size);
    let peaks = get_peaks(mmr_size);

    for peak in peaks.iter() {
        let local_prev_peaks: Vec<u64> = take_while_vec(&mut prev_peaks, |pos| *pos <= *peak);

        // skip if the peak is also the prev_peak: then trivially no additional proof items
        if local_prev_peaks.as_slice() == [*peak] {
            continue;
        }

        // calculate the number of leaves after the last element of local_prev_peaks
        let leaves = 1 << pos_height_in_tree(*peak);
        let local_prev_peaks_leaves: u64 = local_prev_peaks
            .iter()
            .map(|pos| 1 << pos_height_in_tree(*pos))
            .sum();
        let leaves_diff = leaves - local_prev_peaks_leaves;

        expected_proof_size += leaves_diff.count_ones() as usize;

        if local_prev_peaks.is_empty() {
            break;
        }
    }

    expected_proof_size
}
