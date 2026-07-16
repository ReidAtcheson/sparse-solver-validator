//! Streaming BLAKE3 Merkle commitments for canonical complex binary64 leaves.
//!
//! This is intentionally the complex multiproof subset used by the
//! coefficient-aligned unit-circle protocol. Scalar trees and one-leaf wire
//! openings from the research crate are omitted. A builder retains one hash
//! per tree height plus `O(q log N)` temporary authentication data; a verifier
//! retains only the canonical joint frontier for the caller-derived indices.
//!
//! Hash domains, logical-shape binding, padding, index order, and frontier
//! order are frozen from `fast-validation/src/merkle.rs` at research revision
//! `be8b67b74da54d162df2e6e0a9d813779959bb60`.

use thiserror::Error;

const COMPLEX_LEAF_DOMAIN: &[u8] = b"sparse-solution/fast-validation/merkle/complex-leaf/v2";
const COMPLEX_PADDING_DOMAIN: &[u8] = b"sparse-solution/fast-validation/merkle/complex-padding/v2";
const COMPLEX_NODE_DOMAIN: &[u8] = b"sparse-solution/fast-validation/merkle/complex-node/v2";

/// A BLAKE3 Merkle root.
pub type MerkleRoot = [u8; 32];

/// A canonical compact opening of several complex leaves.
///
/// Indices are deliberately absent. `value_bits[i]` opens the independently
/// derived `expected_indices[i]`. `frontier` contains every missing sibling
/// subtree exactly once, from leaves upward and then by increasing node index.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComplexMultiProof {
    pub value_bits: Vec<[u64; 2]>,
    pub frontier: Vec<MerkleRoot>,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum MerkleError {
    #[error("a Merkle tree must contain at least one leaf")]
    EmptyTree,
    #[error("a Merkle multiproof must open at least one leaf")]
    EmptyOpeningSet,
    #[error("Merkle leaf-count padding overflow")]
    LeafCountOverflow,
    #[error("Merkle opening index {index} is outside the {leaf_count}-leaf tree")]
    IndexOutOfBounds { index: usize, leaf_count: usize },
    #[error("Merkle opening index {index} is duplicated")]
    DuplicateOpeningIndex { index: usize },
    #[error("Merkle opening indices are not sorted: {current} follows {previous}")]
    UnsortedOpeningIndices { previous: usize, current: usize },
    #[error("Merkle multiproof has {actual} opened values; exactly {expected} are required")]
    OpeningValueCount { expected: usize, actual: usize },
    #[error("Merkle multiproof has {actual} frontier hashes; exactly {expected} are required")]
    FrontierCount { expected: usize, actual: usize },
    #[error("Merkle opening has {actual} siblings; exactly {expected} are required")]
    SiblingCount { expected: usize, actual: usize },
    #[error("Merkle opening index {actual} does not match expected index {expected}")]
    OpeningIndexMismatch { expected: usize, actual: usize },
    #[error("Merkle openings disagree on frontier node {index} at level {level}")]
    InconsistentFrontierHash { level: usize, index: usize },
    #[error("Merkle opening does not match the root")]
    RootMismatch,
}

/// Computes a complex-leaf root without materializing hash levels.
///
/// The bit pairs must already satisfy the floating-point contract. This layer
/// intentionally commits exact bytes and does not reinterpret them as `f64`.
pub fn streaming_complex_root(
    tree_label: &[u8],
    value_bits: &[[u64; 2]],
) -> Result<MerkleRoot, MerkleError> {
    streaming_complex_root_iter(tree_label, value_bits.iter().copied())
}

/// Iterator form of [`streaming_complex_root`].
///
/// `ExactSizeIterator` binds the logical shape before any leaf is consumed.
pub fn streaming_complex_root_iter<I>(
    tree_label: &[u8],
    value_bits: I,
) -> Result<MerkleRoot, MerkleError>
where
    I: ExactSizeIterator<Item = [u64; 2]>,
{
    streaming_complex_root_and_openings_iter(tree_label, value_bits, &[]).map(|(root, _)| root)
}

/// Computes a complex root and canonical compact multiproof from a slice.
pub fn streaming_complex_root_and_multiproof(
    tree_label: &[u8],
    value_bits: &[[u64; 2]],
    selected_indices: &[usize],
) -> Result<(MerkleRoot, ComplexMultiProof), MerkleError> {
    streaming_complex_root_and_multiproof_iter(
        tree_label,
        value_bits.iter().copied(),
        selected_indices,
    )
}

/// Iterator form of [`streaming_complex_root_and_multiproof`].
///
/// It retains `O(q log N)` temporary path hashes but never allocates an `O(N)`
/// parallel bit or hash array. Selected indices must be strictly increasing.
pub fn streaming_complex_root_and_multiproof_iter<I>(
    tree_label: &[u8],
    value_bits: I,
    selected_indices: &[usize],
) -> Result<(MerkleRoot, ComplexMultiProof), MerkleError>
where
    I: ExactSizeIterator<Item = [u64; 2]>,
{
    let leaf_count = value_bits.len();
    let (root, openings) =
        streaming_complex_root_and_openings_iter(tree_label, value_bits, selected_indices)?;
    let proof = compact_openings(leaf_count, selected_indices, &openings)?;
    Ok((root, proof))
}

/// Returns the exact number of frontier hashes for a public shape and indices.
pub fn complex_multiproof_frontier_len(
    leaf_count: usize,
    expected_indices: &[usize],
) -> Result<usize, MerkleError> {
    Ok(complex_multiproof_frontier_positions(leaf_count, expected_indices)?.len())
}

/// Strictly verifies a canonical compact complex multiproof.
///
/// The proof supplies neither indices nor shape. Missing, extra, duplicate,
/// unsorted, or reordered material is rejected. The return value counts leaf
/// and internal-node BLAKE3 hashes performed by verification.
pub fn verify_complex_multiproof(
    tree_label: &[u8],
    leaf_count: usize,
    root: &MerkleRoot,
    expected_indices: &[usize],
    proof: &ComplexMultiProof,
) -> Result<usize, MerkleError> {
    validate_multiproof_indices(expected_indices, leaf_count)?;
    if proof.value_bits.len() != expected_indices.len() {
        return Err(MerkleError::OpeningValueCount {
            expected: expected_indices.len(),
            actual: proof.value_bits.len(),
        });
    }
    let frontier_positions = complex_multiproof_frontier_positions(leaf_count, expected_indices)?;
    if proof.frontier.len() != frontier_positions.len() {
        return Err(MerkleError::FrontierCount {
            expected: frontier_positions.len(),
            actual: proof.frontier.len(),
        });
    }

    let tree_height = padded_leaf_count(leaf_count)?.ilog2() as usize;
    let mut nodes = expected_indices
        .iter()
        .copied()
        .zip(&proof.value_bits)
        .map(|(index, &[real_bits, imaginary_bits])| {
            (
                index,
                hash_complex_leaf(tree_label, leaf_count, index, real_bits, imaginary_bits),
            )
        })
        .collect::<Vec<_>>();
    let mut hash_count = nodes.len();
    let mut frontier_cursor = 0_usize;

    for level in 0..tree_height {
        let mut parents = Vec::with_capacity(nodes.len().div_ceil(2));
        let mut cursor = 0_usize;
        while cursor < nodes.len() {
            let (node_index, node_hash) = nodes[cursor];
            let selected_sibling = nodes
                .get(cursor + 1)
                .filter(|(next_index, _)| node_index & 1 == 0 && *next_index == node_index + 1);
            let (left, right, consumed) = if let Some(&(_, sibling_hash)) = selected_sibling {
                (node_hash, sibling_hash, 2)
            } else {
                let position = frontier_positions[frontier_cursor];
                debug_assert_eq!(position.level, level);
                debug_assert_eq!(position.index, node_index ^ 1);
                let sibling_hash = proof.frontier[frontier_cursor];
                frontier_cursor += 1;
                if node_index & 1 == 0 {
                    (node_hash, sibling_hash, 1)
                } else {
                    (sibling_hash, node_hash, 1)
                }
            };
            let parent_index = node_index / 2;
            parents.push((
                parent_index,
                hash_complex_node(
                    tree_label,
                    leaf_count,
                    level + 1,
                    parent_index,
                    &left,
                    &right,
                ),
            ));
            hash_count += 1;
            cursor += consumed;
        }
        nodes = parents;
    }

    debug_assert_eq!(frontier_cursor, proof.frontier.len());
    debug_assert_eq!(nodes.len(), 1);
    if &nodes[0].1 != root {
        return Err(MerkleError::RootMismatch);
    }
    Ok(hash_count)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ComplexOpening {
    index: usize,
    real_bits: u64,
    imaginary_bits: u64,
    siblings: Vec<MerkleRoot>,
}

fn streaming_complex_root_and_openings_iter<I>(
    tree_label: &[u8],
    value_bits: I,
    selected_indices: &[usize],
) -> Result<(MerkleRoot, Vec<ComplexOpening>), MerkleError>
where
    I: ExactSizeIterator<Item = [u64; 2]>,
{
    let leaf_count = value_bits.len();
    let padded_leaf_count = padded_leaf_count(leaf_count)?;
    validate_selected_indices(selected_indices, leaf_count)?;

    let tree_height = padded_leaf_count.ilog2() as usize;
    let mut paths = (0..selected_indices.len())
        .map(|_| Vec::with_capacity(tree_height))
        .collect::<Vec<_>>();
    let mut frontier: Vec<Option<StreamingNode>> = vec![None; tree_height + 1];
    let mut selected_cursor = 0_usize;
    let mut selected_values = Vec::with_capacity(selected_indices.len());

    let padded_values = value_bits
        .map(Some)
        .chain((leaf_count..padded_leaf_count).map(|_| None));
    for (leaf_index, value_bits) in padded_values.enumerate() {
        let hash = if let Some([real_bits, imaginary_bits]) = value_bits {
            hash_complex_leaf(
                tree_label,
                leaf_count,
                leaf_index,
                real_bits,
                imaginary_bits,
            )
        } else {
            hash_complex_padding(tree_label, leaf_count, leaf_index)
        };
        let selected_range = if selected_indices.get(selected_cursor) == Some(&leaf_index) {
            let [real_bits, imaginary_bits] =
                value_bits.expect("a selected logical leaf cannot be synthetic padding");
            selected_values.push([real_bits, imaginary_bits]);
            let range = Some(SelectedRange {
                start: selected_cursor,
                end: selected_cursor + 1,
            });
            selected_cursor += 1;
            range
        } else {
            None
        };
        let mut node = StreamingNode {
            hash,
            node_index: leaf_index,
            selected_range,
        };
        let mut height = 0_usize;

        while let Some(left) = frontier[height].take() {
            debug_assert_eq!(left.node_index + 1, node.node_index);
            append_sibling(&mut paths, left.selected_range, node.hash);
            append_sibling(&mut paths, node.selected_range, left.hash);
            let parent_index = node.node_index / 2;
            node = StreamingNode {
                hash: hash_complex_node(
                    tree_label,
                    leaf_count,
                    height + 1,
                    parent_index,
                    &left.hash,
                    &node.hash,
                ),
                node_index: parent_index,
                selected_range: merge_selected_ranges(left.selected_range, node.selected_range),
            };
            height += 1;
        }
        frontier[height] = Some(node);
    }

    debug_assert_eq!(selected_cursor, selected_indices.len());
    debug_assert_eq!(selected_values.len(), selected_indices.len());
    let root = frontier[tree_height]
        .take()
        .expect("power-of-two streaming reduction must produce one root")
        .hash;
    debug_assert!(frontier.into_iter().all(|node| node.is_none()));
    let openings = selected_indices
        .iter()
        .copied()
        .zip(selected_values)
        .zip(paths)
        .map(
            |((index, [real_bits, imaginary_bits]), siblings)| ComplexOpening {
                index,
                real_bits,
                imaginary_bits,
                siblings,
            },
        )
        .collect();
    Ok((root, openings))
}

fn compact_openings(
    leaf_count: usize,
    expected_indices: &[usize],
    openings: &[ComplexOpening],
) -> Result<ComplexMultiProof, MerkleError> {
    validate_multiproof_indices(expected_indices, leaf_count)?;
    if openings.len() != expected_indices.len() {
        return Err(MerkleError::OpeningValueCount {
            expected: expected_indices.len(),
            actual: openings.len(),
        });
    }

    let tree_height = padded_leaf_count(leaf_count)?.ilog2() as usize;
    let mut value_bits = Vec::with_capacity(openings.len());
    for (&expected_index, opening) in expected_indices.iter().zip(openings) {
        if opening.index != expected_index {
            return Err(MerkleError::OpeningIndexMismatch {
                expected: expected_index,
                actual: opening.index,
            });
        }
        if opening.siblings.len() != tree_height {
            return Err(MerkleError::SiblingCount {
                expected: tree_height,
                actual: opening.siblings.len(),
            });
        }
        value_bits.push([opening.real_bits, opening.imaginary_bits]);
    }

    let positions = complex_multiproof_frontier_positions(leaf_count, expected_indices)?;
    let mut frontier = Vec::with_capacity(positions.len());
    for position in positions {
        let mut selected_hash = None;
        for opening in openings {
            let selected_node = opening.index >> position.level;
            if selected_node ^ 1 == position.index {
                let hash = opening.siblings[position.level];
                if selected_hash.is_some_and(|previous| previous != hash) {
                    return Err(MerkleError::InconsistentFrontierHash {
                        level: position.level,
                        index: position.index,
                    });
                }
                selected_hash = Some(hash);
            }
        }
        frontier
            .push(selected_hash.expect("every canonical frontier node borders a selected subtree"));
    }
    Ok(ComplexMultiProof {
        value_bits,
        frontier,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FrontierPosition {
    /// Zero is the leaf level; level `k` contains `2^k` padded leaves.
    level: usize,
    index: usize,
}

fn validate_multiproof_indices(
    expected_indices: &[usize],
    leaf_count: usize,
) -> Result<(), MerkleError> {
    if expected_indices.is_empty() {
        // Preserve EmptyTree precedence for a zero-leaf public shape.
        padded_leaf_count(leaf_count)?;
        return Err(MerkleError::EmptyOpeningSet);
    }
    validate_selected_indices(expected_indices, leaf_count)
}

fn complex_multiproof_frontier_positions(
    leaf_count: usize,
    expected_indices: &[usize],
) -> Result<Vec<FrontierPosition>, MerkleError> {
    validate_multiproof_indices(expected_indices, leaf_count)?;
    let tree_height = padded_leaf_count(leaf_count)?.ilog2() as usize;
    let mut selected_nodes = expected_indices.to_vec();
    let mut frontier = Vec::new();

    for level in 0..tree_height {
        let mut parents = Vec::with_capacity(selected_nodes.len().div_ceil(2));
        let mut cursor = 0_usize;
        while cursor < selected_nodes.len() {
            let node_index = selected_nodes[cursor];
            let selected_sibling = selected_nodes
                .get(cursor + 1)
                .is_some_and(|&next| node_index & 1 == 0 && next == node_index + 1);
            if !selected_sibling {
                frontier.push(FrontierPosition {
                    level,
                    index: node_index ^ 1,
                });
            }
            parents.push(node_index / 2);
            cursor += if selected_sibling { 2 } else { 1 };
        }
        selected_nodes = parents;
    }

    debug_assert_eq!(selected_nodes, [0]);
    Ok(frontier)
}

#[derive(Clone, Copy, Debug)]
struct StreamingNode {
    hash: MerkleRoot,
    node_index: usize,
    selected_range: Option<SelectedRange>,
}

#[derive(Clone, Copy, Debug)]
struct SelectedRange {
    start: usize,
    end: usize,
}

fn append_sibling(
    paths: &mut [Vec<MerkleRoot>],
    selected_range: Option<SelectedRange>,
    sibling: MerkleRoot,
) {
    if let Some(selected_range) = selected_range {
        for path in &mut paths[selected_range.start..selected_range.end] {
            path.push(sibling);
        }
    }
}

fn merge_selected_ranges(
    left: Option<SelectedRange>,
    right: Option<SelectedRange>,
) -> Option<SelectedRange> {
    match (left, right) {
        (Some(left), Some(right)) => {
            debug_assert_eq!(left.end, right.start);
            Some(SelectedRange {
                start: left.start,
                end: right.end,
            })
        }
        (Some(range), None) | (None, Some(range)) => Some(range),
        (None, None) => None,
    }
}

fn validate_selected_indices(
    selected_indices: &[usize],
    leaf_count: usize,
) -> Result<(), MerkleError> {
    for (position, &index) in selected_indices.iter().enumerate() {
        validate_index(index, leaf_count)?;
        if let Some(&previous) = position
            .checked_sub(1)
            .and_then(|previous| selected_indices.get(previous))
        {
            if index == previous {
                return Err(MerkleError::DuplicateOpeningIndex { index });
            }
            if index < previous {
                return Err(MerkleError::UnsortedOpeningIndices {
                    previous,
                    current: index,
                });
            }
        }
    }
    Ok(())
}

fn validate_index(index: usize, leaf_count: usize) -> Result<(), MerkleError> {
    if leaf_count == 0 {
        return Err(MerkleError::EmptyTree);
    }
    if index >= leaf_count {
        return Err(MerkleError::IndexOutOfBounds { index, leaf_count });
    }
    Ok(())
}

fn padded_leaf_count(leaf_count: usize) -> Result<usize, MerkleError> {
    if leaf_count == 0 {
        return Err(MerkleError::EmptyTree);
    }
    leaf_count
        .checked_next_power_of_two()
        .ok_or(MerkleError::LeafCountOverflow)
}

fn hash_complex_leaf(
    tree_label: &[u8],
    leaf_count: usize,
    index: usize,
    real_bits: u64,
    imaginary_bits: u64,
) -> MerkleRoot {
    let mut hasher = blake3::Hasher::new();
    update_field(&mut hasher, COMPLEX_LEAF_DOMAIN);
    update_field(&mut hasher, tree_label);
    update_usize(&mut hasher, leaf_count);
    update_usize(&mut hasher, index);
    hasher.update(&real_bits.to_le_bytes());
    hasher.update(&imaginary_bits.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn hash_complex_padding(tree_label: &[u8], leaf_count: usize, index: usize) -> MerkleRoot {
    let mut hasher = blake3::Hasher::new();
    update_field(&mut hasher, COMPLEX_PADDING_DOMAIN);
    update_field(&mut hasher, tree_label);
    update_usize(&mut hasher, leaf_count);
    update_usize(&mut hasher, index);
    *hasher.finalize().as_bytes()
}

fn hash_complex_node(
    tree_label: &[u8],
    leaf_count: usize,
    level: usize,
    index: usize,
    left: &MerkleRoot,
    right: &MerkleRoot,
) -> MerkleRoot {
    let mut hasher = blake3::Hasher::new();
    update_field(&mut hasher, COMPLEX_NODE_DOMAIN);
    update_field(&mut hasher, tree_label);
    update_usize(&mut hasher, leaf_count);
    update_usize(&mut hasher, level);
    update_usize(&mut hasher, index);
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

fn update_field(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn update_usize(hasher: &mut blake3::Hasher, value: usize) {
    // Supported Rust targets use at most 64-bit `usize`; this keeps roots
    // portable between 32- and 64-bit validators.
    hasher.update(&(value as u64).to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    const LABEL: &[u8] = b"solution-x";

    fn complex_values() -> Vec<[u64; 2]> {
        [[1.0_f64, -0.5], [-2.5, 3.25], [0.0, 4.0]]
            .into_iter()
            .map(|[real, imaginary]| [real.to_bits(), imaginary.to_bits()])
            .collect()
    }

    #[test]
    fn roots_and_multiproofs_round_trip_for_arbitrary_shapes() {
        for leaf_count in 1_usize..=65 {
            let values = (0..leaf_count)
                .map(|index| {
                    [
                        (index as f64 + 0.25).to_bits(),
                        (2.0 - index as f64 * 0.125).to_bits(),
                    ]
                })
                .collect::<Vec<_>>();
            let selected = (0..leaf_count)
                .filter(|index| *index == 0 || *index + 1 == leaf_count || *index % 7 == 0)
                .collect::<Vec<_>>();
            let (root, proof) =
                streaming_complex_root_and_multiproof(LABEL, &values, &selected).unwrap();
            assert_eq!(root, streaming_complex_root(LABEL, &values).unwrap());
            assert_eq!(
                proof.value_bits,
                selected
                    .iter()
                    .map(|&index| values[index])
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                proof.frontier.len(),
                complex_multiproof_frontier_len(leaf_count, &selected).unwrap()
            );
            let hash_count =
                verify_complex_multiproof(LABEL, leaf_count, &root, &selected, &proof).unwrap();
            assert!(hash_count >= selected.len());
        }
    }

    #[test]
    fn iterator_builders_match_slice_builders() {
        let values = (0..33)
            .map(|index| {
                [
                    (index as f64 + 0.75).to_bits(),
                    (index as f64 - 9.0).to_bits(),
                ]
            })
            .collect::<Vec<_>>();
        let selected = vec![0, 1, 7, 16, 31, 32];
        assert_eq!(
            streaming_complex_root_iter(LABEL, values.iter().copied()).unwrap(),
            streaming_complex_root(LABEL, &values).unwrap()
        );
        assert_eq!(
            streaming_complex_root_and_multiproof_iter(LABEL, values.iter().copied(), &selected)
                .unwrap(),
            streaming_complex_root_and_multiproof(LABEL, &values, &selected).unwrap()
        );
    }

    #[test]
    fn canonical_frontier_has_expected_boundary_sizes() {
        let values = (0..8)
            .map(|index| [(index as f64).to_bits(), (index as f64 + 0.5).to_bits()])
            .collect::<Vec<_>>();
        let root = streaming_complex_root(LABEL, &values).unwrap();

        let (_, one) = streaming_complex_root_and_multiproof(LABEL, &values, &[3]).unwrap();
        assert_eq!(one.frontier.len(), 3);
        assert_eq!(
            verify_complex_multiproof(LABEL, 8, &root, &[3], &one),
            Ok(4)
        );

        let all_indices = (0..8).collect::<Vec<_>>();
        let (_, all) = streaming_complex_root_and_multiproof(LABEL, &values, &all_indices).unwrap();
        assert!(all.frontier.is_empty());
        assert_eq!(
            verify_complex_multiproof(LABEL, 8, &root, &all_indices, &all),
            Ok(15)
        );

        let singleton_values = vec![[1.0_f64.to_bits(), 2.0_f64.to_bits()]];
        let (singleton_root, singleton) =
            streaming_complex_root_and_multiproof(LABEL, &singleton_values, &[0]).unwrap();
        assert!(singleton.frontier.is_empty());
        assert_eq!(
            verify_complex_multiproof(LABEL, 1, &singleton_root, &[0], &singleton),
            Ok(1)
        );
    }

    #[test]
    fn mutations_of_every_bound_input_are_rejected() {
        let values = (0..16)
            .map(|index| {
                [
                    (index as f64 + 0.125).to_bits(),
                    (index as f64 * -1.5).to_bits(),
                ]
            })
            .collect::<Vec<_>>();
        let selected = vec![1, 2, 7, 12];
        let (root, proof) =
            streaming_complex_root_and_multiproof(LABEL, &values, &selected).unwrap();

        let mut wrong_real = proof.clone();
        wrong_real.value_bits[0][0] ^= 1;
        assert_eq!(
            verify_complex_multiproof(LABEL, 16, &root, &selected, &wrong_real),
            Err(MerkleError::RootMismatch)
        );
        let mut wrong_imaginary = proof.clone();
        wrong_imaginary.value_bits[0][1] ^= 1;
        assert_eq!(
            verify_complex_multiproof(LABEL, 16, &root, &selected, &wrong_imaginary),
            Err(MerkleError::RootMismatch)
        );
        let mut wrong_frontier = proof.clone();
        wrong_frontier.frontier[0][3] ^= 0x80;
        assert_eq!(
            verify_complex_multiproof(LABEL, 16, &root, &selected, &wrong_frontier),
            Err(MerkleError::RootMismatch)
        );
        let mut wrong_root = root;
        wrong_root[0] ^= 1;
        assert_eq!(
            verify_complex_multiproof(LABEL, 16, &wrong_root, &selected, &proof),
            Err(MerkleError::RootMismatch)
        );
        assert_eq!(
            verify_complex_multiproof(b"other", 16, &root, &selected, &proof),
            Err(MerkleError::RootMismatch)
        );
        assert!(verify_complex_multiproof(LABEL, 15, &root, &selected, &proof).is_err());
    }

    #[test]
    fn counts_and_index_order_are_strict() {
        let values = complex_values();
        let selected = vec![0, 2];
        let (root, proof) =
            streaming_complex_root_and_multiproof(LABEL, &values, &selected).unwrap();

        let mut missing_value = proof.clone();
        missing_value.value_bits.pop();
        assert_eq!(
            verify_complex_multiproof(LABEL, 3, &root, &selected, &missing_value),
            Err(MerkleError::OpeningValueCount {
                expected: 2,
                actual: 1,
            })
        );
        let mut extra_frontier = proof.clone();
        extra_frontier.frontier.push([0; 32]);
        assert_eq!(
            verify_complex_multiproof(LABEL, 3, &root, &selected, &extra_frontier),
            Err(MerkleError::FrontierCount {
                expected: proof.frontier.len(),
                actual: proof.frontier.len() + 1,
            })
        );
        assert_eq!(
            verify_complex_multiproof(LABEL, 3, &root, &[], &proof),
            Err(MerkleError::EmptyOpeningSet)
        );
        assert_eq!(
            verify_complex_multiproof(LABEL, 3, &root, &[2, 0], &proof),
            Err(MerkleError::UnsortedOpeningIndices {
                previous: 2,
                current: 0,
            })
        );
        assert_eq!(
            verify_complex_multiproof(LABEL, 3, &root, &[0, 0], &proof),
            Err(MerkleError::DuplicateOpeningIndex { index: 0 })
        );
    }

    #[test]
    fn reordered_values_and_frontier_are_rejected() {
        let values = (0..32)
            .map(|index| {
                [
                    (index as f64 + 0.25).to_bits(),
                    (index as f64 + 10.0).to_bits(),
                ]
            })
            .collect::<Vec<_>>();
        let selected = vec![0, 5, 9, 18, 31];
        let (root, proof) =
            streaming_complex_root_and_multiproof(LABEL, &values, &selected).unwrap();

        let mut reordered_values = proof.clone();
        reordered_values.value_bits.swap(0, 1);
        assert_eq!(
            verify_complex_multiproof(LABEL, 32, &root, &selected, &reordered_values),
            Err(MerkleError::RootMismatch)
        );
        let mut reordered_frontier = proof.clone();
        reordered_frontier.frontier.swap(0, 1);
        assert_eq!(
            verify_complex_multiproof(LABEL, 32, &root, &selected, &reordered_frontier),
            Err(MerkleError::RootMismatch)
        );
    }

    #[test]
    fn empty_and_invalid_builds_are_rejected() {
        assert_eq!(
            streaming_complex_root(LABEL, &[]),
            Err(MerkleError::EmptyTree)
        );
        let values = complex_values();
        assert_eq!(
            streaming_complex_root_and_multiproof(LABEL, &values, &[]),
            Err(MerkleError::EmptyOpeningSet)
        );
        assert_eq!(
            streaming_complex_root_and_multiproof(LABEL, &values, &[3]),
            Err(MerkleError::IndexOutOfBounds {
                index: 3,
                leaf_count: 3,
            })
        );
    }
}
