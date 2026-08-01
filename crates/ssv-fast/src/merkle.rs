//! Streaming BLAKE3 Merkle commitments for canonical complex binary64 leaves.
//!
//! This is intentionally the complex multiproof subset used by the
//! coefficient-aligned unit-circle protocol. Scalar trees and one-leaf wire
//! openings from the research crate are omitted. A builder retains one hash
//! per tree height plus `O(q log N)` temporary authentication data; a verifier
//! retains only the canonical joint frontier for the caller-derived indices.
//!
//! The per-value V5 hash domains, logical-shape binding, padding, index order,
//! and frontier order are frozen from `fast-validation/src/merkle.rs` at
//! research revision `be8b67b74da54d162df2e6e0a9d813779959bb60`.
//! The separately domain-separated V6 layout commits 32 adjacent evaluations
//! per leaf and opens selected chunks in full.

use thiserror::Error;

const COMPLEX_LEAF_DOMAIN: &[u8] = b"sparse-solution/fast-validation/merkle/complex-leaf/v2";
const COMPLEX_PADDING_DOMAIN: &[u8] = b"sparse-solution/fast-validation/merkle/complex-padding/v2";
const COMPLEX_NODE_DOMAIN: &[u8] = b"sparse-solution/fast-validation/merkle/complex-node/v2";
const COMPLEX_CHUNK_LEAF_DOMAIN: &[u8] =
    b"sparse-solution/fast-validation/merkle/complex-chunk-leaf/v1";
const COMPLEX_CHUNK_PADDING_DOMAIN: &[u8] =
    b"sparse-solution/fast-validation/merkle/complex-chunk-padding/v1";
const COMPLEX_CHUNK_NODE_DOMAIN: &[u8] =
    b"sparse-solution/fast-validation/merkle/complex-chunk-node/v1";

/// Number of adjacent complex evaluations authenticated by one chunked leaf.
pub const COMPLEX_VALUES_PER_CHUNK: usize = 32;

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

/// Constructs a compact multiproof without recomputing the committed root.
///
/// This scans every value but hashes only the disjoint, unselected frontier
/// subtrees required by the proof. The caller must have committed the same
/// values in an earlier root pass; ordinary multiproof verification detects
/// any disagreement. Selected indices must be strictly increasing.
pub(crate) fn streaming_complex_multiproof_iter<I>(
    tree_label: &[u8],
    value_bits: I,
    selected_indices: &[usize],
) -> Result<ComplexMultiProof, MerkleError>
where
    I: ExactSizeIterator<Item = [u64; 2]>,
{
    let leaf_count = value_bits.len();
    let padded_leaf_count = padded_leaf_count(leaf_count)?;
    let expected_frontier = complex_multiproof_frontier_positions(leaf_count, selected_indices)?;
    let tree_height = padded_leaf_count.ilog2() as usize;
    let mut reduction: Vec<Option<SelectiveStreamingNode>> = vec![None; tree_height + 1];
    let mut discovered_frontier = Vec::with_capacity(expected_frontier.len());
    let mut selected_values = Vec::with_capacity(selected_indices.len());
    let mut selected_cursor = 0_usize;

    let padded_values = value_bits
        .map(Some)
        .chain((leaf_count..padded_leaf_count).map(|_| None));
    for (leaf_index, value_bits) in padded_values.enumerate() {
        let selected = selected_indices.get(selected_cursor) == Some(&leaf_index);
        let hash = if selected {
            selected_values
                .push(value_bits.expect("a selected logical leaf cannot be synthetic padding"));
            selected_cursor += 1;
            None
        } else {
            Some(if let Some([real_bits, imaginary_bits]) = value_bits {
                hash_complex_leaf(
                    tree_label,
                    leaf_count,
                    leaf_index,
                    real_bits,
                    imaginary_bits,
                )
            } else {
                hash_complex_padding(tree_label, leaf_count, leaf_index)
            })
        };
        let mut node = SelectiveStreamingNode {
            hash,
            node_index: leaf_index,
        };
        let mut height = 0_usize;

        while let Some(left) = reduction[height].take() {
            debug_assert_eq!(left.node_index + 1, node.node_index);
            let parent_hash = match (left.hash, node.hash) {
                (Some(left_hash), Some(right_hash)) => Some(hash_complex_node(
                    tree_label,
                    leaf_count,
                    height + 1,
                    node.node_index / 2,
                    &left_hash,
                    &right_hash,
                )),
                (None, Some(right_hash)) => {
                    discovered_frontier.push((
                        FrontierPosition {
                            level: height,
                            index: node.node_index,
                        },
                        right_hash,
                    ));
                    None
                }
                (Some(left_hash), None) => {
                    discovered_frontier.push((
                        FrontierPosition {
                            level: height,
                            index: left.node_index,
                        },
                        left_hash,
                    ));
                    None
                }
                (None, None) => None,
            };
            node = SelectiveStreamingNode {
                hash: parent_hash,
                node_index: node.node_index / 2,
            };
            height += 1;
        }
        reduction[height] = Some(node);
    }

    debug_assert_eq!(selected_cursor, selected_indices.len());
    debug_assert_eq!(selected_values.len(), selected_indices.len());
    debug_assert_eq!(
        reduction[tree_height]
            .take()
            .expect("power-of-two streaming reduction must produce one root")
            .hash,
        None
    );
    debug_assert!(reduction.into_iter().all(|node| node.is_none()));
    discovered_frontier.sort_unstable_by_key(|(position, _)| (position.level, position.index));
    debug_assert_eq!(
        discovered_frontier
            .iter()
            .map(|(position, _)| *position)
            .collect::<Vec<_>>(),
        expected_frontier
    );
    Ok(ComplexMultiProof {
        value_bits: selected_values,
        frontier: discovered_frontier
            .into_iter()
            .map(|(_, hash)| hash)
            .collect(),
    })
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

/// Computes a root with 32 adjacent complex evaluations per Merkle leaf.
///
/// The iterator's exact length and every value index are bound into the tree.
/// A final short chunk is canonical; synthetic leaves pad only the chunk count
/// to a power of two. Production unit-circle domains are powers of two, so
/// they have either one short leaf or no synthetic padding.
pub(crate) fn streaming_chunked_complex_root_iter<I>(
    tree_label: &[u8],
    mut value_bits: I,
) -> Result<MerkleRoot, MerkleError>
where
    I: ExactSizeIterator<Item = [u64; 2]>,
{
    let value_count = value_bits.len();
    let chunk_count = complex_chunk_count(value_count)?;
    let padded_chunk_count = padded_leaf_count(chunk_count)?;
    let tree_height = padded_chunk_count.ilog2() as usize;
    let mut reduction: Vec<Option<StreamingNode>> = vec![None; tree_height + 1];
    let mut chunk = [[0_u64; 2]; COMPLEX_VALUES_PER_CHUNK];

    for chunk_index in 0..padded_chunk_count {
        let hash = if chunk_index < chunk_count {
            let chunk_len = complex_chunk_len(value_count, chunk_index)?;
            for slot in &mut chunk[..chunk_len] {
                *slot = value_bits
                    .next()
                    .expect("exact-size complex iterator ended inside a chunk");
            }
            hash_complex_chunk_leaf(tree_label, value_count, chunk_index, &chunk[..chunk_len])
        } else {
            hash_complex_chunk_padding(tree_label, value_count, chunk_index)
        };
        let mut node = StreamingNode {
            hash,
            node_index: chunk_index,
            selected_range: None,
        };
        let mut height = 0_usize;
        while let Some(left) = reduction[height].take() {
            let parent_index = node.node_index / 2;
            node = StreamingNode {
                hash: hash_complex_chunk_node(
                    tree_label,
                    value_count,
                    height + 1,
                    parent_index,
                    &left.hash,
                    &node.hash,
                ),
                node_index: parent_index,
                selected_range: None,
            };
            height += 1;
        }
        reduction[height] = Some(node);
    }
    debug_assert!(value_bits.next().is_none());
    let root = reduction[tree_height]
        .take()
        .expect("power-of-two chunk reduction must produce one root")
        .hash;
    debug_assert!(reduction.into_iter().all(|node| node.is_none()));
    Ok(root)
}

/// Constructs a chunked compact multiproof without recomputing its root.
///
/// Every selected chunk is emitted in full and in increasing chunk order.
/// This deliberately exchanges proof bytes for fewer short-message hashes.
pub(crate) fn streaming_chunked_complex_multiproof_iter<I>(
    tree_label: &[u8],
    mut value_bits: I,
    selected_indices: &[usize],
) -> Result<ComplexMultiProof, MerkleError>
where
    I: ExactSizeIterator<Item = [u64; 2]>,
{
    let value_count = value_bits.len();
    let selected_chunks = selected_complex_chunks(value_count, selected_indices)?;
    let chunk_count = complex_chunk_count(value_count)?;
    let padded_chunk_count = padded_leaf_count(chunk_count)?;
    let expected_frontier = complex_multiproof_frontier_positions(chunk_count, &selected_chunks)?;
    let tree_height = padded_chunk_count.ilog2() as usize;
    let mut reduction: Vec<Option<SelectiveStreamingNode>> = vec![None; tree_height + 1];
    let mut discovered_frontier = Vec::with_capacity(expected_frontier.len());
    let expected_values = chunked_complex_opening_value_len(value_count, selected_indices)?;
    let mut selected_values = Vec::with_capacity(expected_values);
    let mut selected_cursor = 0_usize;
    let mut chunk = [[0_u64; 2]; COMPLEX_VALUES_PER_CHUNK];

    for chunk_index in 0..padded_chunk_count {
        let selected = selected_chunks.get(selected_cursor) == Some(&chunk_index);
        let hash = if chunk_index < chunk_count {
            let chunk_len = complex_chunk_len(value_count, chunk_index)?;
            for slot in &mut chunk[..chunk_len] {
                *slot = value_bits
                    .next()
                    .expect("exact-size complex iterator ended inside a chunk");
            }
            if selected {
                selected_values.extend_from_slice(&chunk[..chunk_len]);
                selected_cursor += 1;
                None
            } else {
                Some(hash_complex_chunk_leaf(
                    tree_label,
                    value_count,
                    chunk_index,
                    &chunk[..chunk_len],
                ))
            }
        } else {
            Some(hash_complex_chunk_padding(
                tree_label,
                value_count,
                chunk_index,
            ))
        };
        let mut node = SelectiveStreamingNode {
            hash,
            node_index: chunk_index,
        };
        let mut height = 0_usize;
        while let Some(left) = reduction[height].take() {
            let parent_hash = match (left.hash, node.hash) {
                (Some(left_hash), Some(right_hash)) => Some(hash_complex_chunk_node(
                    tree_label,
                    value_count,
                    height + 1,
                    node.node_index / 2,
                    &left_hash,
                    &right_hash,
                )),
                (None, Some(right_hash)) => {
                    discovered_frontier.push((
                        FrontierPosition {
                            level: height,
                            index: node.node_index,
                        },
                        right_hash,
                    ));
                    None
                }
                (Some(left_hash), None) => {
                    discovered_frontier.push((
                        FrontierPosition {
                            level: height,
                            index: left.node_index,
                        },
                        left_hash,
                    ));
                    None
                }
                (None, None) => None,
            };
            node = SelectiveStreamingNode {
                hash: parent_hash,
                node_index: node.node_index / 2,
            };
            height += 1;
        }
        reduction[height] = Some(node);
    }
    debug_assert!(value_bits.next().is_none());
    debug_assert_eq!(selected_cursor, selected_chunks.len());
    debug_assert_eq!(selected_values.len(), expected_values);
    debug_assert_eq!(
        reduction[tree_height]
            .take()
            .expect("power-of-two chunk reduction must produce one root")
            .hash,
        None
    );
    discovered_frontier.sort_unstable_by_key(|(position, _)| (position.level, position.index));
    debug_assert_eq!(
        discovered_frontier
            .iter()
            .map(|(position, _)| *position)
            .collect::<Vec<_>>(),
        expected_frontier
    );
    Ok(ComplexMultiProof {
        value_bits: selected_values,
        frontier: discovered_frontier
            .into_iter()
            .map(|(_, hash)| hash)
            .collect(),
    })
}

/// Returns the chunked proof's exact number of revealed complex values.
pub(crate) fn chunked_complex_opening_value_len(
    value_count: usize,
    expected_indices: &[usize],
) -> Result<usize, MerkleError> {
    selected_complex_chunks(value_count, expected_indices)?
        .into_iter()
        .try_fold(0_usize, |total, chunk_index| {
            total
                .checked_add(complex_chunk_len(value_count, chunk_index)?)
                .ok_or(MerkleError::LeafCountOverflow)
        })
}

/// Returns the chunked proof's exact number of frontier hashes.
#[cfg(test)]
pub(crate) fn chunked_complex_multiproof_frontier_len(
    value_count: usize,
    expected_indices: &[usize],
) -> Result<usize, MerkleError> {
    let chunks = selected_complex_chunks(value_count, expected_indices)?;
    Ok(complex_multiproof_frontier_positions(complex_chunk_count(value_count)?, &chunks)?.len())
}

/// Verifies a compact proof whose leaves contain 32 adjacent values.
pub(crate) fn verify_chunked_complex_multiproof(
    tree_label: &[u8],
    value_count: usize,
    root: &MerkleRoot,
    expected_indices: &[usize],
    proof: &ComplexMultiProof,
) -> Result<usize, MerkleError> {
    let selected_chunks = selected_complex_chunks(value_count, expected_indices)?;
    let expected_value_count = chunked_complex_opening_value_len(value_count, expected_indices)?;
    if proof.value_bits.len() != expected_value_count {
        return Err(MerkleError::OpeningValueCount {
            expected: expected_value_count,
            actual: proof.value_bits.len(),
        });
    }
    let chunk_count = complex_chunk_count(value_count)?;
    let frontier_positions = complex_multiproof_frontier_positions(chunk_count, &selected_chunks)?;
    if proof.frontier.len() != frontier_positions.len() {
        return Err(MerkleError::FrontierCount {
            expected: frontier_positions.len(),
            actual: proof.frontier.len(),
        });
    }

    let mut value_cursor = 0_usize;
    let mut nodes = Vec::with_capacity(selected_chunks.len());
    for &chunk_index in &selected_chunks {
        let chunk_len = complex_chunk_len(value_count, chunk_index)?;
        let end = value_cursor
            .checked_add(chunk_len)
            .ok_or(MerkleError::LeafCountOverflow)?;
        nodes.push((
            chunk_index,
            hash_complex_chunk_leaf(
                tree_label,
                value_count,
                chunk_index,
                &proof.value_bits[value_cursor..end],
            ),
        ));
        value_cursor = end;
    }
    debug_assert_eq!(value_cursor, proof.value_bits.len());

    let tree_height = padded_leaf_count(chunk_count)?.ilog2() as usize;
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
                hash_complex_chunk_node(
                    tree_label,
                    value_count,
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
    if nodes.len() != 1 || &nodes[0].1 != root {
        return Err(MerkleError::RootMismatch);
    }
    Ok(hash_count)
}

/// Reads one authenticated value from a previously verified chunked proof.
pub(crate) fn chunked_complex_opened_value_bits(
    value_count: usize,
    expected_indices: &[usize],
    proof: &ComplexMultiProof,
    index: usize,
) -> Result<[u64; 2], MerkleError> {
    validate_index(index, value_count)?;
    let selected_chunks = selected_complex_chunks(value_count, expected_indices)?;
    let chunk_index = index / COMPLEX_VALUES_PER_CHUNK;
    let chunk_position = selected_chunks.binary_search(&chunk_index).map_err(|_| {
        MerkleError::OpeningIndexMismatch {
            expected: index,
            actual: index,
        }
    })?;
    let value_position = chunk_position
        .checked_mul(COMPLEX_VALUES_PER_CHUNK)
        .and_then(|position| position.checked_add(index % COMPLEX_VALUES_PER_CHUNK))
        .ok_or(MerkleError::LeafCountOverflow)?;
    proof
        .value_bits
        .get(value_position)
        .copied()
        .ok_or(MerkleError::OpeningValueCount {
            expected: chunked_complex_opening_value_len(value_count, expected_indices)?,
            actual: proof.value_bits.len(),
        })
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
struct SelectiveStreamingNode {
    hash: Option<MerkleRoot>,
    node_index: usize,
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

fn complex_chunk_count(value_count: usize) -> Result<usize, MerkleError> {
    if value_count == 0 {
        return Err(MerkleError::EmptyTree);
    }
    Ok(value_count.div_ceil(COMPLEX_VALUES_PER_CHUNK))
}

fn complex_chunk_len(value_count: usize, chunk_index: usize) -> Result<usize, MerkleError> {
    let start = chunk_index
        .checked_mul(COMPLEX_VALUES_PER_CHUNK)
        .ok_or(MerkleError::LeafCountOverflow)?;
    if start >= value_count {
        return Err(MerkleError::IndexOutOfBounds {
            index: start,
            leaf_count: value_count,
        });
    }
    Ok((value_count - start).min(COMPLEX_VALUES_PER_CHUNK))
}

fn selected_complex_chunks(
    value_count: usize,
    expected_indices: &[usize],
) -> Result<Vec<usize>, MerkleError> {
    validate_multiproof_indices(expected_indices, value_count)?;
    let mut chunks = Vec::with_capacity(expected_indices.len());
    for &index in expected_indices {
        let chunk = index / COMPLEX_VALUES_PER_CHUNK;
        if chunks.last() != Some(&chunk) {
            chunks.push(chunk);
        }
    }
    Ok(chunks)
}

fn hash_complex_chunk_leaf(
    tree_label: &[u8],
    value_count: usize,
    chunk_index: usize,
    value_bits: &[[u64; 2]],
) -> MerkleRoot {
    debug_assert!(!value_bits.is_empty());
    debug_assert!(value_bits.len() <= COMPLEX_VALUES_PER_CHUNK);
    let mut packed = [0_u8; 16 * COMPLEX_VALUES_PER_CHUNK];
    for (output, [real_bits, imaginary_bits]) in
        packed.chunks_exact_mut(16).zip(value_bits.iter().copied())
    {
        output[..8].copy_from_slice(&real_bits.to_le_bytes());
        output[8..].copy_from_slice(&imaginary_bits.to_le_bytes());
    }
    let mut hasher = blake3::Hasher::new();
    update_field(&mut hasher, COMPLEX_CHUNK_LEAF_DOMAIN);
    update_field(&mut hasher, tree_label);
    update_usize(&mut hasher, value_count);
    update_usize(&mut hasher, chunk_index);
    update_usize(&mut hasher, value_bits.len());
    hasher.update(&packed[..16 * value_bits.len()]);
    *hasher.finalize().as_bytes()
}

fn hash_complex_chunk_padding(
    tree_label: &[u8],
    value_count: usize,
    chunk_index: usize,
) -> MerkleRoot {
    let mut hasher = blake3::Hasher::new();
    update_field(&mut hasher, COMPLEX_CHUNK_PADDING_DOMAIN);
    update_field(&mut hasher, tree_label);
    update_usize(&mut hasher, value_count);
    update_usize(&mut hasher, chunk_index);
    *hasher.finalize().as_bytes()
}

fn hash_complex_chunk_node(
    tree_label: &[u8],
    value_count: usize,
    level: usize,
    index: usize,
    left: &MerkleRoot,
    right: &MerkleRoot,
) -> MerkleRoot {
    let mut hasher = blake3::Hasher::new();
    update_field(&mut hasher, COMPLEX_CHUNK_NODE_DOMAIN);
    update_field(&mut hasher, tree_label);
    update_usize(&mut hasher, value_count);
    update_usize(&mut hasher, level);
    update_usize(&mut hasher, index);
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
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
                streaming_complex_multiproof_iter(LABEL, values.iter().copied(), &selected)
                    .unwrap(),
                proof
            );
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
        assert_eq!(
            streaming_complex_multiproof_iter(LABEL, values.iter().copied(), &selected).unwrap(),
            streaming_complex_root_and_multiproof(LABEL, &values, &selected)
                .unwrap()
                .1
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
            streaming_complex_multiproof_iter(LABEL, values.iter().copied(), &[]),
            Err(MerkleError::EmptyOpeningSet)
        );
        assert_eq!(
            streaming_complex_root_and_multiproof(LABEL, &values, &[3]),
            Err(MerkleError::IndexOutOfBounds {
                index: 3,
                leaf_count: 3,
            })
        );
        assert_eq!(
            streaming_complex_multiproof_iter(LABEL, values.iter().copied(), &[3]),
            Err(MerkleError::IndexOutOfBounds {
                index: 3,
                leaf_count: 3,
            })
        );
    }

    #[test]
    fn chunked_roots_and_multiproofs_round_trip_across_chunk_boundaries() {
        for value_count in 1_usize..=97 {
            let values = (0..value_count)
                .map(|index| {
                    [
                        (index as f64 + 0.375).to_bits(),
                        (17.0 - index as f64 * 0.25).to_bits(),
                    ]
                })
                .collect::<Vec<_>>();
            let selected = (0..value_count)
                .filter(|index| {
                    *index == 0
                        || *index + 1 == value_count
                        || *index == 31
                        || *index == 32
                        || *index % 19 == 0
                })
                .collect::<Vec<_>>();
            let root = streaming_chunked_complex_root_iter(LABEL, values.iter().copied()).unwrap();
            let proof =
                streaming_chunked_complex_multiproof_iter(LABEL, values.iter().copied(), &selected)
                    .unwrap();
            assert_eq!(
                proof.value_bits.len(),
                chunked_complex_opening_value_len(value_count, &selected).unwrap()
            );
            assert_eq!(
                proof.frontier.len(),
                chunked_complex_multiproof_frontier_len(value_count, &selected).unwrap()
            );
            verify_chunked_complex_multiproof(LABEL, value_count, &root, &selected, &proof)
                .unwrap();
            for &index in &selected {
                assert_eq!(
                    chunked_complex_opened_value_bits(value_count, &selected, &proof, index)
                        .unwrap(),
                    values[index]
                );
            }
        }
    }

    #[test]
    fn chunked_openings_bind_unqueried_values_in_revealed_chunks() {
        let values = (0..64)
            .map(|index| [(index as f64).to_bits(), (index as f64 + 0.5).to_bits()])
            .collect::<Vec<_>>();
        let selected = vec![3, 40];
        let root = streaming_chunked_complex_root_iter(LABEL, values.iter().copied()).unwrap();
        let proof =
            streaming_chunked_complex_multiproof_iter(LABEL, values.iter().copied(), &selected)
                .unwrap();
        assert_eq!(proof.value_bits.len(), 64);
        assert!(proof.frontier.is_empty());

        let mut changed = proof.clone();
        changed.value_bits[17][0] ^= 1;
        assert_eq!(
            verify_chunked_complex_multiproof(LABEL, 64, &root, &selected, &changed),
            Err(MerkleError::RootMismatch)
        );
    }

    #[test]
    fn chunked_and_single_value_tree_domains_are_distinct() {
        let values = complex_values();
        assert_ne!(
            streaming_chunked_complex_root_iter(LABEL, values.iter().copied()).unwrap(),
            streaming_complex_root(LABEL, &values).unwrap()
        );
    }
}
