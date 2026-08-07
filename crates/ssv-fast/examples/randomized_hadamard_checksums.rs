//! Cost and attack surrogate for systematic randomized-Hadamard checksums.
//!
//! This example is deliberately not a proof protocol. It measures a candidate
//! row code `Enc_D(u) = [u || H D u]`, a complete column Merkle commitment,
//! and one authenticated row-combination opening. It separately measures the
//! spreading seen when an alteration is fixed before `D` and an explicit
//! alteration constructed after the public signs are known.

#![forbid(unsafe_code)]

use std::error::Error;
use std::hint::black_box;
use std::io;
use std::time::{Duration, Instant};

use clap::Parser;

const LEAF_DOMAIN: &[u8] = b"ssv/research/randomized-hadamard/column-leaf/v1";
const PADDING_DOMAIN: &[u8] = b"ssv/research/randomized-hadamard/column-padding/v1";
const NODE_DOMAIN: &[u8] = b"ssv/research/randomized-hadamard/column-node/v1";
const QUERY_DOMAIN: &[u8] = b"ssv/research/randomized-hadamard/query-seed/v1";
const VALUES_PER_HASH_BLOCK: usize = 64;
const TRANSPOSE_TILE: usize = 32;
const TAIL_SCALE: f64 = 0.5;

#[derive(Debug, Parser)]
#[command(about = "Benchmark speculative randomized-Hadamard metric checksums")]
struct Args {
    /// Logical number of source binary64 values.
    #[arg(long, default_value_t = 1 << 20)]
    dimension: usize,

    /// Rows in the source matrix. The padded column count is a power of two.
    #[arg(long, default_value_t = 256)]
    rows: usize,

    /// Full encoded columns opened after the row-combination claim is fixed.
    #[arg(long, default_value_t = 16)]
    queries: usize,

    /// Independent public-sign draws used by the spreading study.
    #[arg(long, default_value_t = 256)]
    spreading_trials: usize,

    #[arg(long, default_value_t = 2)]
    warmups: usize,

    #[arg(long, default_value_t = 25)]
    repetitions: usize,

    #[arg(long, default_value_t = 0x5eed_c0de_d15c_a11e)]
    seed: u64,
}

#[derive(Debug)]
struct RandomizedHadamardCode {
    width: usize,
    signs: Vec<f64>,
    normalization: f64,
}

impl RandomizedHadamardCode {
    fn new(width: usize, seed: u64) -> Result<Self, io::Error> {
        if width == 0 || !width.is_power_of_two() {
            return Err(invalid("Hadamard width must be a positive power of two"));
        }
        let mut signs = Vec::new();
        signs
            .try_reserve_exact(width)
            .map_err(|_| invalid("could not allocate Hadamard signs"))?;
        let mut state = seed;
        for _ in 0..width {
            signs.push(if splitmix64(&mut state) & 1 == 0 {
                1.0
            } else {
                -1.0
            });
        }
        Ok(Self {
            width,
            signs,
            normalization: 1.0 / (width as f64).sqrt(),
        })
    }

    fn encoded_columns(&self) -> Result<usize, io::Error> {
        self.width
            .checked_mul(2)
            .ok_or_else(|| invalid("encoded column count overflow"))
    }

    fn transform_in_place(&self, values: &mut [f64]) -> Result<(), io::Error> {
        if values.len() != self.width {
            return Err(invalid("Hadamard input does not match the code width"));
        }
        for (value, &sign) in values.iter_mut().zip(&self.signs) {
            *value *= sign;
        }
        fwht_in_place(values);
        for value in values {
            *value *= self.normalization;
        }
        Ok(())
    }

    fn encode_vector(&self, source: &[f64]) -> Result<Vec<f64>, io::Error> {
        if source.len() != self.width {
            return Err(invalid("source vector does not match the code width"));
        }
        let mut parity = source.to_vec();
        self.transform_in_place(&mut parity)?;
        Ok(parity)
    }

    /// Encodes row-major source storage directly into committed column-major
    /// parity storage.
    fn encode_rows_to_columns(&self, source: &[f64], rows: usize) -> Result<Vec<f64>, io::Error> {
        let expected = rows
            .checked_mul(self.width)
            .ok_or_else(|| invalid("source matrix shape overflow"))?;
        if source.len() != expected {
            return Err(invalid("source storage does not match the matrix shape"));
        }
        let mut parity = Vec::new();
        parity
            .try_reserve_exact(expected)
            .map_err(|_| invalid("could not allocate parity storage"))?;
        parity.resize(expected, 0.0);
        let mut transformed_row = vec![0.0; self.width];
        for (row_index, source_row) in source.chunks_exact(self.width).enumerate() {
            transformed_row.copy_from_slice(source_row);
            self.transform_in_place(&mut transformed_row)?;
            for (column_index, &value) in transformed_row.iter().enumerate() {
                parity[column_index * rows + row_index] = value;
            }
        }
        Ok(parity)
    }
}

#[derive(Debug)]
struct ColumnTree {
    hashes: Vec<[u8; 32]>,
    padded_columns: usize,
    column_count: usize,
}

impl ColumnTree {
    fn root(&self) -> [u8; 32] {
        self.hashes[1]
    }

    fn bytes(&self) -> usize {
        self.hashes.len() * size_of::<[u8; 32]>()
    }

    fn naive_opening(
        &self,
        source: &[f64],
        parity: &[f64],
        rows: usize,
        source_columns: usize,
        queries: usize,
        seed: u64,
    ) -> Result<NaiveOpening, io::Error> {
        if queries == 0 || queries > self.column_count {
            return Err(invalid("opening query count is out of range"));
        }

        let mut indices: Vec<usize> = (0..self.column_count).collect();
        let mut state = seed;
        for upper in (1..indices.len()).rev() {
            let selected = (splitmix64(&mut state) as usize) % (upper + 1);
            indices.swap(upper, selected);
        }
        indices.truncate(queries);
        indices.sort_unstable();

        let value_count = queries
            .checked_mul(rows)
            .ok_or_else(|| invalid("opened value count overflow"))?;
        let tree_height = self.padded_columns.ilog2() as usize;
        let authentication_count = queries
            .checked_mul(tree_height)
            .ok_or_else(|| invalid("authentication hash count overflow"))?;
        let mut values = Vec::new();
        values
            .try_reserve_exact(value_count)
            .map_err(|_| invalid("could not allocate opened values"))?;
        let mut authentication = Vec::new();
        authentication
            .try_reserve_exact(authentication_count)
            .map_err(|_| invalid("could not allocate authentication paths"))?;

        for &column_index in &indices {
            values.extend_from_slice(column(source, parity, rows, source_columns, column_index));
            let mut node_index = self.padded_columns + column_index;
            while node_index > 1 {
                authentication.push(self.hashes[node_index ^ 1]);
                node_index /= 2;
            }
        }

        Ok(NaiveOpening {
            indices,
            values,
            authentication,
        })
    }
}

#[derive(Clone, Debug)]
struct NaiveOpening {
    indices: Vec<usize>,
    values: Vec<f64>,
    authentication: Vec<[u8; 32]>,
}

impl NaiveOpening {
    fn payload_bytes(&self, source_columns: usize) -> Result<usize, io::Error> {
        let combination_bytes = source_columns
            .checked_mul(size_of::<f64>())
            .ok_or_else(|| invalid("combination byte count overflow"))?;
        let index_bytes = self
            .indices
            .len()
            .checked_mul(size_of::<u64>())
            .ok_or_else(|| invalid("opening index byte count overflow"))?;
        let value_bytes = self
            .values
            .len()
            .checked_mul(size_of::<f64>())
            .ok_or_else(|| invalid("opened value byte count overflow"))?;
        let authentication_bytes = self
            .authentication
            .len()
            .checked_mul(size_of::<[u8; 32]>())
            .ok_or_else(|| invalid("authentication byte count overflow"))?;
        32_usize
            .checked_add(combination_bytes)
            .and_then(|value| value.checked_add(index_bytes))
            .and_then(|value| value.checked_add(value_bytes))
            .and_then(|value| value.checked_add(authentication_bytes))
            .ok_or_else(|| invalid("opening payload byte count overflow"))
    }

    fn verify(
        &self,
        tree: &ColumnTree,
        rows: usize,
        source_columns: usize,
        row_weights: &[f64],
        combined_source: &[f64],
        combined_parity: &[f64],
    ) -> Result<DefectMetrics, io::Error> {
        let tree_height = tree.padded_columns.ilog2() as usize;
        let expected_values = self
            .indices
            .len()
            .checked_mul(rows)
            .ok_or_else(|| invalid("opened value shape overflow"))?;
        let expected_authentication = self
            .indices
            .len()
            .checked_mul(tree_height)
            .ok_or_else(|| invalid("opening authentication shape overflow"))?;
        if self.values.len() != expected_values
            || self.authentication.len() != expected_authentication
            || combined_source.len() != source_columns
            || combined_parity.len() != source_columns
            || row_weights.len() != rows
        {
            return Err(invalid("opening verification shape is invalid"));
        }

        let mut absolute_defects = Vec::new();
        absolute_defects
            .try_reserve_exact(self.indices.len())
            .map_err(|_| invalid("could not allocate queried defects"))?;
        let mut relative_defects = Vec::new();
        relative_defects
            .try_reserve_exact(self.indices.len())
            .map_err(|_| invalid("could not allocate queried relative defects"))?;

        for (query, &column_index) in self.indices.iter().enumerate() {
            let values = &self.values[query * rows..(query + 1) * rows];
            let path = &self.authentication[query * tree_height..(query + 1) * tree_height];
            let mut hash = hash_column(column_index, values);
            let mut level_index = column_index;
            for (level, sibling) in path.iter().enumerate() {
                let parent_index = level_index / 2;
                hash = if level_index.is_multiple_of(2) {
                    hash_node(level + 1, parent_index, &hash, sibling)
                } else {
                    hash_node(level + 1, parent_index, sibling, &hash)
                };
                level_index = parent_index;
            }
            if hash != tree.root() {
                return Err(invalid(
                    "opening authentication path does not match the root",
                ));
            }

            let actual = dot(values, row_weights)?;
            let expected = if column_index < source_columns {
                combined_source[column_index]
            } else {
                combined_parity[column_index - source_columns]
            };
            let absolute = (actual - expected).abs();
            let scale = actual.abs().max(expected.abs()).max(f64::MIN_POSITIVE);
            absolute_defects.push(absolute);
            relative_defects.push(absolute / scale);
        }

        summarize_defects(&absolute_defects, &relative_defects)
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct DefectMetrics {
    maximum_absolute: f64,
    rms_absolute: f64,
    maximum_relative: f64,
    rms_relative: f64,
}

#[derive(Debug, Default)]
struct TimingSamples {
    transform_encoding: Vec<Duration>,
    transpose: Vec<Duration>,
    commitment: Vec<Duration>,
    combination: Vec<Duration>,
    combination_encoding: Vec<Duration>,
    opening_extraction: Vec<Duration>,
    opening_verification: Vec<Duration>,
    defect_scan: Vec<Duration>,
    total: Vec<Duration>,
}

#[derive(Clone, Copy, Debug)]
struct AlterationMetrics {
    source_tail: usize,
    parity_tail: usize,
    tail_fraction: f64,
    query_miss_probability: f64,
    encoded_energy_ratio: f64,
    effective_support: f64,
}

#[derive(Debug, Default)]
struct SpreadingSeries {
    tail_fractions: Vec<f64>,
    miss_probabilities: Vec<f64>,
    energy_ratios: Vec<f64>,
    effective_supports: Vec<f64>,
}

impl SpreadingSeries {
    fn push(&mut self, metrics: AlterationMetrics) {
        self.tail_fractions.push(metrics.tail_fraction);
        self.miss_probabilities.push(metrics.query_miss_probability);
        self.energy_ratios.push(metrics.encoded_energy_ratio);
        self.effective_supports.push(metrics.effective_support);
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    validate_args(&args)?;

    let minimum_columns = args.dimension.div_ceil(args.rows);
    let source_columns = minimum_columns
        .checked_next_power_of_two()
        .ok_or_else(|| invalid("source column padding overflow"))?;
    let padded_dimension = args
        .rows
        .checked_mul(source_columns)
        .ok_or_else(|| invalid("padded source dimension overflow"))?;
    let code = RandomizedHadamardCode::new(source_columns, args.seed ^ 0x4841_4441_4d41_5244)?;
    let encoded_columns = code.encoded_columns()?;
    if args.queries > encoded_columns {
        return Err(invalid("queries cannot exceed encoded columns").into());
    }

    let source_row_major = generate_source(args.dimension, padded_dimension, args.seed)?;
    let row_weights = signed_dyadic_weights(args.rows, args.seed ^ 0x524f_575f_5745_4947)?;
    let column_weights = signed_dyadic_weights(source_columns, args.seed ^ 0x434f_4c5f_5745_4947)?;

    let mut samples = TimingSamples::default();
    let mut final_root = [0_u8; 32];
    let mut final_tree_bytes = 0_usize;
    let mut final_opening_bytes = 0_usize;
    let mut final_defects = DefectMetrics::default();
    let mut final_query_defects = DefectMetrics::default();
    let mut final_claim = 0.0;

    for repetition in 0..args.warmups + args.repetitions {
        let total_start = Instant::now();

        let start = Instant::now();
        let parity = code.encode_rows_to_columns(&source_row_major, args.rows)?;
        let transform_encoding = start.elapsed();

        let start = Instant::now();
        let source = transpose_row_to_column(&source_row_major, args.rows, source_columns)?;
        let transpose = start.elapsed();

        let start = Instant::now();
        let tree = build_column_tree(&source, &parity, args.rows, source_columns, encoded_columns)?;
        let commitment = start.elapsed();

        let start = Instant::now();
        let combined = combine_columns(
            &source,
            &parity,
            args.rows,
            source_columns,
            encoded_columns,
            &row_weights,
        )?;
        let combination = start.elapsed();

        let start = Instant::now();
        let combined_parity = code.encode_vector(&combined[..source_columns])?;
        let combination_encoding = start.elapsed();

        let start = Instant::now();
        let query_seed = derive_query_seed(&tree.root(), &combined[..source_columns]);
        let opening = tree.naive_opening(
            &source,
            &parity,
            args.rows,
            source_columns,
            args.queries,
            query_seed,
        )?;
        let opening_extraction = start.elapsed();

        let start = Instant::now();
        let defects = compare_vectors(&combined[source_columns..], &combined_parity)?;
        let claim = dot(&combined[..source_columns], &column_weights)?;
        let defect_scan = start.elapsed();
        let total = total_start.elapsed();

        let start = Instant::now();
        let query_defects = opening.verify(
            &tree,
            args.rows,
            source_columns,
            &row_weights,
            &combined[..source_columns],
            &combined_parity,
        )?;
        let opening_verification = start.elapsed();

        black_box(tree.root());
        black_box(defects.maximum_absolute);
        black_box(claim);
        black_box(opening.values.last());
        black_box(query_defects.maximum_absolute);
        final_root = tree.root();
        final_tree_bytes = tree.bytes();
        final_opening_bytes = opening.payload_bytes(source_columns)?;
        final_defects = defects;
        final_query_defects = query_defects;
        final_claim = claim;

        if repetition >= args.warmups {
            samples.transform_encoding.push(transform_encoding);
            samples.transpose.push(transpose);
            samples.commitment.push(commitment);
            samples.combination.push(combination);
            samples.combination_encoding.push(combination_encoding);
            samples.opening_extraction.push(opening_extraction);
            samples.opening_verification.push(opening_verification);
            samples.defect_scan.push(defect_scan);
            samples.total.push(total);
        }
    }

    let source_bytes = padded_dimension * size_of::<f64>();
    let parity_bytes = source_bytes;
    let transform_additions = padded_dimension
        .checked_mul(source_columns.ilog2() as usize)
        .ok_or_else(|| invalid("transform addition count overflow"))?;

    println!("status=cost-and-attack-surrogate-without-soundness-claim");
    println!("logical_dimension={}", args.dimension);
    println!("padded_dimension={padded_dimension}");
    println!("rows={}", args.rows);
    println!("source_columns={source_columns}");
    println!("parity_columns={source_columns}");
    println!("encoded_columns={encoded_columns}");
    println!("queries={}", args.queries);
    println!("spreading_trials={}", args.spreading_trials);
    println!("tail_scale={TAIL_SCALE:.3}");
    println!("source_bytes={source_bytes}");
    println!("parity_bytes={parity_bytes}");
    println!("transform_additions={transform_additions}");
    println!("retained_tree_bytes={final_tree_bytes}");
    println!("naive_opening_bytes={final_opening_bytes}");
    println!("root={}", blake3::Hash::from_bytes(final_root).to_hex());
    println!("opening_claim={final_claim:.17e}");
    println!(
        "linearity_maximum_absolute_defect={:.17e}",
        final_defects.maximum_absolute
    );
    println!(
        "linearity_rms_absolute_defect={:.17e}",
        final_defects.rms_absolute
    );
    println!(
        "linearity_maximum_relative_defect={:.17e}",
        final_defects.maximum_relative
    );
    println!(
        "linearity_rms_relative_defect={:.17e}",
        final_defects.rms_relative
    );
    println!(
        "queried_maximum_absolute_defect={:.17e}",
        final_query_defects.maximum_absolute
    );
    println!(
        "queried_rms_absolute_defect={:.17e}",
        final_query_defects.rms_absolute
    );
    print_timing("transform_encoding", &mut samples.transform_encoding);
    print_timing("transpose", &mut samples.transpose);
    print_timing("commitment", &mut samples.commitment);
    print_timing("combination", &mut samples.combination);
    print_timing("combination_encoding", &mut samples.combination_encoding);
    print_timing("opening_extraction", &mut samples.opening_extraction);
    print_timing("opening_verification", &mut samples.opening_verification);
    print_timing("defect_scan", &mut samples.defect_scan);
    print_timing("total", &mut samples.total);

    run_spreading_study(
        source_columns,
        args.queries,
        args.spreading_trials,
        args.seed ^ 0x5350_5245_4144_494e,
    )?;
    Ok(())
}

fn validate_args(args: &Args) -> Result<(), io::Error> {
    if args.dimension == 0 || args.rows == 0 {
        return Err(invalid("dimension and rows must be positive"));
    }
    if !args.rows.is_power_of_two() {
        return Err(invalid("rows must be a power of two"));
    }
    if args.queries == 0 || args.repetitions == 0 || args.spreading_trials == 0 {
        return Err(invalid(
            "queries, repetitions, and spreading trials must be positive",
        ));
    }
    Ok(())
}

fn fwht_in_place(values: &mut [f64]) {
    debug_assert!(values.len().is_power_of_two());
    let mut half = 1_usize;
    while half < values.len() {
        let block = half * 2;
        for chunk in values.chunks_exact_mut(block) {
            let (left, right) = chunk.split_at_mut(half);
            for (left_value, right_value) in left.iter_mut().zip(right) {
                let lower = *left_value;
                let upper = *right_value;
                *left_value = lower + upper;
                *right_value = lower - upper;
            }
        }
        half = block;
    }
}

fn generate_source(
    dimension: usize,
    padded_dimension: usize,
    seed: u64,
) -> Result<Vec<f64>, io::Error> {
    let mut source = Vec::new();
    source
        .try_reserve_exact(padded_dimension)
        .map_err(|_| invalid("could not allocate source storage"))?;
    source.resize(padded_dimension, 0.0);
    let mut state = seed;
    let denominator = (1_u64 << 52) as f64;
    for value in &mut source[..dimension] {
        let mantissa = (splitmix64(&mut state) & ((1_u64 << 53) - 1)) as i64;
        *value = (mantissa - (1_i64 << 52)) as f64 / denominator;
    }
    Ok(source)
}

fn signed_dyadic_weights(len: usize, seed: u64) -> Result<Vec<f64>, io::Error> {
    if len == 0 || !len.is_power_of_two() {
        return Err(invalid(
            "dyadic weight count must be a positive power of two",
        ));
    }
    let mut weights = Vec::new();
    weights
        .try_reserve_exact(len)
        .map_err(|_| invalid("could not allocate challenge weights"))?;
    let mut state = seed;
    let scale = 1.0 / len as f64;
    for _ in 0..len {
        let sign = if splitmix64(&mut state) & 1 == 0 {
            1.0
        } else {
            -1.0
        };
        weights.push(sign * scale);
    }
    Ok(weights)
}

fn transpose_row_to_column(
    row_major: &[f64],
    rows: usize,
    columns: usize,
) -> Result<Vec<f64>, io::Error> {
    let expected = rows
        .checked_mul(columns)
        .ok_or_else(|| invalid("transpose shape overflow"))?;
    if row_major.len() != expected {
        return Err(invalid("transpose input does not match its shape"));
    }
    let mut column_major = Vec::new();
    column_major
        .try_reserve_exact(expected)
        .map_err(|_| invalid("could not allocate transposed storage"))?;
    column_major.resize(expected, 0.0);

    for row_base in (0..rows).step_by(TRANSPOSE_TILE) {
        let row_end = (row_base + TRANSPOSE_TILE).min(rows);
        for column_base in (0..columns).step_by(TRANSPOSE_TILE) {
            let column_end = (column_base + TRANSPOSE_TILE).min(columns);
            for row in row_base..row_end {
                for column in column_base..column_end {
                    column_major[column * rows + row] = row_major[row * columns + column];
                }
            }
        }
    }
    Ok(column_major)
}

fn build_column_tree(
    source: &[f64],
    parity: &[f64],
    rows: usize,
    source_columns: usize,
    encoded_columns: usize,
) -> Result<ColumnTree, io::Error> {
    let padded_columns = encoded_columns
        .checked_next_power_of_two()
        .ok_or_else(|| invalid("Merkle column padding overflow"))?;
    let hash_count = padded_columns
        .checked_mul(2)
        .ok_or_else(|| invalid("Merkle hash count overflow"))?;
    let mut hashes = Vec::new();
    hashes
        .try_reserve_exact(hash_count)
        .map_err(|_| invalid("could not allocate Merkle tree"))?;
    hashes.resize(hash_count, [0_u8; 32]);

    for column_index in 0..padded_columns {
        hashes[padded_columns + column_index] = if column_index < encoded_columns {
            hash_column(
                column_index,
                column(source, parity, rows, source_columns, column_index),
            )
        } else {
            hash_padding(column_index, encoded_columns)
        };
    }

    let mut child_width = padded_columns;
    let mut level = 1_usize;
    while child_width > 1 {
        let parent_width = child_width / 2;
        for parent_index in 0..parent_width {
            let child_index = child_width + 2 * parent_index;
            hashes[parent_width + parent_index] = hash_node(
                level,
                parent_index,
                &hashes[child_index],
                &hashes[child_index + 1],
            );
        }
        child_width = parent_width;
        level += 1;
    }

    Ok(ColumnTree {
        hashes,
        padded_columns,
        column_count: encoded_columns,
    })
}

fn hash_column(column_index: usize, values: &[f64]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(LEAF_DOMAIN);
    hasher.update(&(column_index as u64).to_le_bytes());
    hasher.update(&(values.len() as u64).to_le_bytes());
    let mut bytes = [0_u8; VALUES_PER_HASH_BLOCK * size_of::<f64>()];
    for block in values.chunks(VALUES_PER_HASH_BLOCK) {
        for (slot, value) in block.iter().enumerate() {
            let start = slot * size_of::<f64>();
            bytes[start..start + size_of::<f64>()].copy_from_slice(&value.to_bits().to_le_bytes());
        }
        hasher.update(&bytes[..size_of_val(block)]);
    }
    *hasher.finalize().as_bytes()
}

fn hash_padding(column_index: usize, column_count: usize) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PADDING_DOMAIN);
    hasher.update(&(column_index as u64).to_le_bytes());
    hasher.update(&(column_count as u64).to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn hash_node(level: usize, index: usize, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(NODE_DOMAIN);
    hasher.update(&(level as u64).to_le_bytes());
    hasher.update(&(index as u64).to_le_bytes());
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

fn derive_query_seed(root: &[u8; 32], combined_source: &[f64]) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(QUERY_DOMAIN);
    hasher.update(root);
    hasher.update(&(combined_source.len() as u64).to_le_bytes());
    let mut bytes = [0_u8; VALUES_PER_HASH_BLOCK * size_of::<f64>()];
    for block in combined_source.chunks(VALUES_PER_HASH_BLOCK) {
        for (slot, value) in block.iter().enumerate() {
            let start = slot * size_of::<f64>();
            bytes[start..start + size_of::<f64>()].copy_from_slice(&value.to_bits().to_le_bytes());
        }
        hasher.update(&bytes[..size_of_val(block)]);
    }
    let digest = hasher.finalize();
    u64::from_le_bytes(
        digest.as_bytes()[..size_of::<u64>()]
            .try_into()
            .expect("a BLAKE3 digest always contains eight bytes"),
    )
}

fn combine_columns(
    source: &[f64],
    parity: &[f64],
    rows: usize,
    source_columns: usize,
    encoded_columns: usize,
    weights: &[f64],
) -> Result<Vec<f64>, io::Error> {
    if weights.len() != rows {
        return Err(invalid("row weights do not match the matrix shape"));
    }
    let mut combined = Vec::new();
    combined
        .try_reserve_exact(encoded_columns)
        .map_err(|_| invalid("could not allocate row combination"))?;
    for column_index in 0..encoded_columns {
        combined.push(dot(
            column(source, parity, rows, source_columns, column_index),
            weights,
        )?);
    }
    Ok(combined)
}

fn column<'a>(
    source: &'a [f64],
    parity: &'a [f64],
    rows: usize,
    source_columns: usize,
    column_index: usize,
) -> &'a [f64] {
    if column_index < source_columns {
        let start = column_index * rows;
        &source[start..start + rows]
    } else {
        let start = (column_index - source_columns) * rows;
        &parity[start..start + rows]
    }
}

fn dot(left: &[f64], right: &[f64]) -> Result<f64, io::Error> {
    if left.len() != right.len() {
        return Err(invalid("dot-product inputs have different lengths"));
    }
    let mut sum = 0.0;
    for (&left_value, &right_value) in left.iter().zip(right) {
        sum += left_value * right_value;
    }
    Ok(sum)
}

fn compare_vectors(actual: &[f64], expected: &[f64]) -> Result<DefectMetrics, io::Error> {
    if actual.len() != expected.len() || actual.is_empty() {
        return Err(invalid("vector comparison shape is invalid"));
    }
    let mut absolute_defects = Vec::new();
    absolute_defects
        .try_reserve_exact(actual.len())
        .map_err(|_| invalid("could not allocate absolute defects"))?;
    let mut relative_defects = Vec::new();
    relative_defects
        .try_reserve_exact(actual.len())
        .map_err(|_| invalid("could not allocate relative defects"))?;
    for (&actual_value, &expected_value) in actual.iter().zip(expected) {
        let absolute = (actual_value - expected_value).abs();
        let scale = actual_value
            .abs()
            .max(expected_value.abs())
            .max(f64::MIN_POSITIVE);
        absolute_defects.push(absolute);
        relative_defects.push(absolute / scale);
    }
    summarize_defects(&absolute_defects, &relative_defects)
}

fn summarize_defects(
    absolute_defects: &[f64],
    relative_defects: &[f64],
) -> Result<DefectMetrics, io::Error> {
    if absolute_defects.len() != relative_defects.len() || absolute_defects.is_empty() {
        return Err(invalid("defect summary shape is invalid"));
    }
    let maximum_absolute = absolute_defects.iter().copied().fold(0.0_f64, f64::max);
    let squared_absolute: f64 = absolute_defects.iter().map(|value| value * value).sum();
    let maximum_relative = relative_defects.iter().copied().fold(0.0_f64, f64::max);
    let squared_relative: f64 = relative_defects.iter().map(|value| value * value).sum();
    let count = absolute_defects.len() as f64;
    Ok(DefectMetrics {
        maximum_absolute,
        rms_absolute: (squared_absolute / count).sqrt(),
        maximum_relative,
        rms_relative: (squared_relative / count).sqrt(),
    })
}

fn run_spreading_study(
    width: usize,
    queries: usize,
    trials: usize,
    seed: u64,
) -> Result<(), io::Error> {
    let fixed_spike = unit_spike(width)?;
    let fixed_subspace = balanced_subspace_vector(width)?;
    let fixed_dense = random_unit_vector(width, seed ^ 0x4649_5845_445f_4445)?;
    let mut fixed_spike_series = SpreadingSeries::default();
    let mut fixed_subspace_series = SpreadingSeries::default();
    let mut fixed_dense_series = SpreadingSeries::default();
    let mut adaptive_subspace_series = SpreadingSeries::default();
    let mut final_adaptive = None;

    let mut state = seed;
    for _ in 0..trials {
        let code_seed = splitmix64(&mut state);
        let code = RandomizedHadamardCode::new(width, code_seed)?;
        fixed_spike_series.push(analyze_alteration(&fixed_spike, &code, queries)?);
        fixed_subspace_series.push(analyze_alteration(&fixed_subspace, &code, queries)?);
        fixed_dense_series.push(analyze_alteration(&fixed_dense, &code, queries)?);

        let mut adaptive_subspace = fixed_subspace.clone();
        for (value, &sign) in adaptive_subspace.iter_mut().zip(&code.signs) {
            *value *= sign;
        }
        let metrics = analyze_alteration(&adaptive_subspace, &code, queries)?;
        adaptive_subspace_series.push(metrics);
        final_adaptive = Some(metrics);
    }

    println!("spreading_threshold_formula={TAIL_SCALE}*l2_norm/sqrt(width)");
    print_spreading_series("fixed_spike", &mut fixed_spike_series);
    print_spreading_series("fixed_subspace", &mut fixed_subspace_series);
    print_spreading_series("fixed_dense", &mut fixed_dense_series);
    print_spreading_series(
        "adaptive_public_signs_subspace",
        &mut adaptive_subspace_series,
    );
    if let Some(metrics) = final_adaptive {
        println!(
            "adaptive_public_signs_source_tail_coordinates={}",
            metrics.source_tail
        );
        println!(
            "adaptive_public_signs_parity_tail_coordinates={}",
            metrics.parity_tail
        );
    }
    Ok(())
}

fn analyze_alteration(
    source: &[f64],
    code: &RandomizedHadamardCode,
    queries: usize,
) -> Result<AlterationMetrics, io::Error> {
    if source.len() != code.width {
        return Err(invalid("alteration does not match the transform width"));
    }
    let parity = code.encode_vector(source)?;
    let source_energy = squared_norm(source);
    if source_energy == 0.0 || !source_energy.is_finite() {
        return Err(invalid("alteration must have finite positive energy"));
    }
    let source_norm = source_energy.sqrt();
    let threshold = TAIL_SCALE * source_norm / (code.width as f64).sqrt();
    let source_tail = source
        .iter()
        .filter(|value| value.abs() >= threshold)
        .count();
    let parity_tail = parity
        .iter()
        .filter(|value| value.abs() >= threshold)
        .count();
    let tail_count = source_tail + parity_tail;
    let encoded_columns = code.encoded_columns()?;
    let encoded_energy = source_energy + squared_norm(&parity);
    let fourth_moment = source
        .iter()
        .chain(&parity)
        .map(|value| value.powi(4))
        .sum::<f64>();
    let effective_support = if fourth_moment == 0.0 {
        0.0
    } else {
        encoded_energy * encoded_energy / fourth_moment
    };
    Ok(AlterationMetrics {
        source_tail,
        parity_tail,
        tail_fraction: tail_count as f64 / encoded_columns as f64,
        query_miss_probability: miss_probability(encoded_columns, tail_count, queries),
        encoded_energy_ratio: encoded_energy / source_energy,
        effective_support,
    })
}

fn unit_spike(width: usize) -> Result<Vec<f64>, io::Error> {
    if width == 0 {
        return Err(invalid("spike width must be positive"));
    }
    let mut values = vec![0.0; width];
    values[0] = 1.0;
    Ok(values)
}

fn balanced_subspace_vector(width: usize) -> Result<Vec<f64>, io::Error> {
    if width == 0 || !width.is_power_of_two() {
        return Err(invalid("subspace width must be a positive power of two"));
    }
    let support = 1_usize << (width.ilog2() / 2);
    let value = 1.0 / (support as f64).sqrt();
    let mut values = vec![0.0; width];
    values[..support].fill(value);
    Ok(values)
}

fn random_unit_vector(width: usize, seed: u64) -> Result<Vec<f64>, io::Error> {
    if width == 0 {
        return Err(invalid("random-vector width must be positive"));
    }
    let mut values = Vec::new();
    values
        .try_reserve_exact(width)
        .map_err(|_| invalid("could not allocate random alteration"))?;
    let mut state = seed;
    let denominator = (1_u64 << 52) as f64;
    for _ in 0..width {
        let mantissa = (splitmix64(&mut state) & ((1_u64 << 53) - 1)) as i64;
        values.push((mantissa - (1_i64 << 52)) as f64 / denominator);
    }
    let norm = squared_norm(&values).sqrt();
    for value in &mut values {
        *value /= norm;
    }
    Ok(values)
}

fn squared_norm(values: &[f64]) -> f64 {
    values.iter().map(|value| value * value).sum()
}

fn miss_probability(population: usize, marked: usize, queries: usize) -> f64 {
    if marked == 0 {
        return 1.0;
    }
    if queries > population - marked {
        return 0.0;
    }
    let mut probability = 1.0;
    for draw in 0..queries {
        probability *= (population - marked - draw) as f64 / (population - draw) as f64;
    }
    probability
}

fn print_spreading_series(label: &str, series: &mut SpreadingSeries) {
    println!(
        "{label}_tail_fraction_min={:.9}",
        minimum(&series.tail_fractions)
    );
    println!(
        "{label}_tail_fraction_median={:.9}",
        median(&mut series.tail_fractions)
    );
    println!(
        "{label}_tail_fraction_max={:.9}",
        maximum(&series.tail_fractions)
    );
    println!(
        "{label}_query_miss_probability_median={:.9e}",
        median(&mut series.miss_probabilities)
    );
    println!(
        "{label}_query_miss_probability_max={:.9e}",
        maximum(&series.miss_probabilities)
    );
    println!(
        "{label}_encoded_energy_ratio_median={:.17e}",
        median(&mut series.energy_ratios)
    );
    println!(
        "{label}_effective_support_median={:.3}",
        median(&mut series.effective_supports)
    );
}

fn minimum(values: &[f64]) -> f64 {
    values.iter().copied().fold(f64::INFINITY, f64::min)
}

fn maximum(values: &[f64]) -> f64 {
    values.iter().copied().fold(f64::NEG_INFINITY, f64::max)
}

fn median(values: &mut [f64]) -> f64 {
    values.sort_by(f64::total_cmp);
    if values.len().is_multiple_of(2) {
        (values[values.len() / 2 - 1] + values[values.len() / 2]) / 2.0
    } else {
        values[values.len() / 2]
    }
}

fn print_timing(label: &str, samples: &mut [Duration]) {
    samples.sort_unstable();
    let minimum = samples[0].as_secs_f64();
    let maximum = samples[samples.len() - 1].as_secs_f64();
    let median = if samples.len().is_multiple_of(2) {
        (samples[samples.len() / 2 - 1].as_secs_f64() + samples[samples.len() / 2].as_secs_f64())
            / 2.0
    } else {
        samples[samples.len() / 2].as_secs_f64()
    };
    println!("{label}_minimum_seconds={minimum:.9}");
    println!("{label}_median_seconds={median:.9}");
    println!("{label}_maximum_seconds={maximum:.9}");
}

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut value = *state;
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn randomized_hadamard_preserves_energy() -> Result<(), Box<dyn Error>> {
        let code = RandomizedHadamardCode::new(256, 7)?;
        let source = random_unit_vector(256, 11)?;
        let parity = code.encode_vector(&source)?;
        assert!((squared_norm(&source) - squared_norm(&parity)).abs() < 1.0e-12);
        Ok(())
    }

    #[test]
    fn public_signs_admit_balanced_subspace_attack() -> Result<(), Box<dyn Error>> {
        let width = 256;
        let code = RandomizedHadamardCode::new(width, 13)?;
        let fixed_spike = analyze_alteration(&unit_spike(width)?, &code, 16)?;
        let mut adaptive = balanced_subspace_vector(width)?;
        for (value, &sign) in adaptive.iter_mut().zip(&code.signs) {
            *value *= sign;
        }
        let attacked = analyze_alteration(&adaptive, &code, 16)?;
        assert_eq!(attacked.source_tail, 16);
        assert_eq!(attacked.parity_tail, 16);
        assert!(attacked.tail_fraction < fixed_spike.tail_fraction);
        assert!(attacked.query_miss_probability > fixed_spike.query_miss_probability);
        Ok(())
    }

    #[test]
    fn row_encoding_commutes_up_to_roundoff() -> Result<(), Box<dyn Error>> {
        let rows = 8;
        let columns = 16;
        let source = generate_source(rows * columns, rows * columns, 17)?;
        let code = RandomizedHadamardCode::new(columns, 19)?;
        let parity_column = code.encode_rows_to_columns(&source, rows)?;
        let source_column = transpose_row_to_column(&source, rows, columns)?;
        let weights = signed_dyadic_weights(rows, 23)?;
        let combined = combine_columns(
            &source_column,
            &parity_column,
            rows,
            columns,
            2 * columns,
            &weights,
        )?;
        let combined_parity = code.encode_vector(&combined[..columns])?;
        let defects = compare_vectors(&combined[columns..], &combined_parity)?;
        assert!(defects.maximum_absolute < 1.0e-12);
        Ok(())
    }

    #[test]
    fn query_seed_binds_root_and_claimed_combination() {
        let root = [7_u8; 32];
        let combination = [1.0, -2.0, 3.0];
        let seed = derive_query_seed(&root, &combination);

        let mut changed_root = root;
        changed_root[0] ^= 1;
        assert_ne!(seed, derive_query_seed(&changed_root, &combination));

        let mut changed_combination = combination;
        changed_combination[1] = f64::from_bits(changed_combination[1].to_bits() ^ 1);
        assert_ne!(seed, derive_query_seed(&root, &changed_combination));
    }

    #[test]
    fn opening_authenticates_values_and_paths() -> Result<(), Box<dyn Error>> {
        let rows = 8;
        let columns = 8;
        let source_row = generate_source(rows * columns, rows * columns, 29)?;
        let code = RandomizedHadamardCode::new(columns, 31)?;
        let parity = code.encode_rows_to_columns(&source_row, rows)?;
        let source = transpose_row_to_column(&source_row, rows, columns)?;
        let tree = build_column_tree(&source, &parity, rows, columns, 2 * columns)?;
        let weights = signed_dyadic_weights(rows, 37)?;
        let combined = combine_columns(&source, &parity, rows, columns, 2 * columns, &weights)?;
        let combined_parity = code.encode_vector(&combined[..columns])?;
        let opening = tree.naive_opening(&source, &parity, rows, columns, 4, 41)?;
        opening.verify(
            &tree,
            rows,
            columns,
            &weights,
            &combined[..columns],
            &combined_parity,
        )?;

        let mut bad_value = opening.clone();
        bad_value.values[0] = f64::from_bits(bad_value.values[0].to_bits() ^ 1);
        assert!(
            bad_value
                .verify(
                    &tree,
                    rows,
                    columns,
                    &weights,
                    &combined[..columns],
                    &combined_parity,
                )
                .is_err()
        );

        let mut bad_path = opening;
        bad_path.authentication[0][0] ^= 1;
        assert!(
            bad_path
                .verify(
                    &tree,
                    rows,
                    columns,
                    &weights,
                    &combined[..columns],
                    &combined_parity,
                )
                .is_err()
        );
        Ok(())
    }
}
