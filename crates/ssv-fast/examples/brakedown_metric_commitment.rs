//! Throughput surrogate for a Brakedown-shaped binary64 metric commitment.
//!
//! This example deliberately implements no proof protocol and makes no
//! proximity or soundness claim. It measures the minimum data movement for a
//! systematic sparse row encoding, a column Merkle commitment, and one encoded
//! row combination. The final defects quantify floating-point disagreement
//! between encode-then-combine and combine-then-encode.

#![forbid(unsafe_code)]

use std::error::Error;
use std::hint::black_box;
use std::io;
use std::time::{Duration, Instant};

use clap::Parser;

const LEAF_DOMAIN: &[u8] = b"ssv/research/brakedown-metric/column-leaf/v1";
const PADDING_DOMAIN: &[u8] = b"ssv/research/brakedown-metric/column-padding/v1";
const NODE_DOMAIN: &[u8] = b"ssv/research/brakedown-metric/column-node/v1";
const VALUES_PER_HASH_BLOCK: usize = 64;

#[derive(Debug, Parser)]
#[command(about = "Benchmark a speculative sparse-code binary64 commitment")]
struct Args {
    /// Logical number of source binary64 values.
    #[arg(long, default_value_t = 1 << 20)]
    dimension: usize,

    /// Rows in the approximately square source matrix.
    #[arg(long, default_value_t = 1024)]
    rows: usize,

    /// Parity columns per this many source columns.
    #[arg(long, default_value_t = 2)]
    parity_denominator: usize,

    /// Distinct source columns used by each parity column.
    #[arg(long, default_value_t = 4)]
    degree: usize,

    /// Naive full-column openings used for the proof-byte estimate.
    #[arg(long, default_value_t = 16)]
    queries: usize,

    #[arg(long, default_value_t = 1)]
    warmups: usize,

    #[arg(long, default_value_t = 7)]
    repetitions: usize,

    #[arg(long, default_value_t = 0x5eed_c0de_d15c_a11e)]
    seed: u64,
}

#[derive(Debug)]
struct SparseSystematicCode {
    source_columns: usize,
    parity_columns: usize,
    degree: usize,
    neighbors: Vec<usize>,
    signs: Vec<bool>,
    scale: f64,
}

impl SparseSystematicCode {
    fn new(
        source_columns: usize,
        parity_columns: usize,
        degree: usize,
        seed: u64,
    ) -> Result<Self, io::Error> {
        if source_columns == 0 || parity_columns == 0 {
            return Err(invalid("source and parity column counts must be positive"));
        }
        if degree == 0 || degree > source_columns || !degree.is_power_of_two() {
            return Err(invalid(
                "degree must be a positive power of two no larger than the source width",
            ));
        }
        let edge_count = parity_columns
            .checked_mul(degree)
            .ok_or_else(|| invalid("code edge count overflow"))?;
        let mut neighbors = Vec::new();
        neighbors
            .try_reserve_exact(edge_count)
            .map_err(|_| invalid("could not allocate code neighbors"))?;
        let mut signs = Vec::new();
        signs
            .try_reserve_exact(edge_count)
            .map_err(|_| invalid("could not allocate code signs"))?;

        let mut state = seed;
        for parity_column in 0..parity_columns {
            let edge_start = neighbors.len();
            while neighbors.len() - edge_start < degree {
                let random = splitmix64(&mut state)
                    ^ (parity_column as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
                let candidate = (random as usize) % source_columns;
                if neighbors[edge_start..].contains(&candidate) {
                    continue;
                }
                neighbors.push(candidate);
                signs.push(random & (1_u64 << 63) == 0);
            }
        }

        Ok(Self {
            source_columns,
            parity_columns,
            degree,
            neighbors,
            signs,
            scale: 1.0 / degree as f64,
        })
    }

    fn encoded_columns(&self) -> Result<usize, io::Error> {
        self.source_columns
            .checked_add(self.parity_columns)
            .ok_or_else(|| invalid("encoded column count overflow"))
    }

    fn encode_rows(&self, source: &[f64], rows: usize) -> Result<Vec<f64>, io::Error> {
        let expected_source_values = rows
            .checked_mul(self.source_columns)
            .ok_or_else(|| invalid("source shape overflow"))?;
        if source.len() != expected_source_values {
            return Err(invalid("source storage does not match the code shape"));
        }
        let parity_values = rows
            .checked_mul(self.parity_columns)
            .ok_or_else(|| invalid("parity shape overflow"))?;
        let mut parity = Vec::new();
        parity
            .try_reserve_exact(parity_values)
            .map_err(|_| invalid("could not allocate parity storage"))?;
        parity.resize(parity_values, 0.0);

        for parity_column in 0..self.parity_columns {
            let edge_start = parity_column * self.degree;
            for row in 0..rows {
                let mut sum = 0.0;
                for edge in edge_start..edge_start + self.degree {
                    let value = source[self.neighbors[edge] * rows + row];
                    sum = if self.signs[edge] {
                        sum + value
                    } else {
                        sum - value
                    };
                }
                parity[parity_column * rows + row] = sum * self.scale;
            }
        }
        Ok(parity)
    }

    fn encode_vector(&self, source: &[f64]) -> Result<Vec<f64>, io::Error> {
        if source.len() != self.source_columns {
            return Err(invalid("source vector does not match the code width"));
        }
        let mut parity = Vec::new();
        parity
            .try_reserve_exact(self.parity_columns)
            .map_err(|_| invalid("could not allocate encoded combination"))?;
        for parity_column in 0..self.parity_columns {
            let edge_start = parity_column * self.degree;
            let mut sum = 0.0;
            for edge in edge_start..edge_start + self.degree {
                let value = source[self.neighbors[edge]];
                sum = if self.signs[edge] {
                    sum + value
                } else {
                    sum - value
                };
            }
            parity.push(sum * self.scale);
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
                combined_parity
                    .get(column_index - source_columns)
                    .copied()
                    .ok_or_else(|| invalid("opened parity column is out of range"))?
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
    encoding: Vec<Duration>,
    commitment: Vec<Duration>,
    combination: Vec<Duration>,
    combination_encoding: Vec<Duration>,
    opening_extraction: Vec<Duration>,
    opening_verification: Vec<Duration>,
    defect_scan: Vec<Duration>,
    total: Vec<Duration>,
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
    let parity_columns = source_columns.div_ceil(args.parity_denominator);
    let code = SparseSystematicCode::new(
        source_columns,
        parity_columns,
        args.degree,
        args.seed ^ 0x434f_4445_4752_4150,
    )?;
    let encoded_columns = code.encoded_columns()?;
    if args.queries > encoded_columns {
        return Err(invalid("queries cannot exceed encoded columns").into());
    }

    let source = generate_source(args.dimension, padded_dimension, args.seed)?;
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
        let parity = code.encode_rows(&source, args.rows)?;
        let encoding = start.elapsed();

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
        let root_seed = u64::from_le_bytes(tree.root()[..8].try_into()?);
        let opening = tree.naive_opening(
            &source,
            &parity,
            args.rows,
            source_columns,
            args.queries,
            args.seed ^ root_seed,
        )?;
        let opening_extraction = start.elapsed();

        let start = Instant::now();
        let defects = compare_parity_combinations(&combined[source_columns..], &combined_parity)?;
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
            samples.encoding.push(encoding);
            samples.commitment.push(commitment);
            samples.combination.push(combination);
            samples.combination_encoding.push(combination_encoding);
            samples.opening_extraction.push(opening_extraction);
            samples.opening_verification.push(opening_verification);
            samples.defect_scan.push(defect_scan);
            samples.total.push(total);
        }
    }

    let source_bytes = source.len() * size_of::<f64>();
    let parity_bytes = args.rows * parity_columns * size_of::<f64>();

    println!("status=throughput-surrogate-without-soundness-claim");
    println!("logical_dimension={}", args.dimension);
    println!("padded_dimension={padded_dimension}");
    println!("rows={}", args.rows);
    println!("source_columns={source_columns}");
    println!("parity_columns={parity_columns}");
    println!("encoded_columns={encoded_columns}");
    println!("degree={}", args.degree);
    println!("queries={}", args.queries);
    println!("source_bytes={source_bytes}");
    println!("parity_bytes={parity_bytes}");
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
    print_timing("encoding", &mut samples.encoding);
    print_timing("commitment", &mut samples.commitment);
    print_timing("combination", &mut samples.combination);
    print_timing("combination_encoding", &mut samples.combination_encoding);
    print_timing("opening_extraction", &mut samples.opening_extraction);
    print_timing("opening_verification", &mut samples.opening_verification);
    print_timing("defect_scan", &mut samples.defect_scan);
    print_timing("total", &mut samples.total);
    Ok(())
}

fn validate_args(args: &Args) -> Result<(), io::Error> {
    if args.dimension == 0 || args.rows == 0 {
        return Err(invalid("dimension and rows must be positive"));
    }
    if !args.rows.is_power_of_two() {
        return Err(invalid("rows must be a power of two"));
    }
    if args.parity_denominator == 0 {
        return Err(invalid("parity denominator must be positive"));
    }
    if args.queries == 0 || args.repetitions == 0 {
        return Err(invalid("queries and repetitions must be positive"));
    }
    Ok(())
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
    // Exercise realistic rounding rather than making every subsequent sum
    // exact: values span [-1, 1) with up to 52 fractional bits.
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

fn compare_parity_combinations(
    encode_then_combine: &[f64],
    combine_then_encode: &[f64],
) -> Result<DefectMetrics, io::Error> {
    if encode_then_combine.len() != combine_then_encode.len() || encode_then_combine.is_empty() {
        return Err(invalid("parity comparison shape is invalid"));
    }
    let mut maximum_absolute = 0.0_f64;
    let mut squared_absolute = 0.0_f64;
    let mut maximum_relative = 0.0_f64;
    let mut squared_relative = 0.0_f64;
    for (&actual, &expected) in encode_then_combine.iter().zip(combine_then_encode) {
        let absolute = (actual - expected).abs();
        let scale = actual.abs().max(expected.abs()).max(f64::MIN_POSITIVE);
        let relative = absolute / scale;
        maximum_absolute = maximum_absolute.max(absolute);
        squared_absolute += absolute * absolute;
        maximum_relative = maximum_relative.max(relative);
        squared_relative += relative * relative;
    }
    let count = encode_then_combine.len() as f64;
    Ok(DefectMetrics {
        maximum_absolute,
        rms_absolute: (squared_absolute / count).sqrt(),
        maximum_relative,
        rms_relative: (squared_relative / count).sqrt(),
    })
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
    fn opening_authenticates_values_and_paths() -> Result<(), Box<dyn Error>> {
        let rows = 8;
        let source_columns = 8;
        let dimension = rows * source_columns;
        let source = generate_source(dimension, dimension, 7)?;
        let code = SparseSystematicCode::new(source_columns, 4, 2, 11)?;
        let parity = code.encode_rows(&source, rows)?;
        let encoded_columns = code.encoded_columns()?;
        let tree = build_column_tree(&source, &parity, rows, source_columns, encoded_columns)?;
        let weights = signed_dyadic_weights(rows, 13)?;
        let combined = combine_columns(
            &source,
            &parity,
            rows,
            source_columns,
            encoded_columns,
            &weights,
        )?;
        let combined_parity = code.encode_vector(&combined[..source_columns])?;
        let opening = tree.naive_opening(&source, &parity, rows, source_columns, 4, 17)?;
        let metrics = opening.verify(
            &tree,
            rows,
            source_columns,
            &weights,
            &combined[..source_columns],
            &combined_parity,
        )?;
        assert!(metrics.maximum_absolute.is_finite());

        let mut bad_value = opening.clone();
        bad_value.values[0] = f64::from_bits(bad_value.values[0].to_bits() ^ 1);
        assert!(
            bad_value
                .verify(
                    &tree,
                    rows,
                    source_columns,
                    &weights,
                    &combined[..source_columns],
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
                    source_columns,
                    &weights,
                    &combined[..source_columns],
                    &combined_parity,
                )
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn graph_and_commitment_are_deterministic() -> Result<(), Box<dyn Error>> {
        let rows = 4;
        let source_columns = 4;
        let dimension = rows * source_columns;
        let source = generate_source(dimension, dimension, 19)?;
        let first_code = SparseSystematicCode::new(source_columns, 2, 2, 23)?;
        let second_code = SparseSystematicCode::new(source_columns, 2, 2, 23)?;
        assert_eq!(first_code.neighbors, second_code.neighbors);
        assert_eq!(first_code.signs, second_code.signs);
        let first_parity = first_code.encode_rows(&source, rows)?;
        let second_parity = second_code.encode_rows(&source, rows)?;
        assert_eq!(first_parity, second_parity);
        let first_tree = build_column_tree(
            &source,
            &first_parity,
            rows,
            source_columns,
            first_code.encoded_columns()?,
        )?;
        let second_tree = build_column_tree(
            &source,
            &second_parity,
            rows,
            source_columns,
            second_code.encoded_columns()?,
        )?;
        assert_eq!(first_tree.root(), second_tree.root());
        Ok(())
    }

    #[test]
    fn invalid_code_degree_is_rejected() {
        assert!(SparseSystematicCode::new(4, 2, 0, 1).is_err());
        assert!(SparseSystematicCode::new(4, 2, 3, 1).is_err());
        assert!(SparseSystematicCode::new(4, 2, 8, 1).is_err());
    }
}
