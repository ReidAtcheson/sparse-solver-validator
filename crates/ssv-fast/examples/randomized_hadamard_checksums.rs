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
use ssv_fast::{
    DefectObservation, ProductEndpoint, ProductSumcheckProof, QuadraticBernstein, Transcript,
    evaluate_mle, product_sum, prove_product_owned, verify_product, verify_product_endpoint,
};

const LEAF_DOMAIN: &[u8] = b"ssv/research/randomized-hadamard/column-leaf/v1";
const PADDING_DOMAIN: &[u8] = b"ssv/research/randomized-hadamard/column-padding/v1";
const NODE_DOMAIN: &[u8] = b"ssv/research/randomized-hadamard/column-node/v1";
const QUERY_DOMAIN: &[u8] = b"ssv/research/randomized-hadamard/query-seed/v1";
const GLOBAL_SUMCHECK_DOMAIN: &[u8] =
    b"ssv/research/randomized-hadamard/global-checksum-sumcheck/v1";
const GLOBAL_WEIGHT_DOMAIN: &[u8] = b"ssv/research/randomized-hadamard/global-checksum-weights/v1";
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
    global_sumcheck_table_build: Vec<Duration>,
    global_sumcheck_prove: Vec<Duration>,
    global_sumcheck_verify: Vec<Duration>,
    staged_total: Vec<Duration>,
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

#[derive(Clone, Copy, Debug)]
struct RecursiveFoldSwitchMetrics {
    first_round_pairs: usize,
    violated_first_round_pairs: usize,
    query_miss_probability: f64,
    child_relation_maximum_absolute_defect: f64,
    terminal_absolute_defect: f64,
}

#[derive(Debug)]
struct GlobalRelationTables {
    data: Vec<f64>,
    coefficients: Vec<f64>,
    row_weights: Vec<f64>,
    output_weights: Vec<f64>,
    source_weights: Vec<f64>,
}

#[derive(Clone, Copy, Debug, Default)]
struct GlobalSumcheckMetrics {
    initial_claim: f64,
    rounds: usize,
    incremental_payload_bytes: usize,
    maximum_round_absolute_defect: f64,
    public_coefficient_endpoint_absolute_defect: f64,
    final_product_absolute_defect: f64,
    unauthenticated_data_endpoint: f64,
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
    let mut final_global_sumcheck = GlobalSumcheckMetrics::default();
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
        let global_tables = build_global_relation_tables(
            source,
            parity,
            args.rows,
            source_columns,
            &code.signs,
            &tree.root(),
        )?;
        let global_initial_claim = product_sum(&global_tables.data, &global_tables.coefficients)?;
        let global_sumcheck_table_build = start.elapsed();

        let start = Instant::now();
        let mut global_prover_transcript =
            initialize_global_sumcheck_transcript(&tree.root(), global_initial_claim);
        let (global_proof, global_endpoint) = prove_product_owned(
            global_tables.data,
            global_tables.coefficients,
            global_initial_claim,
            |round, polynomial| {
                global_sumcheck_challenge(&mut global_prover_transcript, round, polynomial)
            },
        )?;
        let global_sumcheck_prove = start.elapsed();
        let staged_total = total + global_sumcheck_table_build + global_sumcheck_prove;

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

        let start = Instant::now();
        let mut global_verifier_transcript =
            initialize_global_sumcheck_transcript(&tree.root(), global_initial_claim);
        let global_table_len = padded_dimension
            .checked_mul(2)
            .ok_or_else(|| invalid("global sumcheck table length overflow"))?;
        let global_verification = verify_product(
            global_table_len,
            global_initial_claim,
            &global_proof,
            |round, polynomial| {
                global_sumcheck_challenge(&mut global_verifier_transcript, round, polynomial)
            },
        )?;
        let public_coefficient_endpoint = evaluate_global_coefficient_endpoint(
            &global_verification.endpoint.point,
            args.rows,
            source_columns,
            &global_tables.row_weights,
            &global_tables.output_weights,
            &global_tables.source_weights,
        )?;
        let final_product = verify_product_endpoint(
            &global_verification.endpoint,
            global_endpoint.left_evaluation,
            public_coefficient_endpoint,
        )?;
        let global_sumcheck_verify = start.elapsed();

        let global_sumcheck = summarize_global_sumcheck(
            global_initial_claim,
            &global_proof,
            &global_endpoint,
            &global_verification.round_defects,
            public_coefficient_endpoint,
            final_product.absolute_defect,
        )?;

        black_box(tree.root());
        black_box(defects.maximum_absolute);
        black_box(claim);
        black_box(opening.values.last());
        black_box(query_defects.maximum_absolute);
        black_box(global_sumcheck.final_product_absolute_defect);
        final_root = tree.root();
        final_tree_bytes = tree.bytes();
        final_opening_bytes = opening.payload_bytes(source_columns)?;
        final_defects = defects;
        final_query_defects = query_defects;
        final_global_sumcheck = global_sumcheck;
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
            samples
                .global_sumcheck_table_build
                .push(global_sumcheck_table_build);
            samples.global_sumcheck_prove.push(global_sumcheck_prove);
            samples.global_sumcheck_verify.push(global_sumcheck_verify);
            samples.staged_total.push(staged_total);
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
    println!(
        "global_sumcheck_initial_metric_claim={:.17e}",
        final_global_sumcheck.initial_claim
    );
    println!("global_sumcheck_rounds={}", final_global_sumcheck.rounds);
    println!(
        "global_sumcheck_incremental_payload_bytes={}",
        final_global_sumcheck.incremental_payload_bytes
    );
    println!(
        "global_sumcheck_maximum_round_absolute_defect={:.17e}",
        final_global_sumcheck.maximum_round_absolute_defect
    );
    println!(
        "global_sumcheck_public_coefficient_endpoint_absolute_defect={:.17e}",
        final_global_sumcheck.public_coefficient_endpoint_absolute_defect
    );
    println!(
        "global_sumcheck_final_product_absolute_defect={:.17e}",
        final_global_sumcheck.final_product_absolute_defect
    );
    println!(
        "global_sumcheck_unauthenticated_data_endpoint={:.17e}",
        final_global_sumcheck.unauthenticated_data_endpoint
    );
    println!("global_sumcheck_data_endpoint_authenticated=false");
    print_timing("transform_encoding", &mut samples.transform_encoding);
    print_timing("transpose", &mut samples.transpose);
    print_timing("commitment", &mut samples.commitment);
    print_timing("combination", &mut samples.combination);
    print_timing("combination_encoding", &mut samples.combination_encoding);
    print_timing("opening_extraction", &mut samples.opening_extraction);
    print_timing("opening_verification", &mut samples.opening_verification);
    print_timing("defect_scan", &mut samples.defect_scan);
    print_timing("total", &mut samples.total);
    print_timing(
        "global_sumcheck_table_build",
        &mut samples.global_sumcheck_table_build,
    );
    print_timing("global_sumcheck_prove", &mut samples.global_sumcheck_prove);
    print_timing(
        "global_sumcheck_verify",
        &mut samples.global_sumcheck_verify,
    );
    print_timing("staged_total", &mut samples.staged_total);

    run_spreading_study(
        source_columns,
        args.queries,
        args.spreading_trials,
        args.seed ^ 0x5350_5245_4144_494e,
    )?;
    let fold_switch =
        recursive_fold_switch_attack(&code, args.queries, args.seed ^ 0x464f_4c44_5f53_5749)?;
    println!("recursive_fold_candidate=odd-even-local-fold-v1");
    println!(
        "recursive_fold_switch_attack_first_round_pairs={}",
        fold_switch.first_round_pairs
    );
    println!(
        "recursive_fold_switch_attack_violated_first_round_pairs={}",
        fold_switch.violated_first_round_pairs
    );
    println!(
        "recursive_fold_switch_attack_query_miss_probability={:.9e}",
        fold_switch.query_miss_probability
    );
    println!(
        "recursive_fold_switch_attack_child_relation_maximum_absolute_defect={:.17e}",
        fold_switch.child_relation_maximum_absolute_defect
    );
    println!(
        "recursive_fold_switch_attack_terminal_absolute_defect={:.17e}",
        fold_switch.terminal_absolute_defect
    );
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

/// Folds one normalized Walsh--Hadamard relation.
///
/// For `parity = H_n source`, split both vectors into equal halves and set
///
/// ```text
/// next_source = ((1 + challenge) source_0
///              + (1 - challenge) source_1) / sqrt(2)
/// next_parity = parity_0 + challenge parity_1.
/// ```
///
/// The result satisfies `next_parity = H_(n/2) next_source`, up to binary64
/// roundoff. This identity supplies completeness; it does not by itself give
/// proximity soundness for Merkle-sampled fold relations.
fn fold_hadamard_relation(
    source: &[f64],
    parity: &[f64],
    challenge: f64,
) -> Result<(Vec<f64>, Vec<f64>), io::Error> {
    if source.len() != parity.len() || source.len() < 2 || !source.len().is_power_of_two() {
        return Err(invalid("Hadamard fold relation shape is invalid"));
    }
    if !challenge.is_finite() {
        return Err(invalid("Hadamard fold challenge must be finite"));
    }
    let half = source.len() / 2;
    let inverse_sqrt_two = 1.0 / 2.0_f64.sqrt();
    let plus = 1.0 + challenge;
    let minus = 1.0 - challenge;
    let mut next_source = Vec::new();
    next_source
        .try_reserve_exact(half)
        .map_err(|_| invalid("could not allocate folded Hadamard source"))?;
    let mut next_parity = Vec::new();
    next_parity
        .try_reserve_exact(half)
        .map_err(|_| invalid("could not allocate folded Hadamard parity"))?;
    for index in 0..half {
        next_source.push((plus * source[index] + minus * source[index + half]) * inverse_sqrt_two);
        next_parity.push(parity[index] + challenge * parity[index + half]);
    }
    Ok((next_source, next_parity))
}

fn normalized_hadamard(source: &[f64]) -> Result<Vec<f64>, io::Error> {
    if source.is_empty() || !source.len().is_power_of_two() {
        return Err(invalid(
            "normalized Hadamard input must have positive power-of-two length",
        ));
    }
    let mut transformed = source.to_vec();
    fwht_in_place(&mut transformed);
    let normalization = 1.0 / (source.len() as f64).sqrt();
    for value in &mut transformed {
        *value *= normalization;
    }
    Ok(transformed)
}

fn dyadic_fold_challenge(state: &mut u64) -> f64 {
    // Keep the challenge away from either projection endpoint. All possible
    // values are exactly representable in binary64.
    let numerator = 256 + splitmix64(state) % 513;
    numerator as f64 / 1024.0
}

/// Executes the sparse codeword-switch attack against the tempting recursive
/// odd/even checker.
///
/// The checkpoint fixes a one-coordinate source alteration before the random
/// signs. The appended parity is nevertheless allowed to encode the altered
/// source. After seeing the first fold challenge, the adversary changes the
/// child systematic vector at the one affected pair. That child and every
/// later level are honest codewords, so only one first-round local equation is
/// false and the terminal equality is valid independently of later challenges.
fn recursive_fold_switch_attack(
    code: &RandomizedHadamardCode,
    queries: usize,
    seed: u64,
) -> Result<RecursiveFoldSwitchMetrics, io::Error> {
    if code.width < 2 {
        return Err(invalid("recursive fold attack requires width at least two"));
    }

    let committed_source = vec![0.0; code.width];
    let mut fixed_alteration = vec![0.0; code.width];
    fixed_alteration[0] = 1.0;
    let forged_parity = code.encode_vector(&fixed_alteration)?;

    // The recursive relation sees D * source on its systematic side.
    let mut signed_alteration = fixed_alteration;
    for (value, &sign) in signed_alteration.iter_mut().zip(&code.signs) {
        *value *= sign;
    }

    let mut state = seed;
    let first_challenge = dyadic_fold_challenge(&mut state);
    let (honest_child_source, honest_child_parity) =
        fold_hadamard_relation(&committed_source, &forged_parity, first_challenge)?;
    let (altered_child_source, altered_child_parity) =
        fold_hadamard_relation(&signed_alteration, &forged_parity, first_challenge)?;

    // Both executions fold the identical parent parity. The adversary changes
    // only the child systematic coordinate carrying the fixed alteration.
    let parity_fold_defects = compare_vectors(&altered_child_parity, &honest_child_parity)?;
    let violated_first_round_pairs = altered_child_source
        .iter()
        .zip(&honest_child_source)
        .filter(|(altered, honest)| *altered != *honest)
        .count();

    let child_expected_parity = normalized_hadamard(&altered_child_source)?;
    let child_relation = compare_vectors(&altered_child_parity, &child_expected_parity)?;

    let mut source = altered_child_source;
    let mut parity = altered_child_parity;
    while source.len() > 1 {
        let challenge = dyadic_fold_challenge(&mut state);
        (source, parity) = fold_hadamard_relation(&source, &parity, challenge)?;
    }

    let first_round_pairs = code.width / 2;
    let sampled_pairs = queries.min(first_round_pairs);
    Ok(RecursiveFoldSwitchMetrics {
        first_round_pairs,
        violated_first_round_pairs,
        query_miss_probability: miss_probability(
            first_round_pairs,
            violated_first_round_pairs,
            sampled_pairs,
        ),
        child_relation_maximum_absolute_defect: child_relation
            .maximum_absolute
            .max(parity_fold_defects.maximum_absolute),
        terminal_absolute_defect: (source[0] - parity[0]).abs(),
    })
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

fn build_global_relation_tables(
    mut source: Vec<f64>,
    parity: Vec<f64>,
    rows: usize,
    columns: usize,
    signs: &[f64],
    appended_root: &[u8; 32],
) -> Result<GlobalRelationTables, io::Error> {
    let table_len = rows
        .checked_mul(columns)
        .ok_or_else(|| invalid("global relation table shape overflow"))?;
    if source.len() != table_len || parity.len() != table_len || signs.len() != columns {
        return Err(invalid("global relation table shape is invalid"));
    }

    let master_seed = derive_root_seed(appended_root, GLOBAL_WEIGHT_DOMAIN);
    let row_weights = signed_unit_weights(rows, master_seed ^ 0x524f_575f_4c41_4d42)?;
    let output_weights = signed_unit_weights(columns, master_seed ^ 0x4f55_545f_5745_4947)?;
    let mut source_weights = normalized_hadamard(&output_weights)?;
    for (value, &sign) in source_weights.iter_mut().zip(signs) {
        *value = canonicalize_zero(*value * sign);
    }

    let combined_len = table_len
        .checked_mul(2)
        .ok_or_else(|| invalid("global relation combined table length overflow"))?;
    let mut data = parity;
    data.try_reserve_exact(table_len)
        .map_err(|_| invalid("could not grow the global relation data table"))?;
    data.append(&mut source);
    debug_assert_eq!(data.len(), combined_len);
    for value in &mut data {
        *value = canonicalize_zero(*value);
    }

    let mut coefficients = Vec::new();
    coefficients
        .try_reserve_exact(combined_len)
        .map_err(|_| invalid("could not allocate global relation coefficient table"))?;
    for &column_weight in &output_weights {
        for &row_weight in &row_weights {
            coefficients.push(canonicalize_zero(row_weight * column_weight));
        }
    }
    for &column_weight in &source_weights {
        for &row_weight in &row_weights {
            coefficients.push(canonicalize_zero(-(row_weight * column_weight)));
        }
    }

    Ok(GlobalRelationTables {
        data,
        coefficients,
        row_weights,
        output_weights,
        source_weights,
    })
}

fn canonicalize_zero(value: f64) -> f64 {
    if value == 0.0 { 0.0 } else { value }
}

fn signed_unit_weights(len: usize, seed: u64) -> Result<Vec<f64>, io::Error> {
    if len == 0 || !len.is_power_of_two() {
        return Err(invalid(
            "orthogonal weight count must be a positive power of two",
        ));
    }
    let mut weights = Vec::new();
    weights
        .try_reserve_exact(len)
        .map_err(|_| invalid("could not allocate orthogonal weights"))?;
    let mut state = seed;
    let scale = 1.0 / (len as f64).sqrt();
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

fn derive_root_seed(root: &[u8; 32], domain: &[u8]) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(root);
    let digest = hasher.finalize();
    u64::from_le_bytes(
        digest.as_bytes()[..size_of::<u64>()]
            .try_into()
            .expect("a BLAKE3 digest always contains eight bytes"),
    )
}

fn initialize_global_sumcheck_transcript(root: &[u8; 32], initial_claim: f64) -> Transcript {
    let mut transcript = Transcript::new(GLOBAL_SUMCHECK_DOMAIN);
    transcript.absorb_root(b"appended-checksum-root", root);
    transcript.absorb_u64(b"global-relation-initial-claim", initial_claim.to_bits());
    transcript
}

fn global_sumcheck_challenge(
    transcript: &mut Transcript,
    round: usize,
    polynomial: &QuadraticBernstein,
) -> f64 {
    transcript.absorb_u64(b"global-relation-round", round as u64);
    for &coefficient in &polynomial.coefficients {
        transcript.absorb_u64(b"global-relation-coefficient", coefficient.to_bits());
    }
    transcript
        .challenge_dyadic_f64(b"global-relation-challenge")
        .expect("the fixed logarithmic sumcheck cannot exhaust the transcript counter")
}

fn evaluate_global_coefficient_endpoint(
    point: &[f64],
    rows: usize,
    columns: usize,
    row_weights: &[f64],
    output_weights: &[f64],
    source_weights: &[f64],
) -> Result<f64, Box<dyn Error>> {
    let column_variables = columns.ilog2() as usize;
    let row_variables = rows.ilog2() as usize;
    let expected_variables = 1_usize
        .checked_add(column_variables)
        .and_then(|value| value.checked_add(row_variables))
        .ok_or_else(|| invalid("global coefficient point dimension overflow"))?;
    if point.len() != expected_variables
        || row_weights.len() != rows
        || output_weights.len() != columns
        || source_weights.len() != columns
    {
        return Err(invalid("global coefficient endpoint shape is invalid").into());
    }

    let block_coordinate = point[0];
    let column_point = &point[1..1 + column_variables];
    let row_point = &point[1 + column_variables..];
    let row_evaluation = evaluate_mle(row_weights, row_point)?;
    let output_evaluation = evaluate_mle(output_weights, column_point)?;
    let source_evaluation = evaluate_mle(source_weights, column_point)?;
    Ok(
        (1.0 - block_coordinate) * row_evaluation * output_evaluation
            - block_coordinate * row_evaluation * source_evaluation,
    )
}

fn summarize_global_sumcheck(
    initial_claim: f64,
    proof: &ProductSumcheckProof,
    endpoint: &ProductEndpoint,
    round_defects: &[DefectObservation],
    public_coefficient_endpoint: f64,
    final_product_absolute_defect: f64,
) -> Result<GlobalSumcheckMetrics, io::Error> {
    let round_bytes = proof
        .rounds
        .len()
        .checked_mul(3 * size_of::<f64>())
        .ok_or_else(|| invalid("global sumcheck round byte count overflow"))?;
    let incremental_payload_bytes = 2_usize
        .checked_mul(size_of::<f64>())
        .and_then(|value| value.checked_add(round_bytes))
        .ok_or_else(|| invalid("global sumcheck payload byte count overflow"))?;
    let maximum_round_absolute_defect = round_defects
        .iter()
        .map(|defect| defect.absolute_defect)
        .fold(0.0_f64, f64::max);
    Ok(GlobalSumcheckMetrics {
        initial_claim,
        rounds: proof.rounds.len(),
        incremental_payload_bytes,
        maximum_round_absolute_defect,
        public_coefficient_endpoint_absolute_defect: (endpoint.right_evaluation
            - public_coefficient_endpoint)
            .abs(),
        final_product_absolute_defect,
        unauthenticated_data_endpoint: endpoint.left_evaluation,
    })
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

    #[test]
    fn odd_even_fold_preserves_a_hadamard_relation() -> Result<(), Box<dyn Error>> {
        let source = random_unit_vector(256, 43)?;
        let parity = normalized_hadamard(&source)?;
        let (folded_source, folded_parity) = fold_hadamard_relation(&source, &parity, 0.375)?;
        let expected = normalized_hadamard(&folded_source)?;
        let defects = compare_vectors(&folded_parity, &expected)?;
        assert!(defects.maximum_absolute < 1.0e-14);
        Ok(())
    }

    #[test]
    fn sparse_switch_defeats_local_odd_even_fold_queries() -> Result<(), Box<dyn Error>> {
        let code = RandomizedHadamardCode::new(4096, 47)?;
        let metrics = recursive_fold_switch_attack(&code, 16, 53)?;
        assert_eq!(metrics.first_round_pairs, 2048);
        assert_eq!(metrics.violated_first_round_pairs, 1);
        assert!((metrics.query_miss_probability - 0.992_187_5).abs() < f64::EPSILON);
        assert!(metrics.child_relation_maximum_absolute_defect < 1.0e-14);
        assert!(metrics.terminal_absolute_defect < 1.0e-13);
        Ok(())
    }

    #[test]
    fn global_coefficient_endpoint_factorizes() -> Result<(), Box<dyn Error>> {
        let rows = 8;
        let columns = 16;
        let source_row = generate_source(rows * columns, rows * columns, 59)?;
        let code = RandomizedHadamardCode::new(columns, 61)?;
        let parity = code.encode_rows_to_columns(&source_row, rows)?;
        let source = transpose_row_to_column(&source_row, rows, columns)?;
        let tree = build_column_tree(&source, &parity, rows, columns, 2 * columns)?;
        let tables =
            build_global_relation_tables(source, parity, rows, columns, &code.signs, &tree.root())?;
        let point = vec![0.375; (2 * rows * columns).ilog2() as usize];
        let direct = evaluate_mle(&tables.coefficients, &point)?;
        let factored = evaluate_global_coefficient_endpoint(
            &point,
            rows,
            columns,
            &tables.row_weights,
            &tables.output_weights,
            &tables.source_weights,
        )?;
        assert!((direct - factored).abs() < 1.0e-15);
        Ok(())
    }

    #[test]
    fn global_contraction_observes_a_committed_checksum_mutation() -> Result<(), Box<dyn Error>> {
        let rows = 8;
        let columns = 8;
        let source_row = generate_source(rows * columns, rows * columns, 67)?;
        let code = RandomizedHadamardCode::new(columns, 71)?;
        let mut parity = code.encode_rows_to_columns(&source_row, rows)?;
        let source = transpose_row_to_column(&source_row, rows, columns)?;
        let honest_tree = build_column_tree(&source, &parity, rows, columns, 2 * columns)?;
        let honest = build_global_relation_tables(
            source.clone(),
            parity.clone(),
            rows,
            columns,
            &code.signs,
            &honest_tree.root(),
        )?;
        assert!(product_sum(&honest.data, &honest.coefficients)?.abs() < 1.0e-14);

        parity[0] += 1.0;
        let altered_tree = build_column_tree(&source, &parity, rows, columns, 2 * columns)?;
        let altered = build_global_relation_tables(
            source,
            parity,
            rows,
            columns,
            &code.signs,
            &altered_tree.root(),
        )?;
        assert!(product_sum(&altered.data, &altered.coefficients)?.abs() > 0.1);
        Ok(())
    }

    #[test]
    fn unauthenticated_endpoint_allows_a_root_disconnected_zero_table() -> Result<(), Box<dyn Error>>
    {
        let rows = 8;
        let columns = 8;
        let source_row = generate_source(rows * columns, rows * columns, 73)?;
        let code = RandomizedHadamardCode::new(columns, 79)?;
        let mut parity = code.encode_rows_to_columns(&source_row, rows)?;
        parity[0] += 1.0;
        let source = transpose_row_to_column(&source_row, rows, columns)?;
        let tree = build_column_tree(&source, &parity, rows, columns, 2 * columns)?;
        let tables =
            build_global_relation_tables(source, parity, rows, columns, &code.signs, &tree.root())?;
        assert!(product_sum(&tables.data, &tables.coefficients)?.abs() > 0.1);

        // The alleged sumcheck table is not linked to the committed root. A
        // malicious prover substitutes zeros while retaining the public
        // coefficient table derived from that root.
        let fake_data = vec![0.0; tables.data.len()];
        let mut prover_transcript = initialize_global_sumcheck_transcript(&tree.root(), 0.0);
        let (proof, endpoint) =
            prove_product_owned(fake_data, tables.coefficients, 0.0, |round, polynomial| {
                global_sumcheck_challenge(&mut prover_transcript, round, polynomial)
            })?;
        let mut verifier_transcript = initialize_global_sumcheck_transcript(&tree.root(), 0.0);
        let verification = verify_product(tables.data.len(), 0.0, &proof, |round, polynomial| {
            global_sumcheck_challenge(&mut verifier_transcript, round, polynomial)
        })?;
        let public_endpoint = evaluate_global_coefficient_endpoint(
            &verification.endpoint.point,
            rows,
            columns,
            &tables.row_weights,
            &tables.output_weights,
            &tables.source_weights,
        )?;
        let final_defect = verify_product_endpoint(
            &verification.endpoint,
            endpoint.left_evaluation,
            public_endpoint,
        )?;
        assert_eq!(endpoint.left_evaluation, 0.0);
        assert_eq!(final_defect.absolute_defect, 0.0);
        assert!(
            verification
                .round_defects
                .iter()
                .all(|defect| defect.absolute_defect == 0.0)
        );
        Ok(())
    }
}
