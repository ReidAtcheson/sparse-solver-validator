//! Throughput surrogate for a Brakedown-shaped binary64 metric commitment.
//!
//! The default mode deliberately implements no proof protocol and measures the
//! minimum data movement for a systematic sparse row encoding, a column Merkle
//! commitment, and one encoded row combination. `--residual-composition` adds
//! the two existing binary64 sumchecks and batches their terminal MLE claims
//! into one sampled-column opening. Neither mode instantiates a distance code
//! or makes a proximity or soundness claim.

#![forbid(unsafe_code)]

use std::error::Error;
use std::hint::black_box;
use std::io;
use std::time::{Duration, Instant};

use clap::Parser;
use ssv_fast::{
    ProductSumcheckProof, QuadraticBernstein, Transcript, canonical_bits,
    float_contract::canonicalize_arithmetic, product_sum, prove_product_owned, verify_product,
    verify_product_endpoint,
};
use ssv_problem::{
    BoundaryRule, GeneratedProblem, InstanceSeed, MatrixSpec, ProblemTemplate, RequestedOutput,
    RhsSpec, SuccinctPublicEvaluator, SymmetricDiaEdge, TemplateRandomness, TemplateSchema,
};

const LEAF_DOMAIN: &[u8] = b"ssv/research/brakedown-metric/column-leaf/v1";
const PADDING_DOMAIN: &[u8] = b"ssv/research/brakedown-metric/column-padding/v1";
const NODE_DOMAIN: &[u8] = b"ssv/research/brakedown-metric/column-node/v1";
const VALUES_PER_HASH_BLOCK: usize = 64;
const RESIDUAL_PROTOCOL_LABEL: &[u8] = b"ssv/research/brakedown-residual-composition/v1";

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

    /// Run the two-sumcheck residual composition over a generated sparse system.
    #[arg(long)]
    residual_composition: bool,

    /// Positive graph-Laplacian offsets used by residual-composition mode.
    #[arg(long, value_delimiter = ',', default_value = "1,32")]
    offsets: Vec<usize>,

    /// Candidate-solution perturbation is an integer multiple of 2^-bits.
    #[arg(long, default_value_t = 24)]
    perturbation_bits: u32,
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

        self.opening_at_indices(source, parity, rows, source_columns, &indices)
    }

    fn opening_at_indices(
        &self,
        source: &[f64],
        parity: &[f64],
        rows: usize,
        source_columns: usize,
        indices: &[usize],
    ) -> Result<NaiveOpening, io::Error> {
        if indices.is_empty()
            || indices.iter().any(|&index| index >= self.column_count)
            || indices.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(invalid(
                "opening indices must be nonempty, sorted, unique, and in range",
            ));
        }

        let value_count = indices
            .len()
            .checked_mul(rows)
            .ok_or_else(|| invalid("opened value count overflow"))?;
        let tree_height = self.padded_columns.ilog2() as usize;
        let authentication_count = indices
            .len()
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

        for &column_index in indices {
            values.extend_from_slice(column(source, parity, rows, source_columns, column_index));
            let mut node_index = self.padded_columns + column_index;
            while node_index > 1 {
                authentication.push(self.hashes[node_index ^ 1]);
                node_index /= 2;
            }
        }

        Ok(NaiveOpening {
            indices: indices.to_vec(),
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

#[derive(Clone, Debug)]
struct ResidualCompositionProof {
    residual_squared_l2: f64,
    norm_sumcheck: ProductSumcheckProof,
    residual_at_row_point: f64,
    matvec_sumcheck: ProductSumcheckProof,
    solution_at_column_point: f64,
    source_combinations: [Vec<f64>; 2],
    opening: NaiveOpening,
}

impl ResidualCompositionProof {
    fn payload_bytes(&self) -> Result<usize, io::Error> {
        let scalar_bytes = 3_usize
            .checked_mul(size_of::<f64>())
            .ok_or_else(|| invalid("proof scalar byte count overflow"))?;
        let sumcheck_rounds = self
            .norm_sumcheck
            .rounds
            .len()
            .checked_add(self.matvec_sumcheck.rounds.len())
            .ok_or_else(|| invalid("proof sumcheck round count overflow"))?;
        let sumcheck_bytes = sumcheck_rounds
            .checked_mul(3 * size_of::<f64>())
            .ok_or_else(|| invalid("proof sumcheck byte count overflow"))?;
        let combination_values = self
            .source_combinations
            .iter()
            .try_fold(0_usize, |total, combination| {
                total.checked_add(combination.len())
            })
            .ok_or_else(|| invalid("proof combination value count overflow"))?;
        let combination_bytes = combination_values
            .checked_mul(size_of::<f64>())
            .ok_or_else(|| invalid("proof combination byte count overflow"))?;
        let index_bytes = self
            .opening
            .indices
            .len()
            .checked_mul(size_of::<u64>())
            .ok_or_else(|| invalid("proof opening index byte count overflow"))?;
        let value_bytes = self
            .opening
            .values
            .len()
            .checked_mul(size_of::<f64>())
            .ok_or_else(|| invalid("proof opening value byte count overflow"))?;
        let authentication_bytes = self
            .opening
            .authentication
            .len()
            .checked_mul(size_of::<[u8; 32]>())
            .ok_or_else(|| invalid("proof authentication byte count overflow"))?;
        32_usize
            .checked_add(scalar_bytes)
            .and_then(|bytes| bytes.checked_add(sumcheck_bytes))
            .and_then(|bytes| bytes.checked_add(combination_bytes))
            .and_then(|bytes| bytes.checked_add(index_bytes))
            .and_then(|bytes| bytes.checked_add(value_bytes))
            .and_then(|bytes| bytes.checked_add(authentication_bytes))
            .ok_or_else(|| invalid("proof payload byte count overflow"))
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct ResidualCompositionMetrics {
    norm_sumcheck_maximum_absolute_defect: f64,
    matvec_sumcheck_maximum_absolute_defect: f64,
    residual_opening_absolute_defect: f64,
    solution_opening_absolute_defect: f64,
    queried_combination_maximum_absolute_defect: f64,
    public_matrix_forward_error_bound: f64,
    public_rhs_forward_error_bound: f64,
}

#[derive(Debug, Default)]
struct ResidualTimingSamples {
    residual: Vec<Duration>,
    packing: Vec<Duration>,
    encoding: Vec<Duration>,
    commitment: Vec<Duration>,
    norm_sumcheck: Vec<Duration>,
    matvec_compression: Vec<Duration>,
    matvec_sumcheck: Vec<Duration>,
    opening_combinations: Vec<Duration>,
    opening_extraction: Vec<Duration>,
    total: Vec<Duration>,
    verification: Vec<Duration>,
}

fn run_residual_composition(args: &Args) -> Result<(), Box<dyn Error>> {
    let padded_dimension = args
        .dimension
        .checked_next_power_of_two()
        .ok_or_else(|| invalid("dimension padding overflow"))?;
    let packed_dimension = padded_dimension
        .checked_mul(2)
        .ok_or_else(|| invalid("packed residual message length overflow"))?;
    let source_columns = packed_dimension / args.rows;
    let parity_columns = source_columns.div_ceil(args.parity_denominator);
    let code_seed = args.seed ^ 0x434f_4445_4752_4150;
    let code = SparseSystematicCode::new(source_columns, parity_columns, args.degree, code_seed)?;
    let encoded_columns = code.encoded_columns()?;
    if args.queries > encoded_columns {
        return Err(invalid("queries cannot exceed encoded columns").into());
    }

    let problem = generated_laplacian_problem(args.dimension, &args.offsets, args.seed)?;
    let solution = generate_candidate_solution(
        args.dimension,
        args.perturbation_bits,
        args.seed ^ 0x534f_4c55_5449_4f4e,
    )?;
    let mut samples = ResidualTimingSamples::default();
    let mut final_root = [0_u8; 32];
    let mut final_tree_bytes = 0_usize;
    let mut final_proof_bytes = 0_usize;
    let mut final_metrics = ResidualCompositionMetrics::default();
    let mut final_residual_squared_l2 = 0.0_f64;

    for repetition in 0..args.warmups + args.repetitions {
        let total_start = Instant::now();

        let start = Instant::now();
        let residual = compute_generated_residual(&problem, &solution)?;
        let residual_time = start.elapsed();

        let start = Instant::now();
        let source =
            pack_solution_and_residual(&solution, &residual, padded_dimension, packed_dimension)?;
        let packing = start.elapsed();

        let start = Instant::now();
        let parity = code.encode_rows(&source, args.rows)?;
        let encoding = start.elapsed();

        let start = Instant::now();
        let tree = build_column_tree(&source, &parity, args.rows, source_columns, encoded_columns)?;
        let commitment = start.elapsed();

        let mut transcript = initialize_residual_transcript(
            &problem,
            tree.root(),
            args.rows,
            &code,
            args.queries,
            code_seed,
        )?;

        let start = Instant::now();
        let residual_left = source[padded_dimension..].to_vec();
        let residual_right = residual_left.clone();
        let residual_squared_l2 =
            product_sum(&residual_left, &residual_right).map_err(calculation_error)?;
        absorb_float(
            &mut transcript,
            b"residual-squared-l2-claim",
            residual_squared_l2,
        )?;
        let (norm_sumcheck, norm_endpoint) = prove_product_owned(
            residual_left,
            residual_right,
            residual_squared_l2,
            |round, polynomial| {
                sumcheck_challenge(&mut transcript, b"residual-norm", round, polynomial)
            },
        )
        .map_err(calculation_error)?;
        let residual_at_row_point = norm_endpoint.left_evaluation;
        absorb_float(
            &mut transcript,
            b"residual-at-shared-row-point",
            residual_at_row_point,
        )?;
        let norm_sumcheck_time = start.elapsed();

        let rhs = problem
            .public_evaluation_plan()
            .evaluate_rhs_mle_f64(&norm_endpoint.point)
            .map_err(calculation_error)?;
        let matvec_initial_claim = canonical(rhs.value + residual_at_row_point)?;
        absorb_float(
            &mut transcript,
            b"matvec-initial-claim",
            matvec_initial_claim,
        )?;

        let start = Instant::now();
        let compressed_columns =
            prepare_compressed_columns(&problem, &norm_endpoint.point, padded_dimension)?;
        let padded_solution = source[..padded_dimension].to_vec();
        let matvec_compression = start.elapsed();

        let start = Instant::now();
        let (matvec_sumcheck, matvec_endpoint) = prove_product_owned(
            compressed_columns,
            padded_solution,
            matvec_initial_claim,
            |round, polynomial| {
                sumcheck_challenge(&mut transcript, b"matvec-product", round, polynomial)
            },
        )
        .map_err(calculation_error)?;
        let solution_at_column_point = matvec_endpoint.right_evaluation;
        absorb_float(
            &mut transcript,
            b"solution-at-column-point",
            solution_at_column_point,
        )?;
        let matvec_sumcheck_time = start.elapsed();

        let start = Instant::now();
        let solution_packed_point = packed_endpoint_point(0.0, &matvec_endpoint.point);
        let residual_packed_point = packed_endpoint_point(1.0, &norm_endpoint.point);
        let solution_combination = prepare_endpoint_combination(
            &source,
            &parity,
            args.rows,
            source_columns,
            encoded_columns,
            &solution_packed_point,
        )?;
        let residual_combination = prepare_endpoint_combination(
            &source,
            &parity,
            args.rows,
            source_columns,
            encoded_columns,
            &residual_packed_point,
        )?;
        let source_combinations = [solution_combination, residual_combination];
        absorb_combinations(&mut transcript, &source_combinations)?;
        let opening_combinations = start.elapsed();

        let start = Instant::now();
        let query_indices = derive_query_indices(&mut transcript, encoded_columns, args.queries)?;
        let opening =
            tree.opening_at_indices(&source, &parity, args.rows, source_columns, &query_indices)?;
        let opening_extraction = start.elapsed();
        let total = total_start.elapsed();

        let proof = ResidualCompositionProof {
            residual_squared_l2,
            norm_sumcheck,
            residual_at_row_point,
            matvec_sumcheck,
            solution_at_column_point,
            source_combinations,
            opening,
        };

        let start = Instant::now();
        let metrics = verify_residual_composition(
            &problem,
            &code,
            tree.root(),
            tree.padded_columns,
            args.rows,
            args.queries,
            code_seed,
            &proof,
        )?;
        let verification = start.elapsed();

        black_box(tree.root());
        black_box(proof.residual_squared_l2);
        black_box(metrics.queried_combination_maximum_absolute_defect);
        final_root = tree.root();
        final_tree_bytes = tree.bytes();
        final_proof_bytes = proof.payload_bytes()?;
        final_metrics = metrics;
        final_residual_squared_l2 = proof.residual_squared_l2;

        if repetition >= args.warmups {
            samples.residual.push(residual_time);
            samples.packing.push(packing);
            samples.encoding.push(encoding);
            samples.commitment.push(commitment);
            samples.norm_sumcheck.push(norm_sumcheck_time);
            samples.matvec_compression.push(matvec_compression);
            samples.matvec_sumcheck.push(matvec_sumcheck_time);
            samples.opening_combinations.push(opening_combinations);
            samples.opening_extraction.push(opening_extraction);
            samples.total.push(total);
            samples.verification.push(verification);
        }
    }

    let raw_solution_bytes = args.dimension * size_of::<f64>();
    let source_bytes = packed_dimension * size_of::<f64>();
    let parity_bytes = args.rows * parity_columns * size_of::<f64>();
    let (minimum_single_source_weight, maximum_single_source_weight) =
        single_source_encoded_weight_range(&code)?;
    let single_source_query_miss_probability = without_replacement_miss_probability(
        encoded_columns,
        minimum_single_source_weight,
        args.queries,
    )?;
    println!("status=two-sumcheck-composition-with-assumed-code-proximity");
    println!("logical_dimension={}", args.dimension);
    println!("padded_dimension={padded_dimension}");
    println!("structural_nnz={}", problem.structural_nnz());
    println!("offsets={:?}", args.offsets);
    println!("rows={}", args.rows);
    println!("source_columns={source_columns}");
    println!("parity_columns={parity_columns}");
    println!("encoded_columns={encoded_columns}");
    println!("degree={}", args.degree);
    println!("queries={}", args.queries);
    println!("minimum_single_source_encoded_weight={minimum_single_source_weight}");
    println!("maximum_single_source_encoded_weight={maximum_single_source_weight}");
    println!(
        "minimum_weight_single_source_query_miss_probability={single_source_query_miss_probability:.17e}"
    );
    println!("raw_solution_bytes={raw_solution_bytes}");
    println!("source_bytes={source_bytes}");
    println!("parity_bytes={parity_bytes}");
    println!("retained_tree_bytes={final_tree_bytes}");
    println!("estimated_proof_bytes={final_proof_bytes}");
    println!(
        "proof_to_raw_solution_ratio={:.9}",
        final_proof_bytes as f64 / raw_solution_bytes as f64
    );
    println!("root={}", blake3::Hash::from_bytes(final_root).to_hex());
    println!("residual_squared_l2={final_residual_squared_l2:.17e}");
    println!(
        "norm_sumcheck_maximum_absolute_defect={:.17e}",
        final_metrics.norm_sumcheck_maximum_absolute_defect
    );
    println!(
        "matvec_sumcheck_maximum_absolute_defect={:.17e}",
        final_metrics.matvec_sumcheck_maximum_absolute_defect
    );
    println!(
        "residual_opening_absolute_defect={:.17e}",
        final_metrics.residual_opening_absolute_defect
    );
    println!(
        "solution_opening_absolute_defect={:.17e}",
        final_metrics.solution_opening_absolute_defect
    );
    println!(
        "queried_combination_maximum_absolute_defect={:.17e}",
        final_metrics.queried_combination_maximum_absolute_defect
    );
    println!(
        "public_matrix_forward_error_bound={:.17e}",
        final_metrics.public_matrix_forward_error_bound
    );
    println!(
        "public_rhs_forward_error_bound={:.17e}",
        final_metrics.public_rhs_forward_error_bound
    );
    print_timing("residual", &mut samples.residual);
    print_timing("packing", &mut samples.packing);
    print_timing("encoding", &mut samples.encoding);
    print_timing("commitment", &mut samples.commitment);
    print_timing("norm_sumcheck", &mut samples.norm_sumcheck);
    print_timing("matvec_compression", &mut samples.matvec_compression);
    print_timing("matvec_sumcheck", &mut samples.matvec_sumcheck);
    print_timing("opening_combinations", &mut samples.opening_combinations);
    print_timing("opening_extraction", &mut samples.opening_extraction);
    print_timing("total", &mut samples.total);
    print_timing("verification", &mut samples.verification);
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    validate_args(&args)?;
    if args.residual_composition {
        return run_residual_composition(&args);
    }

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
    if args.perturbation_bits > 52 {
        return Err(invalid("perturbation-bits cannot exceed 52"));
    }
    if args.residual_composition {
        if args.offsets.is_empty() || args.offsets.len() > 16 {
            return Err(invalid(
                "residual composition needs between one and sixteen offsets",
            ));
        }
        if args.offsets.windows(2).any(|pair| pair[0] >= pair[1])
            || args
                .offsets
                .iter()
                .any(|&offset| offset == 0 || offset >= args.dimension)
        {
            return Err(invalid(
                "offsets must be strictly increasing, positive, and below dimension",
            ));
        }
        let padded = args
            .dimension
            .checked_next_power_of_two()
            .ok_or_else(|| invalid("dimension padding overflow"))?;
        let message_len = padded
            .checked_mul(2)
            .ok_or_else(|| invalid("packed residual message length overflow"))?;
        if args.rows > message_len || message_len % args.rows != 0 {
            return Err(invalid(
                "rows must divide the power-of-two packed residual message length",
            ));
        }
    }
    Ok(())
}

fn generated_laplacian_problem(
    dimension: usize,
    offsets: &[usize],
    seed: u64,
) -> Result<GeneratedProblem, io::Error> {
    let edge_diagonals = offsets
        .iter()
        .copied()
        .map(|offset| {
            Ok(SymmetricDiaEdge {
                positive_offset: u64::try_from(offset)
                    .map_err(|_| invalid("offset does not fit in u64"))?,
                period_bits: 8,
                minimum_weight_mantissa: 1,
                maximum_weight_mantissa: 3,
            })
        })
        .collect::<Result<Vec<_>, io::Error>>()?;
    ProblemTemplate {
        schema: TemplateSchema::V1,
        randomness: TemplateRandomness::LiteralV1 {
            seed: InstanceSeed::from_bytes(expand_seed(seed)),
        },
        matrix: MatrixSpec::SeededSymmetricDiaLaplacianV1 {
            dimension: u64::try_from(dimension)
                .map_err(|_| invalid("dimension does not fit in u64"))?,
            boundary: BoundaryRule::TruncateV1,
            fractional_bits: 8,
            diagonal_shift_mantissa: 256,
            edge_diagonals,
        },
        rhs: RhsSpec::ManufacturedOnesV1,
        requested_outputs: vec![RequestedOutput::SquaredL2ResidualV1],
    }
    .finalize_literal()
    .and_then(|problem| problem.compile())
    .map_err(calculation_error)
}

fn expand_seed(seed: u64) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    let mut state = seed;
    for chunk in bytes.chunks_exact_mut(size_of::<u64>()) {
        chunk.copy_from_slice(&splitmix64(&mut state).to_le_bytes());
    }
    bytes
}

fn generate_candidate_solution(
    dimension: usize,
    perturbation_bits: u32,
    seed: u64,
) -> Result<Vec<f64>, io::Error> {
    let exponent = i32::try_from(perturbation_bits)
        .map_err(|_| invalid("perturbation exponent does not fit in i32"))?;
    let unit = 2.0_f64.powi(-exponent);
    let mut state = seed;
    let mut solution = Vec::new();
    solution
        .try_reserve_exact(dimension)
        .map_err(|_| invalid("could not allocate candidate solution"))?;
    for _ in 0..dimension {
        let signed_step = (splitmix64(&mut state) % 5) as i32 - 2;
        solution.push(canonical(1.0 + f64::from(signed_step) * unit)?);
    }
    Ok(solution)
}

fn compute_generated_residual(
    problem: &GeneratedProblem,
    solution: &[f64],
) -> Result<Vec<f64>, io::Error> {
    if solution.len() != problem.dimension() {
        return Err(invalid(
            "solution length does not match the generated problem",
        ));
    }
    let mut residual = Vec::new();
    residual
        .try_reserve_exact(problem.dimension())
        .map_err(|_| invalid("could not allocate residual"))?;
    for row in 0..problem.dimension() {
        let mut dot_product = 0.0_f64;
        for entry in problem
            .row(row)
            .ok_or_else(|| invalid("generated matrix row is missing"))?
        {
            let product = canonical(entry.value.to_f64() * solution[entry.column])?;
            dot_product = canonical(dot_product + product)?;
        }
        let rhs = problem
            .rhs_f64(row)
            .ok_or_else(|| invalid("generated RHS entry is missing"))?;
        residual.push(canonical(dot_product - rhs)?);
    }
    Ok(residual)
}

fn pack_solution_and_residual(
    solution: &[f64],
    residual: &[f64],
    padded_dimension: usize,
    packed_dimension: usize,
) -> Result<Vec<f64>, io::Error> {
    if solution.len() != residual.len()
        || solution.len() > padded_dimension
        || packed_dimension != 2 * padded_dimension
    {
        return Err(invalid("solution/residual packing shape is invalid"));
    }
    let mut source = Vec::new();
    source
        .try_reserve_exact(packed_dimension)
        .map_err(|_| invalid("could not allocate packed source"))?;
    source.resize(packed_dimension, 0.0);
    source[..solution.len()].copy_from_slice(solution);
    source[padded_dimension..padded_dimension + residual.len()].copy_from_slice(residual);
    Ok(source)
}

fn prepare_compressed_columns(
    problem: &GeneratedProblem,
    row_point: &[f64],
    padded_dimension: usize,
) -> Result<Vec<f64>, io::Error> {
    if row_point.len() != padded_dimension.ilog2() as usize {
        return Err(invalid("row-compression point has the wrong dimension"));
    }
    let row_weights = equality_table(row_point)?;
    let mut compressed_columns = Vec::new();
    compressed_columns
        .try_reserve_exact(padded_dimension)
        .map_err(|_| invalid("could not allocate compressed columns"))?;
    compressed_columns.resize(padded_dimension, 0.0);
    for (row, &weight) in row_weights.iter().take(problem.dimension()).enumerate() {
        for entry in problem
            .row(row)
            .ok_or_else(|| invalid("generated matrix row is missing"))?
        {
            let contribution = canonical(weight * entry.value.to_f64())?;
            compressed_columns[entry.column] =
                canonical(compressed_columns[entry.column] + contribution)?;
        }
    }
    Ok(compressed_columns)
}

fn initialize_residual_transcript(
    problem: &GeneratedProblem,
    root: [u8; 32],
    rows: usize,
    code: &SparseSystematicCode,
    queries: usize,
    code_seed: u64,
) -> Result<Transcript, io::Error> {
    let mut transcript = Transcript::new(RESIDUAL_PROTOCOL_LABEL);
    transcript.absorb_bytes(b"problem-digest", problem.problem_digest().as_bytes());
    transcript.absorb_u64(
        b"logical-dimension",
        u64::try_from(problem.dimension())
            .map_err(|_| invalid("dimension does not fit in transcript"))?,
    );
    transcript.absorb_u64(
        b"commitment-rows",
        u64::try_from(rows).map_err(|_| invalid("row count does not fit in transcript"))?,
    );
    transcript.absorb_u64(
        b"source-columns",
        u64::try_from(code.source_columns)
            .map_err(|_| invalid("source width does not fit in transcript"))?,
    );
    transcript.absorb_u64(
        b"parity-columns",
        u64::try_from(code.parity_columns)
            .map_err(|_| invalid("parity width does not fit in transcript"))?,
    );
    transcript.absorb_u64(
        b"code-degree",
        u64::try_from(code.degree)
            .map_err(|_| invalid("code degree does not fit in transcript"))?,
    );
    transcript.absorb_u64(b"code-seed", code_seed);
    transcript.absorb_u64(
        b"column-queries",
        u64::try_from(queries).map_err(|_| invalid("query count does not fit in transcript"))?,
    );
    transcript.absorb_root(b"encoded-column-root", &root);
    Ok(transcript)
}

fn sumcheck_challenge(
    transcript: &mut Transcript,
    phase: &[u8],
    round: usize,
    polynomial: &QuadraticBernstein,
) -> f64 {
    transcript.absorb_bytes(b"sumcheck-phase", phase);
    transcript.absorb_u64(b"sumcheck-round", round as u64);
    for &coefficient in &polynomial.coefficients {
        transcript.absorb_u64(b"sumcheck-bernstein-coefficient", coefficient.to_bits());
    }
    transcript
        .challenge_dyadic_f64(b"sumcheck-challenge")
        .expect("the bounded research transcript cannot exhaust its challenge counter")
}

fn absorb_float(transcript: &mut Transcript, tag: &[u8], value: f64) -> Result<(), io::Error> {
    transcript.absorb_u64(tag, canonical_bits(value).map_err(calculation_error)?);
    Ok(())
}

fn canonical(value: f64) -> Result<f64, io::Error> {
    canonicalize_arithmetic(value).map_err(calculation_error)
}

fn equality_table(point: &[f64]) -> Result<Vec<f64>, io::Error> {
    let final_len = 1_usize
        .checked_shl(
            u32::try_from(point.len())
                .map_err(|_| invalid("MLE point dimension does not fit in u32"))?,
        )
        .ok_or_else(|| invalid("equality-table length overflow"))?;
    let mut table = Vec::new();
    table
        .try_reserve_exact(final_len)
        .map_err(|_| invalid("could not allocate equality table"))?;
    table.resize(final_len, 0.0);
    table[0] = 1.0;
    let mut active_len = 1_usize;
    for &coordinate in point {
        for index in (0..active_len).rev() {
            let weight = table[index];
            table[2 * index] = canonical(weight * (1.0 - coordinate))?;
            table[2 * index + 1] = canonical(weight * coordinate)?;
        }
        active_len = active_len
            .checked_mul(2)
            .ok_or_else(|| invalid("equality-table expansion overflow"))?;
    }
    Ok(table)
}

fn packed_endpoint_point(selector: f64, table_point: &[f64]) -> Vec<f64> {
    let mut point = Vec::with_capacity(table_point.len() + 1);
    point.push(selector);
    point.extend_from_slice(table_point);
    point
}

fn split_commitment_point(
    point: &[f64],
    rows: usize,
    source_columns: usize,
) -> Result<(&[f64], &[f64]), io::Error> {
    let row_variables = rows.ilog2() as usize;
    let column_variables = source_columns.ilog2() as usize;
    if point.len() != row_variables + column_variables {
        return Err(invalid("packed MLE point does not match commitment shape"));
    }
    Ok(point.split_at(column_variables))
}

fn prepare_endpoint_combination(
    source: &[f64],
    parity: &[f64],
    rows: usize,
    source_columns: usize,
    encoded_columns: usize,
    packed_point: &[f64],
) -> Result<Vec<f64>, io::Error> {
    let (_, row_point) = split_commitment_point(packed_point, rows, source_columns)?;
    let row_weights = equality_table(row_point)?;
    let encoded_combination = combine_columns(
        source,
        parity,
        rows,
        source_columns,
        encoded_columns,
        &row_weights,
    )?;
    Ok(encoded_combination[..source_columns].to_vec())
}

fn absorb_combinations(
    transcript: &mut Transcript,
    combinations: &[Vec<f64>; 2],
) -> Result<(), io::Error> {
    for (index, combination) in combinations.iter().enumerate() {
        let byte_len = combination
            .len()
            .checked_mul(size_of::<f64>())
            .ok_or_else(|| invalid("combination serialization length overflow"))?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(byte_len)
            .map_err(|_| invalid("could not allocate combination serialization"))?;
        for &value in combination {
            bytes.extend_from_slice(
                &canonical_bits(value)
                    .map_err(calculation_error)?
                    .to_le_bytes(),
            );
        }
        transcript.absorb_u64(b"opening-combination-index", index as u64);
        transcript.absorb_bytes(b"opening-source-combination", &bytes);
    }
    Ok(())
}

fn derive_query_indices(
    transcript: &mut Transcript,
    encoded_columns: usize,
    queries: usize,
) -> Result<Vec<usize>, io::Error> {
    if queries == 0 || queries > encoded_columns {
        return Err(invalid("query count is outside the encoded-column domain"));
    }
    let mut indices = Vec::new();
    indices
        .try_reserve_exact(queries)
        .map_err(|_| invalid("could not allocate query indices"))?;
    while indices.len() < queries {
        let index = transcript
            .challenge_usize(b"encoded-column-query", encoded_columns)
            .map_err(calculation_error)?;
        if !indices.contains(&index) {
            indices.push(index);
        }
    }
    indices.sort_unstable();
    Ok(indices)
}

fn single_source_encoded_weight_range(
    code: &SparseSystematicCode,
) -> Result<(usize, usize), io::Error> {
    let mut weights = Vec::new();
    weights
        .try_reserve_exact(code.source_columns)
        .map_err(|_| invalid("could not allocate source-column weights"))?;
    weights.resize(code.source_columns, 1_usize);
    for &neighbor in &code.neighbors {
        weights[neighbor] = weights[neighbor]
            .checked_add(1)
            .ok_or_else(|| invalid("source-column encoded weight overflow"))?;
    }
    let minimum = weights
        .iter()
        .copied()
        .min()
        .ok_or_else(|| invalid("source-column weight set is empty"))?;
    let maximum = weights
        .iter()
        .copied()
        .max()
        .ok_or_else(|| invalid("source-column weight set is empty"))?;
    Ok((minimum, maximum))
}

fn without_replacement_miss_probability(
    population: usize,
    bad_items: usize,
    queries: usize,
) -> Result<f64, io::Error> {
    if bad_items > population || queries > population {
        return Err(invalid("miss-probability parameters are out of range"));
    }
    if queries > population - bad_items {
        return Ok(0.0);
    }
    let mut probability = 1.0_f64;
    for query in 0..queries {
        probability *= (population - bad_items - query) as f64 / (population - query) as f64;
    }
    Ok(probability)
}

#[allow(clippy::too_many_arguments)]
fn verify_residual_composition(
    problem: &GeneratedProblem,
    code: &SparseSystematicCode,
    root: [u8; 32],
    padded_columns: usize,
    rows: usize,
    queries: usize,
    code_seed: u64,
    proof: &ResidualCompositionProof,
) -> Result<ResidualCompositionMetrics, io::Error> {
    let encoded_columns = code.encoded_columns()?;
    if padded_columns != encoded_columns.next_power_of_two() {
        return Err(invalid(
            "committed tree padding does not match the code width",
        ));
    }
    let padded_dimension = problem.dimension().next_power_of_two();
    let mut transcript =
        initialize_residual_transcript(problem, root, rows, code, queries, code_seed)?;

    absorb_float(
        &mut transcript,
        b"residual-squared-l2-claim",
        proof.residual_squared_l2,
    )?;
    let norm = verify_product(
        padded_dimension,
        proof.residual_squared_l2,
        &proof.norm_sumcheck,
        |round, polynomial| {
            sumcheck_challenge(&mut transcript, b"residual-norm", round, polynomial)
        },
    )
    .map_err(calculation_error)?;
    absorb_float(
        &mut transcript,
        b"residual-at-shared-row-point",
        proof.residual_at_row_point,
    )?;
    let norm_endpoint = verify_product_endpoint(
        &norm.endpoint,
        proof.residual_at_row_point,
        proof.residual_at_row_point,
    )
    .map_err(calculation_error)?;

    let rhs = problem
        .public_evaluation_plan()
        .evaluate_rhs_mle_f64(&norm.endpoint.point)
        .map_err(calculation_error)?;
    let matvec_initial_claim = canonical(rhs.value + proof.residual_at_row_point)?;
    absorb_float(
        &mut transcript,
        b"matvec-initial-claim",
        matvec_initial_claim,
    )?;
    let matvec = verify_product(
        padded_dimension,
        matvec_initial_claim,
        &proof.matvec_sumcheck,
        |round, polynomial| {
            sumcheck_challenge(&mut transcript, b"matvec-product", round, polynomial)
        },
    )
    .map_err(calculation_error)?;
    absorb_float(
        &mut transcript,
        b"solution-at-column-point",
        proof.solution_at_column_point,
    )?;
    let matrix = problem
        .public_evaluation_plan()
        .evaluate_matrix_mle_f64(&norm.endpoint.point, &matvec.endpoint.point)
        .map_err(calculation_error)?;
    let matvec_endpoint = verify_product_endpoint(
        &matvec.endpoint,
        matrix.value,
        proof.solution_at_column_point,
    )
    .map_err(calculation_error)?;

    let solution_packed_point = packed_endpoint_point(0.0, &matvec.endpoint.point);
    let residual_packed_point = packed_endpoint_point(1.0, &norm.endpoint.point);
    absorb_combinations(&mut transcript, &proof.source_combinations)?;
    let expected_queries = derive_query_indices(&mut transcript, encoded_columns, queries)?;
    if proof.opening.indices != expected_queries {
        return Err(invalid(
            "opening indices do not match transcript-derived queries",
        ));
    }

    let queried_combination_maximum_absolute_defect = verify_batched_opening(
        root,
        padded_columns,
        encoded_columns,
        rows,
        code,
        [&solution_packed_point, &residual_packed_point],
        &proof.source_combinations,
        &proof.opening,
    )?;

    let (solution_column_point, _) =
        split_commitment_point(&solution_packed_point, rows, code.source_columns)?;
    let (residual_column_point, _) =
        split_commitment_point(&residual_packed_point, rows, code.source_columns)?;
    let opened_solution = dot(
        &proof.source_combinations[0],
        &equality_table(solution_column_point)?,
    )?;
    let opened_residual = dot(
        &proof.source_combinations[1],
        &equality_table(residual_column_point)?,
    )?;

    let norm_sumcheck_maximum_absolute_defect = norm
        .round_defects
        .iter()
        .map(|observation| observation.absolute_defect)
        .fold(norm_endpoint.absolute_defect, f64::max);
    let matvec_sumcheck_maximum_absolute_defect = matvec
        .round_defects
        .iter()
        .map(|observation| observation.absolute_defect)
        .fold(matvec_endpoint.absolute_defect, f64::max);

    Ok(ResidualCompositionMetrics {
        norm_sumcheck_maximum_absolute_defect,
        matvec_sumcheck_maximum_absolute_defect,
        residual_opening_absolute_defect: (opened_residual - proof.residual_at_row_point).abs(),
        solution_opening_absolute_defect: (opened_solution - proof.solution_at_column_point).abs(),
        queried_combination_maximum_absolute_defect,
        public_matrix_forward_error_bound: matrix.roundoff.forward_absolute_error_bound,
        public_rhs_forward_error_bound: rhs.roundoff.forward_absolute_error_bound,
    })
}

#[allow(clippy::too_many_arguments)]
fn verify_batched_opening(
    root: [u8; 32],
    padded_columns: usize,
    encoded_columns: usize,
    rows: usize,
    code: &SparseSystematicCode,
    packed_points: [&[f64]; 2],
    source_combinations: &[Vec<f64>; 2],
    opening: &NaiveOpening,
) -> Result<f64, io::Error> {
    let tree_height = padded_columns.ilog2() as usize;
    let expected_values = opening
        .indices
        .len()
        .checked_mul(rows)
        .ok_or_else(|| invalid("opened value shape overflow"))?;
    let expected_authentication = opening
        .indices
        .len()
        .checked_mul(tree_height)
        .ok_or_else(|| invalid("opening authentication shape overflow"))?;
    if opening.indices.is_empty()
        || opening.indices.windows(2).any(|pair| pair[0] >= pair[1])
        || opening
            .indices
            .iter()
            .any(|&index| index >= encoded_columns)
        || opening.values.len() != expected_values
        || opening.authentication.len() != expected_authentication
        || source_combinations
            .iter()
            .any(|combination| combination.len() != code.source_columns)
    {
        return Err(invalid("batched opening shape is invalid"));
    }

    let mut row_weights = Vec::with_capacity(2);
    let mut combined_parity = Vec::with_capacity(2);
    for (packed_point, source_combination) in packed_points.iter().zip(source_combinations) {
        let (_, row_point) = split_commitment_point(packed_point, rows, code.source_columns)?;
        row_weights.push(equality_table(row_point)?);
        combined_parity.push(code.encode_vector(source_combination)?);
    }

    let mut maximum_absolute_defect = 0.0_f64;
    for (query, &column_index) in opening.indices.iter().enumerate() {
        let values = &opening.values[query * rows..(query + 1) * rows];
        let path = &opening.authentication[query * tree_height..(query + 1) * tree_height];
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
        if hash != root {
            return Err(invalid(
                "batched opening authentication path does not match the root",
            ));
        }

        for endpoint in 0..2 {
            let actual = dot(values, &row_weights[endpoint])?;
            let expected = if column_index < code.source_columns {
                source_combinations[endpoint][column_index]
            } else {
                combined_parity[endpoint]
                    .get(column_index - code.source_columns)
                    .copied()
                    .ok_or_else(|| invalid("opened parity column is out of range"))?
            };
            maximum_absolute_defect = maximum_absolute_defect.max((actual - expected).abs());
        }
    }
    Ok(maximum_absolute_defect)
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

fn calculation_error(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(error.to_string())
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

    #[test]
    fn sparse_surrogate_exposes_its_single_coordinate_escape_rate() -> Result<(), Box<dyn Error>> {
        let code = SparseSystematicCode::new(4096, 2048, 4, 29)?;
        let (minimum_weight, maximum_weight) = single_source_encoded_weight_range(&code)?;
        let miss = without_replacement_miss_probability(6144, minimum_weight, 16)?;
        assert!(minimum_weight < maximum_weight);
        assert!(miss > 0.98);
        Ok(())
    }

    #[test]
    fn residual_composition_replays_and_binds_terminal_claims() -> Result<(), Box<dyn Error>> {
        let dimension = 128;
        let rows = 16;
        let queries = 8;
        let seed = 0x1234_5678_9abc_def0;
        let code_seed = seed ^ 0x434f_4445_4752_4150;
        let problem = generated_laplacian_problem(dimension, &[1, 32], seed)?;
        let solution = generate_candidate_solution(dimension, 24, seed ^ 7)?;
        let padded_dimension = dimension.next_power_of_two();
        let packed_dimension = 2 * padded_dimension;
        let source_columns = packed_dimension / rows;
        let code = SparseSystematicCode::new(source_columns, source_columns / 2, 4, code_seed)?;
        let encoded_columns = code.encoded_columns()?;
        let residual = compute_generated_residual(&problem, &solution)?;
        let source =
            pack_solution_and_residual(&solution, &residual, padded_dimension, packed_dimension)?;
        let parity = code.encode_rows(&source, rows)?;
        let tree = build_column_tree(&source, &parity, rows, source_columns, encoded_columns)?;
        let mut transcript =
            initialize_residual_transcript(&problem, tree.root(), rows, &code, queries, code_seed)?;

        let residual_left = source[padded_dimension..].to_vec();
        let residual_right = residual_left.clone();
        let residual_squared_l2 = product_sum(&residual_left, &residual_right)?;
        absorb_float(
            &mut transcript,
            b"residual-squared-l2-claim",
            residual_squared_l2,
        )?;
        let (norm_sumcheck, norm_endpoint) = prove_product_owned(
            residual_left,
            residual_right,
            residual_squared_l2,
            |round, polynomial| {
                sumcheck_challenge(&mut transcript, b"residual-norm", round, polynomial)
            },
        )?;
        let residual_at_row_point = norm_endpoint.left_evaluation;
        absorb_float(
            &mut transcript,
            b"residual-at-shared-row-point",
            residual_at_row_point,
        )?;
        let rhs = problem
            .public_evaluation_plan()
            .evaluate_rhs_mle_f64(&norm_endpoint.point)?;
        let matvec_initial_claim = canonical(rhs.value + residual_at_row_point)?;
        absorb_float(
            &mut transcript,
            b"matvec-initial-claim",
            matvec_initial_claim,
        )?;
        let compressed =
            prepare_compressed_columns(&problem, &norm_endpoint.point, padded_dimension)?;
        let (matvec_sumcheck, matvec_endpoint) = prove_product_owned(
            compressed,
            source[..padded_dimension].to_vec(),
            matvec_initial_claim,
            |round, polynomial| {
                sumcheck_challenge(&mut transcript, b"matvec-product", round, polynomial)
            },
        )?;
        let solution_at_column_point = matvec_endpoint.right_evaluation;
        absorb_float(
            &mut transcript,
            b"solution-at-column-point",
            solution_at_column_point,
        )?;
        let solution_point = packed_endpoint_point(0.0, &matvec_endpoint.point);
        let residual_point = packed_endpoint_point(1.0, &norm_endpoint.point);
        let source_combinations = [
            prepare_endpoint_combination(
                &source,
                &parity,
                rows,
                source_columns,
                encoded_columns,
                &solution_point,
            )?,
            prepare_endpoint_combination(
                &source,
                &parity,
                rows,
                source_columns,
                encoded_columns,
                &residual_point,
            )?,
        ];
        absorb_combinations(&mut transcript, &source_combinations)?;
        let indices = derive_query_indices(&mut transcript, encoded_columns, queries)?;
        let opening = tree.opening_at_indices(&source, &parity, rows, source_columns, &indices)?;
        let proof = ResidualCompositionProof {
            residual_squared_l2,
            norm_sumcheck,
            residual_at_row_point,
            matvec_sumcheck,
            solution_at_column_point,
            source_combinations,
            opening,
        };

        let metrics = verify_residual_composition(
            &problem,
            &code,
            tree.root(),
            tree.padded_columns,
            rows,
            queries,
            code_seed,
            &proof,
        )?;
        assert!(metrics.norm_sumcheck_maximum_absolute_defect.is_finite());
        assert!(metrics.matvec_sumcheck_maximum_absolute_defect.is_finite());
        assert!(metrics.residual_opening_absolute_defect.is_finite());
        assert!(metrics.solution_opening_absolute_defect.is_finite());

        let mut changed_endpoint = proof.clone();
        changed_endpoint.solution_at_column_point =
            f64::from_bits(changed_endpoint.solution_at_column_point.to_bits() ^ 1);
        assert!(
            verify_residual_composition(
                &problem,
                &code,
                tree.root(),
                tree.padded_columns,
                rows,
                queries,
                code_seed,
                &changed_endpoint,
            )
            .is_err()
        );

        let mut changed_path = proof;
        changed_path.opening.authentication[0][0] ^= 1;
        assert!(
            verify_residual_composition(
                &problem,
                &code,
                tree.root(),
                tree.padded_columns,
                rows,
                queries,
                code_seed,
                &changed_path,
            )
            .is_err()
        );
        Ok(())
    }
}
