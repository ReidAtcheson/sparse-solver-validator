use std::iter::FusedIterator;

use blake3::OutputReader;

use crate::{
    BoundaryRule, Dyadic, FinalizedProblem, InstanceSeed, MatrixSpec, ProblemDigest, ProblemError,
    RhsSpec, derive_subseed,
};

const MATRIX_VALUES_LABEL: &str = "matrix/seeded-symmetric-tridiagonal-v1/off-diagonal-values";
const RHS_VALUES_LABEL: &str = "rhs/seeded-periodic-dyadic-v1/values";
const UNBIASED_STREAM_CONTEXT: &str = "sparse-solve/unbiased-u64-stream/v1";

/// One sorted structural matrix entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MatrixEntry {
    pub column: usize,
    pub value: Dyadic,
}

/// Reviewed bounds and structural facts derived from the registered generator.
///
/// This object is never accepted from JSON. It is recomputed while compiling
/// the finalized problem.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GeneratorCertificate {
    pub dimension: usize,
    pub structural_nonzeros: usize,
    pub maximum_nonzeros_per_row: u8,
    pub matrix_period: usize,
    pub coefficient_fractional_bits: u8,
    pub minimum_off_diagonal_magnitude_mantissa: u64,
    pub maximum_off_diagonal_magnitude_mantissa: u64,
    pub maximum_diagonal_mantissa_bound: u64,
    pub maximum_absolute_row_sum_mantissa_bound: u64,
    pub maximum_absolute_column_sum_mantissa_bound: u64,
    pub strict_diagonal_dominance_margin_mantissa: u64,
    pub rhs_period: usize,
    pub rhs_fractional_bits: u8,
    pub maximum_absolute_rhs_mantissa: u64,
    pub symmetric: bool,
    pub positive_diagonal: bool,
    pub nonpositive_off_diagonal: bool,
    pub strictly_row_diagonally_dominant: bool,
    pub nonsingular_m_matrix: bool,
    pub boundary: BoundaryRule,
}

/// Random-access sparse matrix interface used by both streaming provers and validators.
pub trait SparseMatrix {
    type Row<'a>: ExactSizeIterator<Item = MatrixEntry> + FusedIterator
    where
        Self: 'a;

    fn dimension(&self) -> usize;
    fn structural_nonzeros(&self) -> usize;
    fn row(&self, row: usize) -> Option<Self::Row<'_>>;
}

/// A validated, compiled problem backed only by bounded periodic tables.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedProblem {
    problem_digest: ProblemDigest,
    instance_seed: InstanceSeed,
    matrix: PeriodicSymmetricTridiagonal,
    rhs: GeneratedRhs,
    certificate: GeneratorCertificate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PeriodicSymmetricTridiagonal {
    dimension: usize,
    fractional_bits: u8,
    margin_mantissa: u64,
    /// Negative mantissas for edges `(i, i + 1)`, indexed by `i mod period`.
    off_diagonal_mantissas: Box<[i64]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum GeneratedRhs {
    ManufacturedOnes {
        dimension: usize,
        value: Dyadic,
    },
    SeededPeriodic {
        dimension: usize,
        fractional_bits: u8,
        mantissas: Box<[i64]>,
    },
}

/// Allocation-free, sorted iterator containing at most three entries.
#[derive(Clone, Debug)]
pub struct MatrixRow {
    entries: [MatrixEntry; 3],
    front: u8,
    back: u8,
}

impl MatrixRow {
    fn new(matrix: &PeriodicSymmetricTridiagonal, row: usize) -> Self {
        let empty = MatrixEntry {
            column: 0,
            value: Dyadic::new(0, matrix.fractional_bits),
        };
        let mut entries = [empty; 3];
        let mut len = 0_usize;
        let mut diagonal_mantissa = matrix.margin_mantissa;

        if row > 0 {
            let value = matrix.edge_mantissa(row - 1);
            diagonal_mantissa += value.unsigned_abs();
            entries[len] = MatrixEntry {
                column: row - 1,
                value: Dyadic::new(value, matrix.fractional_bits),
            };
            len += 1;
        }

        if row + 1 < matrix.dimension {
            diagonal_mantissa += matrix.edge_mantissa(row).unsigned_abs();
        }
        entries[len] = MatrixEntry {
            column: row,
            value: Dyadic::new(
                i64::try_from(diagonal_mantissa).expect("validated diagonal fits i64"),
                matrix.fractional_bits,
            ),
        };
        len += 1;

        if row + 1 < matrix.dimension {
            entries[len] = MatrixEntry {
                column: row + 1,
                value: Dyadic::new(matrix.edge_mantissa(row), matrix.fractional_bits),
            };
            len += 1;
        }

        Self {
            entries,
            front: 0,
            back: len as u8,
        }
    }
}

impl Iterator for MatrixRow {
    type Item = MatrixEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if self.front == self.back {
            return None;
        }
        let entry = self.entries[usize::from(self.front)];
        self.front += 1;
        Some(entry)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.len();
        (len, Some(len))
    }
}

impl DoubleEndedIterator for MatrixRow {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.front == self.back {
            return None;
        }
        self.back -= 1;
        Some(self.entries[usize::from(self.back)])
    }
}

impl ExactSizeIterator for MatrixRow {
    fn len(&self) -> usize {
        usize::from(self.back - self.front)
    }
}

impl FusedIterator for MatrixRow {}

/// Sequential row view that retains the same allocation-free row representation.
#[derive(Clone, Debug)]
pub struct MatrixRows<'a> {
    matrix: &'a PeriodicSymmetricTridiagonal,
    next: usize,
}

impl Iterator for MatrixRows<'_> {
    type Item = MatrixRow;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next == self.matrix.dimension {
            return None;
        }
        let row = self.next;
        self.next += 1;
        Some(MatrixRow::new(self.matrix, row))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.len();
        (len, Some(len))
    }
}

impl ExactSizeIterator for MatrixRows<'_> {
    fn len(&self) -> usize {
        self.matrix.dimension - self.next
    }
}

impl FusedIterator for MatrixRows<'_> {}

impl GeneratedProblem {
    pub(crate) fn compile(problem: &FinalizedProblem) -> Result<Self, ProblemError> {
        problem.validate()?;
        let problem_digest = problem.digest()?;
        let instance_seed = problem.instance_seed();
        let MatrixSpec::SeededSymmetricTridiagonalV1 {
            dimension,
            boundary,
            off_diagonal,
            diagonal,
        } = problem.matrix;
        let dimension = usize::try_from(dimension)
            .map_err(|_| ProblemError::IntegerOverflow("compiled matrix dimension"))?;
        let (period_bits, fractional_bits, minimum_magnitude, maximum_magnitude) =
            off_diagonal.parameters();
        let matrix_period = 1_usize << period_bits;
        let matrix_seed = derive_subseed(instance_seed, MATRIX_VALUES_LABEL);
        let off_diagonal_mantissas = generate_negative_i64_table(
            matrix_seed,
            matrix_period,
            minimum_magnitude,
            maximum_magnitude,
        )?
        .into_boxed_slice();
        let margin_mantissa = diagonal.margin_mantissa();
        let maximum_generated_off_diagonal = off_diagonal_mantissas
            .iter()
            .map(|value| value.unsigned_abs())
            .max()
            .expect("validated period is nonempty");
        let minimum_generated_off_diagonal = off_diagonal_mantissas
            .iter()
            .map(|value| value.unsigned_abs())
            .min()
            .expect("validated period is nonempty");

        let matrix = PeriodicSymmetricTridiagonal {
            dimension,
            fractional_bits,
            margin_mantissa,
            off_diagonal_mantissas,
        };
        let rhs = compile_rhs(problem.rhs, dimension, &matrix, instance_seed)?;
        let structural_nonzeros = structural_nonzeros(dimension)?;
        let maximum_diagonal_mantissa_bound = maximum_generated_off_diagonal
            .checked_mul(2)
            .and_then(|value| value.checked_add(margin_mantissa))
            .ok_or(ProblemError::IntegerOverflow("compiled diagonal bound"))?;
        let maximum_absolute_row_sum_mantissa_bound = maximum_generated_off_diagonal
            .checked_mul(4)
            .and_then(|value| value.checked_add(margin_mantissa))
            .ok_or(ProblemError::IntegerOverflow("compiled row-sum bound"))?;
        let (rhs_period, rhs_fractional_bits, maximum_absolute_rhs_mantissa) =
            rhs.certificate_values();
        let certificate = GeneratorCertificate {
            dimension,
            structural_nonzeros,
            maximum_nonzeros_per_row: if dimension == 2 { 2 } else { 3 },
            matrix_period,
            coefficient_fractional_bits: fractional_bits,
            minimum_off_diagonal_magnitude_mantissa: minimum_generated_off_diagonal,
            maximum_off_diagonal_magnitude_mantissa: maximum_generated_off_diagonal,
            maximum_diagonal_mantissa_bound,
            maximum_absolute_row_sum_mantissa_bound,
            maximum_absolute_column_sum_mantissa_bound: maximum_absolute_row_sum_mantissa_bound,
            strict_diagonal_dominance_margin_mantissa: margin_mantissa,
            rhs_period,
            rhs_fractional_bits,
            maximum_absolute_rhs_mantissa,
            symmetric: true,
            positive_diagonal: true,
            nonpositive_off_diagonal: true,
            strictly_row_diagonally_dominant: true,
            nonsingular_m_matrix: true,
            boundary,
        };

        Ok(Self {
            problem_digest,
            instance_seed,
            matrix,
            rhs,
            certificate,
        })
    }

    #[must_use]
    pub const fn problem_digest(&self) -> ProblemDigest {
        self.problem_digest
    }

    #[must_use]
    pub const fn instance_seed(&self) -> InstanceSeed {
        self.instance_seed
    }

    #[must_use]
    pub const fn dimension(&self) -> usize {
        self.matrix.dimension
    }

    #[must_use]
    pub const fn structural_nonzeros(&self) -> usize {
        self.certificate.structural_nonzeros
    }

    /// Alias matching the mathematical `nnz` abbreviation.
    #[must_use]
    pub const fn structural_nnz(&self) -> usize {
        self.structural_nonzeros()
    }

    #[must_use]
    pub const fn certificate(&self) -> &GeneratorCertificate {
        &self.certificate
    }

    #[must_use]
    pub fn row(&self, row: usize) -> Option<MatrixRow> {
        if row >= self.dimension() {
            return None;
        }
        Some(MatrixRow::new(&self.matrix, row))
    }

    #[must_use]
    pub fn rows(&self) -> MatrixRows<'_> {
        MatrixRows {
            matrix: &self.matrix,
            next: 0,
        }
    }

    #[must_use]
    pub fn rhs(&self, row: usize) -> Option<Dyadic> {
        self.rhs.value(row)
    }

    #[must_use]
    pub fn rhs_f64(&self, row: usize) -> Option<f64> {
        self.rhs(row).map(Dyadic::to_f64)
    }

    /// Flat periodic matrix table, useful for diagnostics and succinct evaluators.
    #[must_use]
    pub fn off_diagonal_periodic_mantissas(&self) -> &[i64] {
        &self.matrix.off_diagonal_mantissas
    }

    /// Returns the seeded RHS table. Manufactured RHS values have no table.
    #[must_use]
    pub fn rhs_periodic_mantissas(&self) -> Option<&[i64]> {
        match &self.rhs {
            GeneratedRhs::ManufacturedOnes { .. } => None,
            GeneratedRhs::SeededPeriodic { mantissas, .. } => Some(mantissas),
        }
    }
}

impl SparseMatrix for GeneratedProblem {
    type Row<'a> = MatrixRow;

    fn dimension(&self) -> usize {
        self.dimension()
    }

    fn structural_nonzeros(&self) -> usize {
        self.structural_nonzeros()
    }

    fn row(&self, row: usize) -> Option<Self::Row<'_>> {
        self.row(row)
    }
}

impl PeriodicSymmetricTridiagonal {
    fn edge_mantissa(&self, lower_endpoint: usize) -> i64 {
        self.off_diagonal_mantissas[lower_endpoint & (self.off_diagonal_mantissas.len() - 1)]
    }
}

impl GeneratedRhs {
    fn value(&self, row: usize) -> Option<Dyadic> {
        match self {
            Self::ManufacturedOnes { dimension, value } => (row < *dimension).then_some(*value),
            Self::SeededPeriodic {
                dimension,
                fractional_bits,
                mantissas,
            } => (row < *dimension)
                .then(|| Dyadic::new(mantissas[row & (mantissas.len() - 1)], *fractional_bits)),
        }
    }

    fn certificate_values(&self) -> (usize, u8, u64) {
        match self {
            Self::ManufacturedOnes { value, .. } => {
                (1, value.fractional_bits(), value.mantissa().unsigned_abs())
            }
            Self::SeededPeriodic {
                fractional_bits,
                mantissas,
                ..
            } => (
                mantissas.len(),
                *fractional_bits,
                mantissas
                    .iter()
                    .map(|value| value.unsigned_abs())
                    .max()
                    .expect("validated period is nonempty"),
            ),
        }
    }
}

fn compile_rhs(
    spec: RhsSpec,
    dimension: usize,
    matrix: &PeriodicSymmetricTridiagonal,
    instance_seed: InstanceSeed,
) -> Result<GeneratedRhs, ProblemError> {
    match spec {
        RhsSpec::ManufacturedOnesV1 => Ok(GeneratedRhs::ManufacturedOnes {
            dimension,
            value: Dyadic::new(
                i64::try_from(matrix.margin_mantissa).expect("validated dominance margin fits i64"),
                matrix.fractional_bits,
            ),
        }),
        RhsSpec::SeededPeriodicDyadicV1 {
            period_bits,
            fractional_bits,
            minimum_mantissa,
            maximum_mantissa,
        } => {
            let period = 1_usize << period_bits;
            let seed = derive_subseed(instance_seed, RHS_VALUES_LABEL);
            let width =
                u64::try_from(i128::from(maximum_mantissa) - i128::from(minimum_mantissa) + 1)
                    .map_err(|_| ProblemError::RhsRangeTooWide)?;
            let mut stream = UniformStream::new(seed);
            let mut mantissas = Vec::new();
            mantissas
                .try_reserve_exact(period)
                .map_err(|_| ProblemError::AllocationFailed)?;
            for _ in 0..period {
                let offset = stream.sample_below(width);
                let value = i128::from(minimum_mantissa) + i128::from(offset);
                mantissas.push(i64::try_from(value).expect("validated RHS range fits i64"));
            }
            Ok(GeneratedRhs::SeededPeriodic {
                dimension,
                fractional_bits,
                mantissas: mantissas.into_boxed_slice(),
            })
        }
    }
}

fn generate_negative_i64_table(
    seed: InstanceSeed,
    period: usize,
    minimum: u64,
    maximum: u64,
) -> Result<Vec<i64>, ProblemError> {
    let width = maximum
        .checked_sub(minimum)
        .and_then(|value| value.checked_add(1))
        .ok_or(ProblemError::IntegerOverflow("generator sample interval"))?;
    let mut stream = UniformStream::new(seed);
    let mut table = Vec::new();
    table
        .try_reserve_exact(period)
        .map_err(|_| ProblemError::AllocationFailed)?;
    for _ in 0..period {
        let magnitude = minimum + stream.sample_below(width);
        table.push(-i64::try_from(magnitude).expect("validated off-diagonal magnitude fits i64"));
    }
    Ok(table)
}

fn structural_nonzeros(dimension: usize) -> Result<usize, ProblemError> {
    dimension
        .checked_mul(3)
        .and_then(|value| value.checked_sub(2))
        .ok_or(ProblemError::IntegerOverflow("structural nonzero count"))
}

/// BLAKE3 XOF words mapped with rejection sampling, never modulo-biased.
struct UniformStream {
    reader: OutputReader,
}

impl UniformStream {
    fn new(seed: InstanceSeed) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key(UNBIASED_STREAM_CONTEXT);
        hasher.update(seed.as_bytes());
        Self {
            reader: hasher.finalize_xof(),
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0_u8; 8];
        self.reader.fill(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn sample_below(&mut self, bound: u64) -> u64 {
        debug_assert!(bound > 0);
        let rejection_threshold = bound.wrapping_neg() % bound;
        loop {
            let candidate = self.next_u64();
            if candidate >= rejection_threshold {
                return candidate % bound;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DiagonalConstruction, MatrixSpec, OffDiagonalValues, ProblemSchema, ProblemTemplate,
        RequestedOutput, SeedDerivation, TemplateRandomness, TemplateSchema,
    };

    fn matrix(dimension: u64) -> MatrixSpec {
        MatrixSpec::SeededSymmetricTridiagonalV1 {
            dimension,
            boundary: BoundaryRule::TruncateV1,
            off_diagonal: OffDiagonalValues::SeededPeriodicNegativeDyadicV1 {
                period_bits: 3,
                fractional_bits: 8,
                minimum_magnitude_mantissa: 1,
                maximum_magnitude_mantissa: 12,
            },
            diagonal: DiagonalConstruction::AbsoluteRowSumPlusMarginV1 {
                margin_mantissa: 16,
            },
        }
    }

    fn template(seed_byte: u8, rhs: RhsSpec) -> ProblemTemplate {
        ProblemTemplate {
            schema: TemplateSchema::V1,
            randomness: TemplateRandomness::LiteralV1 {
                seed: InstanceSeed::from_bytes([seed_byte; 32]),
            },
            matrix: matrix(19),
            rhs,
            requested_outputs: vec![RequestedOutput::SquaredL2ResidualV1],
        }
    }

    fn generated(seed_byte: u8, rhs: RhsSpec) -> GeneratedProblem {
        template(seed_byte, rhs)
            .finalize_literal()
            .unwrap()
            .compile()
            .unwrap()
    }

    #[test]
    fn generation_is_deterministic_and_seed_bound() {
        let lhs = generated(1, RhsSpec::ManufacturedOnesV1);
        let rhs = generated(1, RhsSpec::ManufacturedOnesV1);
        let changed = generated(2, RhsSpec::ManufacturedOnesV1);
        assert_eq!(lhs, rhs);
        assert_ne!(
            lhs.off_diagonal_periodic_mantissas(),
            changed.off_diagonal_periodic_mantissas()
        );
        assert_ne!(lhs.problem_digest(), changed.problem_digest());
    }

    #[test]
    fn rows_are_sorted_symmetric_negative_and_strictly_dominant() {
        let problem = generated(9, RhsSpec::ManufacturedOnesV1);
        for row_index in 0..problem.dimension() {
            let row = problem.row(row_index).unwrap().collect::<Vec<_>>();
            assert!(row.windows(2).all(|pair| pair[0].column < pair[1].column));
            let diagonal = row
                .iter()
                .find(|entry| entry.column == row_index)
                .unwrap()
                .value
                .mantissa();
            let off_sum: i64 = row
                .iter()
                .filter(|entry| entry.column != row_index)
                .map(|entry| {
                    assert!(entry.value.mantissa() < 0);
                    entry.value.mantissa().abs()
                })
                .sum();
            assert_eq!(diagonal - off_sum, 16);
            for entry in &row {
                let transpose = problem
                    .row(entry.column)
                    .unwrap()
                    .find(|candidate| candidate.column == row_index)
                    .unwrap();
                assert_eq!(entry.value, transpose.value);
            }
        }
    }

    #[test]
    fn truncating_endpoints_and_structural_nnz_are_exact() {
        let problem = generated(4, RhsSpec::ManufacturedOnesV1);
        assert_eq!(problem.row(0).unwrap().len(), 2);
        assert_eq!(problem.row(problem.dimension() - 1).unwrap().len(), 2);
        assert!(
            problem
                .rows()
                .skip(1)
                .take(problem.dimension() - 2)
                .all(|row| row.len() == 3)
        );
        let enumerated = problem.rows().map(|row| row.len()).sum::<usize>();
        assert_eq!(problem.structural_nonzeros(), 3 * problem.dimension() - 2);
        assert_eq!(enumerated, problem.structural_nonzeros());
        assert!(problem.row(problem.dimension()).is_none());
    }

    #[test]
    fn manufactured_rhs_is_exactly_matrix_times_ones() {
        let problem = generated(5, RhsSpec::ManufacturedOnesV1);
        for row_index in 0..problem.dimension() {
            let row_sum: i64 = problem
                .row(row_index)
                .unwrap()
                .map(|entry| entry.value.mantissa())
                .sum();
            let rhs = problem.rhs(row_index).unwrap();
            assert_eq!(rhs.fractional_bits(), 8);
            assert_eq!(rhs.mantissa(), row_sum);
            assert_eq!(problem.rhs_f64(row_index), Some(rhs.to_f64()));
        }
        assert!(problem.rhs(problem.dimension()).is_none());
    }

    #[test]
    fn seeded_rhs_is_bounded_periodic_and_domain_separated() {
        let rhs = RhsSpec::SeededPeriodicDyadicV1 {
            period_bits: 2,
            fractional_bits: 6,
            minimum_mantissa: -7,
            maximum_mantissa: 11,
        };
        let problem = generated(3, rhs);
        let table = problem.rhs_periodic_mantissas().unwrap();
        assert_eq!(table.len(), 4);
        assert!(table.iter().all(|value| (-7..=11).contains(value)));
        for row in 0..problem.dimension() - table.len() {
            assert_eq!(problem.rhs(row), problem.rhs(row + table.len()));
        }
        assert_ne!(
            table,
            &problem.off_diagonal_periodic_mantissas()[..table.len()]
        );
    }

    #[test]
    fn derived_context_recomputes_and_validates() {
        let mut template = template(0, RhsSpec::ManufacturedOnesV1);
        template.randomness = TemplateRandomness::ChallengeDerivedV1 {
            derivation: SeedDerivation::Blake3XofV1,
        };
        let problem = template
            .finalize_with_challenge_context(b"signed challenge")
            .unwrap();
        problem
            .verify_challenge_context(b"signed challenge")
            .unwrap();
        assert!(
            problem
                .verify_challenge_context(b"other challenge")
                .is_err()
        );

        let mut tampered = problem.clone();
        tampered.schema = ProblemSchema::V1;
        if let crate::FinalizedRandomness::ChallengeDerivedV1 { seed, .. } =
            &mut tampered.randomness
        {
            *seed = InstanceSeed::from_bytes([99; 32]);
        }
        assert!(matches!(
            tampered.validate(),
            Err(ProblemError::DerivedSeedMismatch)
        ));
    }

    #[test]
    fn sampler_stays_in_range_for_non_power_of_two_bounds() {
        let mut stream = UniformStream::new(InstanceSeed::from_bytes([42; 32]));
        let samples = (0..10_000)
            .map(|_| stream.sample_below(7))
            .collect::<Vec<_>>();
        assert!(samples.iter().all(|sample| *sample < 7));
        assert!((0..7).all(|value| samples.contains(&value)));
    }
}
